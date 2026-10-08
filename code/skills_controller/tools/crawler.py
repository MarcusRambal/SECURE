"""Analizador pasivo de tecnologías, metadatos y encabezados HTTP.

Configure TARGET_URL y ejecute este archivo directamente para obtener un JSON
legible con la información pública de la página.
"""

from __future__ import annotations

import json
import os
import re
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.sync_api import Page, Response, sync_playwright

#URL http://127.0.0.1:3003  http://localhost:3001

DEFAULT_TIMEOUT_MS = 30_000
MAX_NAVIGATION_DEPTH = 2
MAX_NAVIGATION_ROUTES = 40
MAX_ROUTE_SAMPLES = 2
MAX_LINKS_PER_PAGE = 150
AUTH_LOGIN_PATH = os.getenv("CRAWLER_LOGIN_PATH", "/login/")
AUTH_USERNAME_SELECTOR = os.getenv("CRAWLER_USERNAME_SELECTOR", "#id_username")
AUTH_PASSWORD_SELECTOR = os.getenv("CRAWLER_PASSWORD_SELECTOR", "#id_password")
AUTH_SUBMIT_SELECTOR = os.getenv("CRAWLER_SUBMIT_SELECTOR", "form")
REPORT_OUTPUT_DEFAULT = Path(__file__).with_name("crawler_report.json")

STATIC_EXTENSIONS = {
        ".7z", ".avi", ".bmp", ".css", ".csv", ".doc", ".docx", ".eot",
        ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mp3", ".mp4",
        ".pdf", ".png", ".svg", ".tar", ".ttf", ".webm", ".webp", ".woff",
        ".woff2", ".xls", ".xlsx", ".zip",
}

ROUTE_CHANGE_LISTENER = """
(() => {
    const changes = [];
    const record = (type) => changes.push({ type, url: location.href });
    for (const method of ['pushState', 'replaceState']) {
        const original = history[method];
        history[method] = function (...args) {
            const result = original.apply(this, args);
            record(method);
            return result;
        };
    }
    addEventListener('popstate', () => record('popstate'));
    addEventListener('hashchange', () => record('hashchange'));
    Object.defineProperty(window, '__crawlerRouteChanges', { value: changes });
})();
"""

# Estructura: "Nombre": [ (Regex_Patron, Permite_Extraer_Version?) ]
TECHNOLOGY_SIGNATURES = {
    "React": [
        r"__next|_reactrootcontainer|data-reactroot",
        r"react(?:\.production)?(?:\.min)?\.js",
    ],
    "Next.js": [
        r"/_next/",
        r"__NEXT_DATA__",
    ],
    "Angular": [
        r'ng-version=["\']([^"\']+)["\']',  # Captura la versión exacta (Grupo 1)
        r"angular(?:\.min)?\.js",
        r"/main\.[a-z0-9]+\.js",
    ],
    "Vue.js": [
        r"__vue__|data-v-[a-f0-9]+",
        r"vue(?:\.global|\.runtime)?(?:\.prod)?(?:\.min)?\.js",
    ],
    "Nuxt": [
        r"/_nuxt/|__NUXT__",
    ],
    "WordPress": [
        r"/wp-content/|/wp-includes/",
        r'content=["\']wordpress\s*([0-9\.]*)["\']',  # Versión desde meta generator
    ],
    "Tailwind CSS": [
        r"tailwind(?:\.min)?\.css",
        r"(--tw-bg-opacity|--tw-shadow|--tw-text-opacity)",
    ],
    "Bootstrap": [
        r"bootstrap(?:\.min)?\.(?:css|js)",
        r'/*!* bootstrap v([0-9\.]+)["\']',
    ],
}

SECURITY_HEADERS = {
    "content-security-policy": "Restringe las fuentes de contenido permitidas.",
    "strict-transport-security": "Fuerza conexiones HTTPS en visitas futuras.",
    "x-content-type-options": "Evita la detección MIME por el navegador.",
    "x-frame-options": "Controla el embebido de la página en frames.",
    "referrer-policy": "Limita la información enviada en el encabezado Referer.",
    "permissions-policy": "Restringe APIs y capacidades del navegador.",
    "access-control-allow-origin": "Define qué orígenes pueden acceder a los recursos (CORS).",
}

def _unique(values: list[str]) -> list[str]:
	return list(dict.fromkeys(value for value in values if value))


def _extract_metadata(page: Page) -> dict[str, Any]:
    """Extrae los metadatos accesibles del documento renderizado de forma robusta."""
    return page.evaluate(
        """() => {
            // 1. Extracción amplia de cualquier etiqueta <meta>
            const readMeta = () => Array.from(document.querySelectorAll('meta'))
                .map(element => ({
                    name: element.getAttribute('name') || 
                          element.getAttribute('property') || 
                          element.getAttribute('http-equiv') || 
                          (element.hasAttribute('charset') ? 'charset' : ''),
                    content: element.getAttribute('content') || 
                             element.getAttribute('charset') || ''
                }))
                .filter(item => item.name || item.content);

            // 2. Búsqueda de Favicon con fallback inteligente
            const getFavicon = () => {
                const iconNode = document.querySelector('link[rel*="icon"], link[rel="apple-touch-icon"]');
                if (iconNode && iconNode.href) return iconNode.href;
                return new URL('/favicon.ico', window.location.origin).href;
            };

            // 3. Procesamiento seguro de Scripts (filtrando inline masivos)
            const getScripts = () => Array.from(document.scripts)
                .map(script => {
                    if (script.src) return script.src;
                    const text = script.textContent ? script.textContent.trim() : '';
                    // Si el script inline es muy largo (>300 chars), guardamos solo una muestra
                    return text.length > 300 ? text.substring(0, 300) + '... [TRUNCATED]' : text;
                })
                .filter(Boolean);

            return {
                title: document.title ? document.title.trim() : '',
                language: document.documentElement.lang || document.body?.getAttribute('lang') || '',
                canonical_url: document.querySelector('link[rel="canonical"]')?.href || '',
                favicon: getFavicon(),
                meta: readMeta(),
                scripts: getScripts(),
                stylesheets: Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
                    .map(link => link.href || '')
                    .filter(Boolean)
            };
        }"""
    )


def _detect_technologies(page: Page, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Identifica tecnologías y versiones mediante huellas en el DOM, recursos y contexto JS."""
    
    html = page.content()
    resources = [*metadata.get("scripts", []), *metadata.get("stylesheets", [])]
    
    # Extraer meta generator
    generator = next(
        (item["content"] for item in metadata.get("meta", []) if item.get("name", "").lower() == "generator"),
        ""
    )
    
    # Inspección de variables globales en la ventana (Window Object)
    js_objects = page.evaluate("""() => {
        return {
            hasReact: !!(window.React || document.querySelector('[data-reactroot], [data-reactid]')),
            hasVue: !!(window.Vue || document.querySelector('[data-v-]')),
            hasAngular: !!(window.angular || document.querySelector('[ng-version]')),
            angularVersion: document.querySelector('[ng-version]')?.getAttribute('ng-version') || null,
            hasjQuery: !!window.jQuery,
            jQueryVersion: window.jQuery?.fn?.jquery || null
        };
    }""")

    fingerprints = "\n".join([html, *resources, generator])
    detected = []

    # 1. Análisis por RegEx en HTML y Recursos
    for technology, patterns in TECHNOLOGY_SIGNATURES.items():
        matches = []
        extracted_version = None

        for pattern in patterns:
            match = re.search(pattern, fingerprints, re.IGNORECASE)
            if match:
                matches.append(match.group(0))
                # Si la Regex tiene un grupo de captura `()`, asumimos que es la versión
                if match.groups() and match.group(1):
                    extracted_version = match.group(1)

        if matches:
            tech_data = {
                "name": technology,
                "evidence": list(set(matches)),
                "confidence": "high" if len(matches) > 1 or generator else "medium"
            }
            if extracted_version:
                tech_data["version"] = extracted_version
                
            detected.append(tech_data)

    # 2. Complementar con datos del contexto JS
    if js_objects.get("angularVersion"):
        _update_or_add_tech(detected, "Angular", js_objects["angularVersion"])
    if js_objects.get("jQueryVersion"):
        _update_or_add_tech(detected, "jQuery", js_objects["jQueryVersion"])

    return detected

def _update_or_add_tech(detected_list: list, tech_name: str, version: str):
    """Actualiza la versión si la tecnología ya fue detectada o la añade."""
    for item in detected_list:
        if item["name"] == tech_name:
            item["version"] = version
            item["confidence"] = "high"
            return
    detected_list.append({
        "name": tech_name,
        "version": version,
        "evidence": ["window object / DOM attribute"],
        "confidence": "high"
    })


def _process_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Normaliza encabezados y resume las cabeceras de seguridad relevantes."""
    normalized = {name.lower(): value.strip() for name, value in headers.items()}
    
    security = {}
    for name, purpose in SECURITY_HEADERS.items():
        val = normalized.get(name, "")
        # Se considera presente solo si existe la clave Y tiene un valor no vacío
        is_present = bool(val)
        security[name] = {
            "present": is_present,
            "value": val,
            "purpose": purpose,
        }

    return {
        "all": normalized,
        "server": normalized.get("server", ""),
        "powered_by": normalized.get("x-powered-by", ""),
        "content_type": normalized.get("content-type", ""),
        "security": security,
        "missing_security_headers": [
            name for name, details in security.items() if not details["present"]
        ],
    }


def _is_login_page(page: Page) -> bool:
    return urlsplit(page.url).path.rstrip("/").endswith(AUTH_LOGIN_PATH.rstrip("/"))


def _authentication_state_path(target_url: str) -> Path:
    configured_path = os.getenv("CRAWLER_STORAGE_STATE")
    if configured_path:
        return Path(configured_path).expanduser()
    origin = urlsplit(target_url).netloc.lower()
    safe_origin = re.sub(r"[^a-z0-9]+", "_", origin).strip("_") or "target"
    return Path(__file__).with_name(f".crawler_auth_state.{safe_origin}.json")


def _authenticate_if_configured(
    context: Any,
    page: Page,
    target_url: str,
    timeout_ms: int,
    state_path: Path,
    state_restored: bool,
) -> tuple[Response | None, dict[str, Any]]:
    """Restaura o crea una sesión opcional sin incluir credenciales en el informe."""
    username = os.getenv("CRAWLER_USERNAME")
    password = os.getenv("CRAWLER_PASSWORD")
    authentication = {
        "configured": bool(username and password),
        "state_restored": state_restored,
        "authenticated": False,
        "state_path": str(state_path),
    }
    initial_url = (
        urljoin(target_url, AUTH_LOGIN_PATH)
        if username and password and not state_restored
        else target_url
    )
    response = page.goto(initial_url, wait_until="domcontentloaded", timeout=timeout_ms)

    if not _is_login_page(page):
        authentication["authenticated"] = state_restored
        authentication["mode"] = "session_restored" if state_restored else "not_required_or_not_configured"
        return response, authentication
    if not username or not password:
        authentication["mode"] = "login_required"
        authentication["reason"] = "The target redirected to login and no crawler credentials are configured."
        return response, authentication

    page.locator(AUTH_USERNAME_SELECTOR).fill(username)
    page.locator(AUTH_PASSWORD_SELECTOR).fill(password)
    page.locator(AUTH_SUBMIT_SELECTOR).press("Enter")
    page.wait_for_timeout(500)
    if _is_login_page(page):
        raise RuntimeError("PyGoat authentication did not leave the login page.")

    state_path.parent.mkdir(parents=True, exist_ok=True)
    context.storage_state(path=str(state_path))
    authentication["authenticated"] = True
    authentication["state_saved"] = True
    authentication["mode"] = "credentials"
    return page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms), authentication


def _route_template(url: str) -> str:
    """Normaliza IDs y valores de consulta para limitar rutas repetitivas."""
    parsed = urlsplit(url)
    path_parts = []
    for part in parsed.path.split("/"):
        if re.fullmatch(r"\d+|[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|[0-9a-f]{16,}", part, re.IGNORECASE):
            path_parts.append("{id}")
        else:
            path_parts.append(part)
    query = urlencode(
        sorted((name, "{val}") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)),
        safe="{}",
    )
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(path_parts), query, parsed.fragment))


def _is_navigation_url(url: str, origin: tuple[str, str]) -> bool:
    parsed = urlsplit(url)
    if (parsed.scheme, parsed.netloc) != origin or not parsed.path:
        return False
    return not any(parsed.path.lower().endswith(extension) for extension in STATIC_EXTENSIONS)


def _extract_navigation_links(page: Page) -> list[dict[str, str]]:
    """Extrae primero enlaces de cabecera, navegacion, pie y menus declarados."""
    return page.evaluate(
        """() => {
            const priorityZones = 'header, nav, footer, aside, [role="navigation"], [role="menubar"], [role="menu"]';
            return Array.from(document.querySelectorAll('a[href]')).map(link => ({
                url: link.href,
                text: (link.innerText || link.getAttribute('aria-label') || '').trim(),
                priority: link.closest(priorityZones) ? 'high' : 'normal'
            }));
        }"""
    )


def _click_route(page: Page, source_url: str, target_url: str, timeout_ms: int) -> tuple[str, str]:
    """Sigue un enlace visible con Playwright; usa navegacion directa solo como respaldo."""
    page.goto(source_url, wait_until="domcontentloaded", timeout=timeout_ms)
    for index in range(min(page.locator("a[href]").count(), MAX_LINKS_PER_PAGE)):
        link = page.locator("a[href]").nth(index)
        href = link.get_attribute("href")
        if href and urljoin(page.url, href) == target_url:
            try:
                link.click(timeout=3_000)
                page.wait_for_timeout(300)
                return page.url, "click"
            except Exception:
                break
    page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
    return page.url, "direct_fallback"


def _map_navigation(page: Page, context: Any, root_url: str, timeout_ms: int) -> dict[str, Any]:
    """Recorre enlaces principales de mismo origen, sin formularios ni acciones de negocio."""
    root = urlsplit(root_url)
    origin = (root.scheme, root.netloc)
    context.add_init_script(ROUTE_CHANGE_LISTENER)
    queue = deque([{"url": root_url, "source": "", "depth": 0, "priority": "high"}])
    template_samples = {_route_template(root_url): 1}
    visited, discovered, history_events = [], [], []
    seen_urls = set()

    while queue and len(visited) < MAX_NAVIGATION_ROUTES:
        candidate = queue.popleft()
        if candidate["url"] in seen_urls:
            continue
        try:
            if candidate["source"]:
                final_url, method = _click_route(page, candidate["source"], candidate["url"], timeout_ms)
            else:
                page.goto(candidate["url"], wait_until="domcontentloaded", timeout=timeout_ms)
                final_url, method = page.url, "initial"
            if not _is_navigation_url(final_url, origin):
                continue
            seen_urls.add(candidate["url"])
            changes = page.evaluate("window.__crawlerRouteChanges || []")
            for change in changes:
                if change not in history_events:
                    history_events.append(change)
            visited.append({
                "url": final_url,
                "template": _route_template(final_url),
                "depth": candidate["depth"],
                "method": method,
                "priority": candidate["priority"],
            })
            if candidate["depth"] >= MAX_NAVIGATION_DEPTH:
                continue

            links = sorted(_extract_navigation_links(page), key=lambda link: link["priority"] != "high")
            for link in links:
                link_url = link.get("url", "")
                if not _is_navigation_url(link_url, origin):
                    continue
                template = _route_template(link_url)
                if template_samples.get(template, 0) >= MAX_ROUTE_SAMPLES:
                    continue
                template_samples[template] = template_samples.get(template, 0) + 1
                discovered.append({"url": link_url, "template": template, **link})
                queue.append({
                    "url": link_url,
                    "source": final_url,
                    "depth": candidate["depth"] + 1,
                    "priority": link["priority"],
                })
        except Exception as error:
            visited.append({
                "url": candidate["url"],
                "depth": candidate["depth"],
                "error": str(error),
            })

    return {
        "settings": {
            "max_depth": MAX_NAVIGATION_DEPTH,
            "max_routes": MAX_NAVIGATION_ROUTES,
            "max_samples_per_template": MAX_ROUTE_SAMPLES,
            "same_origin_only": True,
        },
        "visited_routes": visited,
        "discovered_routes": discovered,
        "history_events": history_events,
        "queue_truncated": bool(queue),
    }


def _build_endpoint_catalog(navigation_map: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Agrupa URLs descubiertas y visitadas bajo una unica plantilla de ruta."""
    grouped: dict[str, dict[str, Any]] = {}
    sample_urls_seen: set[str] = set()
    errors = []
    errors_seen: set[tuple[str, str]] = set()
    for source, is_visited in (("discovered_routes", False), ("visited_routes", True)):
        for route in navigation_map[source]:
            if route.get("error"):
                error_key = (route["url"], route["error"])
                if error_key not in errors_seen:
                    errors_seen.add(error_key)
                    errors.append({"url": route["url"], "error": route["error"]})
                continue
            template = route.get("template", _route_template(route["url"]))
            endpoint = grouped.setdefault(
                template,
                {
                    "template": template,
                    "sample_urls": [],
                    "labels": [],
                    "depth": route.get("depth", 0),
                    "priority": route.get("priority", "normal"),
                    "visited": False,
                    "methods": [],
                },
            )
            if route["url"] not in sample_urls_seen and len(endpoint["sample_urls"]) < MAX_ROUTE_SAMPLES:
                endpoint["sample_urls"].append(route["url"])
                sample_urls_seen.add(route["url"])
            if route.get("text") and route["text"] not in endpoint["labels"]:
                endpoint["labels"].append(route["text"])
            if route.get("method") and route["method"] not in endpoint["methods"]:
                endpoint["methods"].append(route["method"])
            endpoint["depth"] = min(endpoint["depth"], route.get("depth", 0))
            if route.get("priority") == "high":
                endpoint["priority"] = "high"
            endpoint["visited"] = endpoint["visited"] or is_visited
    endpoints = [endpoint for endpoint in grouped.values() if endpoint["sample_urls"]]
    return sorted(endpoints, key=lambda endpoint: (endpoint["depth"], endpoint["template"])), errors


def _build_filtered_report(
    target_url: str,
    final_url: str,
    response: Response | None,
    authentication: dict[str, Any],
    technologies: list[dict[str, Any]],
    metadata: dict[str, Any],
    headers: dict[str, Any],
    navigation_map: dict[str, Any],
) -> dict[str, Any]:
    """Prepara una salida compacta y sin rutas repetidas para consumo posterior."""
    endpoints, navigation_errors = _build_endpoint_catalog(navigation_map)
    history_event_types = []
    for event in navigation_map["history_events"]:
        event_type = event.get("type", "unknown")
        if event_type not in history_event_types:
            history_event_types.append(event_type)
    return {
        "target": {
            "requested_url": target_url,
            "final_url": final_url,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "response": {
                "status": response.status if response else None,
                "status_text": response.status_text if response else "No response received",
            },
        },
        "authentication": authentication,
        "technologies": technologies,
        "metadata": {
            key: value for key, value in metadata.items()
            if key not in {"scripts", "stylesheets"}
        },
        "server": {
            "server": headers["server"],
            "powered_by": headers["powered_by"],
            "content_type": headers["content_type"],
            "missing_security_headers": headers["missing_security_headers"],
        },
        "navigation": {
            "settings": navigation_map["settings"],
            "unique_endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "history_event_types": history_event_types,
            "errors": navigation_errors,
            "queue_truncated": navigation_map["queue_truncated"],
        },
        "resources": {
            "scripts": _unique(metadata["scripts"]),
            "stylesheets": _unique(metadata["stylesheets"]),
        },
    }


def analyze_website(url: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, Any]:
    """Devuelve un informe JSON serializable de una página web pública."""
    parsed_url = urlsplit(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("La URL debe incluir esquema http(s) y un dominio valido.")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            state_path = _authentication_state_path(url)
            state_restored = state_path.is_file()
            context_options = {"storage_state": str(state_path)} if state_restored else {}
            context = browser.new_context(**context_options)
            page = context.new_page()
            response, authentication = _authenticate_if_configured(
                context, page, url, timeout_ms, state_path, state_restored
            )
            page.wait_for_timeout(500)
            metadata = _extract_metadata(page)
            headers = response.all_headers() if response else {}
            navigation_map = _map_navigation(page, context, page.url, timeout_ms)
            return _build_filtered_report(
                url,
                page.url,
                response,
                authentication,
                _detect_technologies(page, metadata),
                metadata,
                _process_headers(headers),
                navigation_map,
            )
        finally:
            browser.close()


def _write_report(report: dict[str, Any]) -> Path:
    """Guarda el informe JSON en UTF-8 y devuelve su ruta final."""
    output_path = Path(
        os.getenv("CRAWLER_REPORT_PATH", str(REPORT_OUTPUT_DEFAULT))
    ).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Crawler de enlaces para aplicaciones web")
    parser.add_argument("--target-url", required=True, help="URL raiz a rastrear")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    args = parser.parse_args()
    try:
        report = analyze_website(args.target_url, args.timeout_ms)
    except Exception as error:
        report = {"target_url": args.target_url, "error": str(error)}
    print(json.dumps(report, ensure_ascii=False, indent=2))