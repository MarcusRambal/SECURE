import sys
import os
import json
import urllib.parse
from playwright.sync_api import sync_playwright

OUTPUT_REQ_DIR = "/app/requests"

def save_raw_request(request, index):
    try:
        parsed_url = urllib.parse.urlparse(request.url)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        headers_text = f"{request.method} {path} HTTP/1.1\n"
        headers_text += f"Host: {parsed_url.netloc}\n"

        for key, value in request.headers.items():
            if key.lower() != "host":
                headers_text += f"{key}: {value}\n"

        post_data = request.post_data or ""
        if post_data:
            headers_text += f"\n{post_data}"
        else:
            headers_text += "\n"

        clean_path = path.replace("/", "_").replace("?", "_").replace("&", "_")[:35]
        filename = os.path.join(OUTPUT_REQ_DIR, f"req_{index:03d}_{request.method}{clean_path}.req")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(headers_text)
    except Exception as e:
        sys.stderr.write(f"Error guardando petición raw: {str(e)}\n")

def dismiss_popups_and_overlays(page):
    """Cierra modales de bienvenida, avisos de cookies o diálogos flotantes."""
    try:
        # Botones comunes para cerrar overlays (adaptado para Juice Shop y SPAs comunes)
        overlay_selectors = [
            'button[aria-label="Close Welcome Banner"]',
            'a.cc-btn.cc-dismiss',
            'button[aria-label="dismiss cookie message"]',
            'button.close',
            'div.cdk-overlay-backdrop'
        ]
        for sel in overlay_selectors:
            elements = page.query_selector_all(sel)
            for el in elements:
                if el.is_visible():
                    el.click()
                    page.wait_for_timeout(300)
    except Exception:
        pass

def interact_with_all_elements(page):
    """Interactúa masivamente con formularios, botones, selects y elementos cliqueables."""
    try:
        dismiss_popups_and_overlays(page)

        # 1. Rellenar TODOS los campos de entrada según su tipo/nombre
        inputs = page.query_selector_all('input, textarea, select')
        for inp in inputs:
            try:
                if not inp.is_visible() or inp.is_disabled():
                    continue

                input_type = (inp.get_attribute("type") or "text").lower()
                name_attr = (inp.get_attribute("name") or "").lower()
                id_attr = (inp.get_attribute("id") or "").lower()

                if input_type in ["email"] or "email" in name_attr or "email" in id_attr:
                    inp.fill("test@example.com")
                elif input_type in ["password"] or "pass" in name_attr or "pass" in id_attr:
                    inp.fill("password123")
                elif input_type in ["number"]:
                    inp.fill("1")
                elif input_type in ["text", "search"]:
                    inp.fill("apple")
                elif input_type == "checkbox":
                    inp.check()
            except Exception:
                continue

        page.wait_for_timeout(400)

        # 2. Hacer scroll para activar lazy-loading e infini-scroll
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(500)

        # 3. Hacer clic en elementos interactivos (Botones, Tarjetas, Paginación, Menús)
        clickable_selectors = [
            'button:not([disabled])',
            '[role="button"]',
            'mat-card',                 # Componentes Angular comunes
            'mat-select',               # Desplegables
            '.mat-paginator-navigation-next', # Paginación
            'a[routerlink]',
            '[ng-click]'
        ]

        for selector in clickable_selectors:
            elements = page.query_selector_all(selector)
            # Limitamos la interacción a los primeros 10 elementos por selector para evitar loops infinitos
            for el in elements[:10]:
                try:
                    if el.is_visible():
                        el.click(timeout=1500)
                        page.wait_for_timeout(300)
                        dismiss_popups_and_overlays(page)
                except Exception:
                    continue

    except Exception as e:
        sys.stderr.write(f"Error durante la interacción amplia: {str(e)}\n")

def extract_all_discovered_routes(page, target_url):
    """Extrae enlaces HTML, atributos de frameworks (Angular/React) y fragmentos de URL (#)."""
    routes = set()
    try:
        # Extraer enlaces href
        links = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.getAttribute("href"))')
        for link in links:
            if link:
                if link.startswith("/") or "#" in link:
                    routes.add(urllib.parse.urljoin(target_url, link))

        # Extraer routerlink (Angular)
        rlinks = page.eval_on_selector_all('[routerlink]', 'els => els.map(e => e.getAttribute("routerlink"))')
        for rlink in rlinks:
            if rlink:
                routes.add(f"{target_url.rstrip('/')}/#/{rlink.strip('/')}")

    except Exception as e:
        sys.stderr.write(f"Error extrayendo rutas: {str(e)}\n")
    return routes

def crawl_and_capture(target_url):
    endpoints = set()
    api_requests = set()
    req_counter = 0

    if not os.path.exists(OUTPUT_REQ_DIR):
        os.makedirs(OUTPUT_REQ_DIR, exist_ok=True)

    # Limpieza de ejecuciones anteriores
    for filename in os.listdir(OUTPUT_REQ_DIR):
        if filename.endswith((".req", ".har")) or filename == "spa_crawler_output.json":
            try:
                os.remove(os.path.join(OUTPUT_REQ_DIR, filename))
            except OSError as cleanup_error:
                sys.stderr.write(f"Error limpiando artefacto anterior {filename}: {cleanup_error}\n")

    har_path = os.path.join(OUTPUT_REQ_DIR, "session_traffic.har")
    output_json_path = os.path.join(OUTPUT_REQ_DIR, "spa_crawler_output.json")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )

        context = browser.new_context(record_har_path=har_path)
        page = context.new_page()

        def handle_request(request):
            nonlocal req_counter
            url = request.url
            # Filtrar estáticos de bajo valor
            if any(ext in url.lower() for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ttf", ".ico"]):
                return

            api_requests.add(url)
            req_counter += 1
            save_raw_request(request, req_counter)

        page.on("request", handle_request)

        try:
            # FASE 1: Carga e Interacción Inicial
            page.goto(target_url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(2000)

            # Cierre inicial de anuncios/modales e interacción
            dismiss_popups_and_overlays(page)
            interact_with_all_elements(page)

            # Recolectar rutas iniciales
            endpoints.update(extract_all_discovered_routes(page, target_url))

            # FASE 2: Navegación recursiva e Interacción Profunda
            visited_urls = set()
            nav_list = list(endpoints)

            for nav_url in nav_list:
                if nav_url in visited_urls or target_url not in nav_url:
                    continue

                visited_urls.add(nav_url)
                try:
                    page.goto(nav_url, wait_until="networkidle", timeout=12000)
                    page.wait_for_timeout(1000)

                    # Interactuar profundamente con la nueva vista cargada
                    interact_with_all_elements(page)

                    # Descubrir nuevas rutas que hayan aparecido tras interactuar
                    new_routes = extract_all_discovered_routes(page, target_url)
                    for nr in new_routes:
                        if nr not in visited_urls and nr not in nav_list:
                            nav_list.append(nr)
                            endpoints.add(nr)

                except Exception as nav_err:
                    sys.stderr.write(f"Error visitando {nav_url}: {str(nav_err)}\n")

        except Exception as e:
            sys.stderr.write(f"Error durante la ejecución principal: {str(e)}\n")
        finally:
            context.close()
            browser.close()

    result = {
        "target": target_url,
        "captured_requests_count": req_counter,
        "har_file": har_path,
        "navigation_routes": sorted(list(endpoints)),
        "api_endpoints": sorted(list(api_requests)),
        "output_json_file": output_json_path
    }

    try:
        with open(output_json_path, "w", encoding="utf-8") as output_file:
            json.dump(result, output_file, ensure_ascii=False, indent=2)
            output_file.write("\n")
    except OSError as output_error:
        sys.stderr.write(f"Error guardando salida JSON del crawler: {output_error}\n")

    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python spa_crawler.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    result = crawl_and_capture(target)
    print(json.dumps(result, indent=2))