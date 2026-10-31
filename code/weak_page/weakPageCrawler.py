#!/usr/bin/env python3
"""Passive route and request mapper for the project's own weak_page lab."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_TARGET = "http://weak-page:3009"
ALLOWED_HOSTS = {"weak-page", "weak-page-lab"}
MAX_ROUTES = 40
MAX_REQUESTS = 500
NAVIGATION_TIMEOUT_MS = 12_000
SENSITIVE_FIELD = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie|session|"
    r"csrf|xsrf|email|username|user_name|phone|address",
    re.IGNORECASE,
)
FRONTEND_ROUTE = re.compile(
    r'pattern:\s*/\^(.+?)/,\s*key:\s*"([^"]+)",\s*title:\s*"([^"]+)"'
)
APP_IMPORT = re.compile(
    r'import\s+(\w+)\s+from\s+["\']\.\.\/routes\/([^"\']+)["\']'
)
ROUTE_MOUNT = re.compile(
    r'\bapp\.use\(\s*["\']([^"\']+)["\']\s*,\s*(\w+)\s*\)'
)
APP_ENDPOINT = re.compile(
    r'\bapp\.(get|post|put|patch|delete|options|head)\(\s*["\']([^"\']+)["\']'
)
ROUTER_ENDPOINT = re.compile(
    r'\brouter\.(get|post|put|patch|delete|options|head)\(\s*["\']([^"\']+)["\']'
)


def validate_target_url(target_url: str) -> str:
    parsed = urlsplit(target_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.port != 3009
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "weakPageCrawler solo admite http://weak-page:3009 "
            "dentro de la red sec-net."
        )
    return f"http://{parsed.hostname}:3009"


def _route_template(regex_body: str) -> str:
    path = regex_body.replace(r"\/", "/")
    path = re.sub(r"\([^)]*\)", "{id}", path)
    path = path.strip("^$")
    path = path.replace("/?", "")
    path = path.rstrip("/")
    return path or "/"


def discover_frontend_routes(router_path: Path) -> list[dict[str, str]]:
    source = router_path.read_text(encoding="utf-8")
    routes = [
        {
            "template": _route_template(pattern),
            "key": key,
            "title": title,
        }
        for pattern, key, title in FRONTEND_ROUTE.findall(source)
    ]
    if not routes:
        raise ValueError(f"No se encontraron rutas SPA en {router_path}")
    return routes


def discover_api_routes(app_path: Path, routes_dir: Path) -> list[dict[str, str]]:
    app_source = app_path.read_text(encoding="utf-8")
    module_names = {
        variable: filename
        for variable, filename in APP_IMPORT.findall(app_source)
    }
    mounts = {
        variable: prefix.rstrip("/")
        for prefix, variable in ROUTE_MOUNT.findall(app_source)
    }
    endpoints: set[tuple[str, str, str]] = set()

    for method, path in APP_ENDPOINT.findall(app_source):
        endpoints.add((method.upper(), path, "app"))

    for variable, filename in module_names.items():
        prefix = mounts.get(variable)
        if prefix is None:
            continue
        source_path = routes_dir / filename
        if not source_path.is_file():
            raise FileNotFoundError(f"No se encontró el módulo de rutas: {source_path}")
        source = source_path.read_text(encoding="utf-8")
        for method, path in ROUTER_ENDPOINT.findall(source):
            full_path = f"{prefix}/{path.lstrip('/')}" if path != "/" else prefix
            endpoints.add((method.upper(), full_path, filename))

    if not endpoints:
        raise ValueError("No se encontraron endpoints Express en el código de weak_page")
    return [
        {"method": method, "path": path, "source": source}
        for method, path, source in sorted(endpoints)
    ]


def _same_origin(url: str, origin: tuple[str, str, int]) -> bool:
    parsed = urlsplit(url)
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return (parsed.scheme, parsed.hostname or "", port) == origin


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    safe_query = [
        (name, "[REDACTED]" if SENSITIVE_FIELD.search(name) else value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc.rsplit("@", 1)[-1],
            parts.path,
            urlencode(safe_query),
            parts.fragment,
        )
    )


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name.lower(): "[REDACTED]" if SENSITIVE_FIELD.search(name) else value
        for name, value in headers.items()
    }


def _route_key(path: str) -> str | None:
    return re.sub(r"/+", "/", path.split("?", 1)[0]).rstrip("/") or "/"


def _matches_declared_route(path: str, route_templates: list[str]) -> bool:
    normalized = _route_key(path)
    for template in route_templates:
        pattern = re.escape(_route_key(template)).replace(r"\{id\}", r"[^/]+")
        if re.fullmatch(pattern, normalized):
            return True
    return False


def _observed_api_endpoints(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    for request in requests:
        url_parts = urlsplit(request["url"])
        if not url_parts.path.startswith("/api/"):
            continue
        endpoint_key = (request["method"], url_parts.path)
        endpoint = endpoints.setdefault(
            endpoint_key,
            {
                "method": request["method"],
                "path": url_parts.path,
                "query_parameters": [],
                "request_ids": [],
            },
        )
        endpoint["query_parameters"] = sorted(
            set(endpoint["query_parameters"]) | set(request["query_parameters"])
        )
        endpoint["request_ids"].append(request["id"])
    return sorted(
        endpoints.values(),
        key=lambda endpoint: (endpoint["path"], endpoint["method"]),
    )


def run_crawl(target_url: str) -> dict[str, Any]:
    target = validate_target_url(target_url)
    source_root = Path(os.environ.get("WEAK_PAGE_SOURCE_ROOT", Path(__file__).parent))
    frontend_routes = discover_frontend_routes(source_root / "js" / "router.js")
    api_routes = discover_api_routes(
        source_root / "backend" / "src" / "app.js",
        source_root / "backend" / "routes",
    )
    templates = [route["template"] for route in frontend_routes]
    captured_requests: list[dict[str, Any]] = []
    capture_errors: list[str] = []
    request_records: dict[int, dict[str, Any]] = {}
    target_parts = urlsplit(target)
    origin = ("http", target_parts.hostname or "", 3009)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(service_workers="block")

        def restrict_request(route: Any) -> None:
            request = route.request
            if (
                _same_origin(request.url, origin)
                and request.method in {"GET", "HEAD"}
            ):
                route.continue_()
            else:
                route.abort()

        context.route("**/*", restrict_request)
        page = context.new_page()

        def record_request(request: Any) -> None:
            if not _same_origin(request.url, origin):
                return
            if len(captured_requests) >= MAX_REQUESTS:
                return
            try:
                record = {
                    "id": f"req_{len(captured_requests) + 1:04d}",
                    "method": request.method,
                    "url": _safe_url(request.url),
                    "path": urlsplit(request.url).path,
                    "query_parameters": sorted(
                        {
                            name
                            for name, _ in parse_qsl(
                                urlsplit(request.url).query,
                                keep_blank_values=True,
                            )
                        }
                    ),
                    "resource_type": request.resource_type,
                    "request_headers": _safe_headers(request.headers),
                    "response": None,
                }
                captured_requests.append(record)
                request_records[id(request)] = record
            except Exception as error:
                capture_errors.append(
                    f"No se pudo registrar una petición: {type(error).__name__}"
                )

        def record_response(response: Any) -> None:
            record = request_records.get(id(response.request))
            if record is None:
                return
            try:
                record["response"] = {
                    "status": response.status,
                    "status_text": response.status_text,
                    "headers": _safe_headers(response.all_headers()),
                }
            except Exception as error:
                capture_errors.append(
                    f"No se pudo registrar una respuesta: {type(error).__name__}"
                )

        page.on("request", record_request)
        page.on("response", record_response)

        visited: list[dict[str, Any]] = []
        discovered: list[dict[str, str]] = []
        queue: deque[str] = deque(
            route["template"]
            for route in frontend_routes
            if "{id}" not in route["template"]
        )
        queued = set(queue)
        processed: set[str] = set()

        try:
            while queue and len(processed) < MAX_ROUTES:
                route_path = queue.popleft()
                if route_path in processed or not _matches_declared_route(
                    route_path, templates
                ):
                    continue
                processed.add(route_path)
                navigation_url = f"{target}/#{route_path}"
                route_result: dict[str, Any] = {
                    "path": route_path,
                    "url": navigation_url,
                }
                try:
                    response = page.goto(
                        navigation_url,
                        wait_until="domcontentloaded",
                        timeout=NAVIGATION_TIMEOUT_MS,
                    )
                    page.wait_for_timeout(250)
                    route_result["status"] = response.status if response else None
                    route_result["title"] = page.title()
                    route_result["visited"] = True

                    links = page.locator('a[href*="#/"]').evaluate_all(
                        "nodes => nodes.map(node => node.href)"
                    )
                    for link_url in links:
                        if not _same_origin(link_url, origin):
                            continue
                        linked_path = urlsplit(link_url).fragment
                        if not linked_path.startswith("/"):
                            linked_path = f"/{linked_path}"
                        linked_path = _route_key(linked_path)
                        if (
                            linked_path not in queued
                            and len(queued) < MAX_ROUTES
                            and _matches_declared_route(linked_path, templates)
                        ):
                            queued.add(linked_path)
                            discovered.append(
                                {"path": linked_path, "source_path": route_path}
                            )
                            queue.append(linked_path)
                except Exception as error:
                    route_result["visited"] = False
                    route_result["error"] = type(error).__name__
                visited.append(route_result)
        finally:
            browser.close()

    for route in frontend_routes:
        route["visited"] = any(
            _matches_declared_route(item["path"], [route["template"]])
            for item in visited
        )
        if "{id}" in route["template"] and not route["visited"]:
            route["note"] = "La ruta requiere un identificador y no fue inferido ni enviado."

    return {
        "tool": "weakPageCrawler",
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "same_origin_only": True,
            "allowed_methods": ["GET", "HEAD"],
            "forms_submitted": False,
            "response_bodies_saved": False,
            "request_limit": MAX_REQUESTS,
            "route_limit": MAX_ROUTES,
        },
        "frontend_routes": {
            "declared": frontend_routes,
            "visited": visited,
            "discovered_from_links": discovered,
            "declared_count": len(frontend_routes),
            "visited_count": sum(item["visited"] for item in visited),
        },
        "api_routes_from_source": api_routes,
        "observed_endpoints": _observed_api_endpoints(captured_requests),
        "requests": captured_requests,
        "request_count": len(captured_requests),
        "capture_errors": capture_errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crawler pasivo del laboratorio local weak_page."
    )
    parser.add_argument("--target-url", default=DEFAULT_TARGET)
    args = parser.parse_args()
    try:
        report = run_crawl(args.target_url)
    except Exception as error:
        print(
            json.dumps(
                {
                    "tool": "weakPageCrawler",
                    "target": args.target_url,
                    "error": str(error),
                },
                ensure_ascii=False,
            )
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
