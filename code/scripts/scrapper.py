#!/usr/bin/env python3
"""Synthetic-input route and request mapper for the project's own weak_page lab."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

DEFAULT_TARGET = "http://weak-page:3009"
ALLOWED_HOSTS = {"weak-page", "weak-page-lab"}
MAX_ROUTES = 40
MAX_REQUESTS = 500
MAX_BODY_BYTES = 64 * 1024
MAX_CAPTURED_BODIES = 200
NAVIGATION_TIMEOUT_MS = 12_000
FORM_SETTLE_MS = 700
MAX_FORM_SUBMISSIONS = 40
CRAWLER_PROBE_HEADER = "x-weak-page-crawler"
CRAWLER_PROBE_VALUE = "synthetic-probe"
SENSITIVE_FIELD = re.compile(
    r"password|passwd|secret|token|(?:api[_-]?)?key|authorization|cookie|session|"
    r"csrf|xsrf|email|username|user_name|phone|address|postal",
    re.IGNORECASE,
)
PERSONAL_FIELD = re.compile(r"^(?:name|full_?name|city|user)$", re.IGNORECASE)
EMAIL_ADDRESS = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_NUMBER = re.compile(r"(?<!\w)\+?\d[\d ().-]{7,}\d(?!\w)")
PRIVATE_API_PATH = re.compile(
    r"^/api/(?:auth|me(?:/|$)|orders(?:/|$)|contact(?:/|$)|admin/users(?:/|$))",
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


def _query_values(url: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name, value in parse_qsl(
        urlsplit(url).query,
        keep_blank_values=True,
    ):
        if name in values:
            previous = values[name]
            values[name] = (
                [*previous, value] if isinstance(previous, list) else [previous, value]
            )
        else:
            values[name] = value
    return values


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name.lower(): "[REDACTED]" if SENSITIVE_FIELD.search(name) else value
        for name, value in headers.items()
    }


def _sanitize_json(value: Any, private_context: bool) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            if SENSITIVE_FIELD.search(str(key)) or (
                private_context and PERSONAL_FIELD.fullmatch(str(key))
            ):
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize_json(item, private_context)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_json(item, private_context) for item in value]
    if private_context and isinstance(value, str):
        value = EMAIL_ADDRESS.sub("[REDACTED_EMAIL]", value)
        value = PHONE_NUMBER.sub("[REDACTED_PHONE]", value)
    return value


def _sanitize_body(
    body: str | bytes | None,
    content_type: str,
    path: str,
) -> dict[str, Any] | None:
    if body is None:
        return None
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if len(raw) > MAX_BODY_BYTES:
        return {
            "captured": False,
            "reason": "body_too_large",
            "content_type": media_type,
            "data": None,
            "bytes": len(raw),
        }
    if not raw:
        return None

    text = raw.decode("utf-8", errors="replace")
    private_context = bool(PRIVATE_API_PATH.search(path))
    if media_type == "application/x-www-form-urlencoded":
        from urllib.parse import parse_qsl

        values: dict[str, Any] = {}
        for key, value in parse_qsl(text, keep_blank_values=True):
            safe_value = "[REDACTED]" if SENSITIVE_FIELD.search(key) or (
                private_context and PERSONAL_FIELD.fullmatch(key)
            ) else value
            if key in values:
                previous = values[key]
                values[key] = [*previous, safe_value] if isinstance(previous, list) else [previous, safe_value]
            else:
                values[key] = safe_value
        return {
            "captured": True,
            "content_type": media_type,
            "data": values,
        }
    if "json" in media_type:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {
                "captured": False,
                "reason": "invalid_json",
                "content_type": media_type,
                "data": None,
                "bytes": len(raw),
            }
        return {
            "captured": True,
            "content_type": media_type,
            "data": _sanitize_json(parsed, private_context),
        }
    if media_type.startswith("text/"):
        if private_context:
            return {
                "captured": False,
                "reason": "private_text_body_redacted",
                "content_type": media_type,
                "data": None,
                "bytes": len(raw),
            }
        return {
            "captured": True,
            "content_type": media_type,
            "data": text,
        }
    return {
        "captured": False,
        "reason": "unsupported_content_type",
        "content_type": media_type or "unknown",
        "data": None,
        "bytes": len(raw),
    }


def _response_body_for_report(
    body: dict[str, Any] | None, content_type: str
) -> dict[str, Any]:
    """Return response bodies in Recon's stable captured/content_type/data shape."""
    media_type = content_type.split(";", 1)[0].strip().lower()
    if not isinstance(body, dict):
        return {
            "captured": False,
            "content_type": media_type,
            "data": None,
        }

    return {
        "captured": body.get("captured") is True,
        "content_type": body.get("content_type") or media_type,
        "data": body.get("data", body.get("text")),
    }


def _complete_request_records(requests: list[dict[str, Any]]) -> None:
    """Keep requests without an HTTP response representable in the input contract."""
    for request in requests:
        if not isinstance(request.get("response"), dict):
            request["response"] = {
                "status": None,
                "status_text": "",
                "headers": {},
                "body": _response_body_for_report(None, ""),
            }
            continue

        response = request["response"]
        response["body"] = _response_body_for_report(
            response.get("body"),
            response.get("headers", {}).get("content-type", ""),
        )


def _discover_forms(page: Any) -> list[dict[str, Any]]:
    forms = page.locator("form").evaluate_all(
        """forms => forms.map((form, formIndex) => {
            const marker = `weak-page-form-${formIndex}`;
            form.setAttribute("data-weak-page-form", marker);
            const fields = Array.from(form.querySelectorAll("input, textarea, select"))
                .map((field, fieldIndex) => {
                    const fieldMarker = `${marker}-field-${fieldIndex}`;
                    field.setAttribute("data-weak-page-field", fieldMarker);
                    return {
                    marker: fieldMarker,
                    name: field.name || "",
                    id: field.id || "",
                    type: field.type || field.tagName.toLowerCase(),
                    required: Boolean(field.required),
                    disabled: Boolean(field.disabled),
                    read_only: Boolean(field.readOnly),
                    autocomplete: field.autocomplete || "",
                    options: field.tagName === "SELECT"
                        ? Array.from(field.options)
                            .filter(option => !option.disabled)
                            .map(option => option.value)
                        : []
                };
            });
            const submitters = Array.from(form.querySelectorAll(
                'button, input[type="submit"], input[type="image"]'
            )).filter(button => !button.disabled).map((button, buttonIndex) => {
                const submitterMarker = `${marker}-submit-${buttonIndex}`;
                button.setAttribute("data-weak-page-submit", submitterMarker);
                return {
                    marker: submitterMarker,
                    text: (button.innerText || button.value || "").trim()
                };
            });
            return {
                marker,
                id: form.id || "",
                action: form.getAttribute("action") || "",
                method: (form.getAttribute("method") || "GET").toUpperCase(),
                fields,
                submitters
            };
        })"""
    )
    return forms


def _synthetic_field_value(field: dict[str, Any]) -> str | None:
    """Provide harmless, non-account data that passes common client-side checks."""
    if field.get("disabled") or field.get("read_only"):
        return None

    field_type = str(field.get("type") or "text").casefold()
    name = str(field.get("name") or field.get("id") or "").casefold()
    if field_type in {"hidden", "submit", "button", "reset", "image", "file"}:
        return None
    if field_type in {"checkbox", "radio"}:
        return "__check__" if field.get("required") else None
    if field_type in {"select-one", "select-multiple", "select"}:
        return next((option for option in field.get("options", []) if option), None)
    if field_type == "password" or "password" in name or "passwd" in name:
        return "WeakPageCrawler-Invalid-Only"
    if field_type == "email" or "email" in name:
        return "weakpage-crawler@invalid.example"
    if field_type == "tel" or any(term in name for term in ("phone", "mobile", "tel")):
        return "5550100100"
    if field_type == "number":
        return "0"
    if field_type == "url":
        return "https://example.invalid"
    if field_type == "date":
        return "2000-01-01"
    if field_type == "datetime-local":
        return "2000-01-01T00:00"
    if field_type == "time":
        return "00:00"
    if field_type == "month":
        return "2000-01"
    if field_type == "color":
        return "#000000"
    if field_type == "range":
        return "0"
    if "postal" in name or "zip" in name:
        return "00000"
    if "message" in name or field_type == "textarea":
        return "Synthetic weakPageCrawler probe message."
    if "subject" in name:
        return "Synthetic crawler probe"
    if name in {"name", "full_name", "fullname"}:
        return "Weak Page Crawler"
    return "weakpage synthetic input"


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
            },
        )
        endpoint["query_parameters"] = sorted(
            set(endpoint["query_parameters"]) | set(request["query_parameters"])
        )
    return sorted(
        endpoints.values(),
        key=lambda endpoint: (endpoint["path"], endpoint["method"]),
    )


def _build_scraping_report(
    target: str, captured_requests: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build only the public input contract consumed by Recon."""
    _complete_request_records(captured_requests)
    request_fields = (
        "id",
        "method",
        "url",
        "path",
        "request_line",
        "query_parameters",
        "query_values",
        "resource_type",
        "request_headers",
        "request_body",
        "response",
        "observed_on",
    )
    requests = []
    for request in captured_requests:
        response = request["response"]
        status = response.get("status")
        if (
            not isinstance(status, (int, float))
            or isinstance(status, bool)
        ):
            continue
        requests.append({field: request.get(field) for field in request_fields})

    return {
        "target": target,
        "observed_endpoints": _observed_api_endpoints(requests),
        "requests": requests,
    }


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
    captured_body_count = 0
    form_submission_count = 0
    allow_synthetic_writes = False
    active_route_url: str | None = None
    interactions: list[dict[str, Any]] = []
    target_parts = urlsplit(target)
    origin = ("http", target_parts.hostname or "", 3009)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(service_workers="block")

        def restrict_request(route: Any) -> None:
            request = route.request
            request_path = urlsplit(request.url).path
            read_only = request.method in {"GET", "HEAD"}
            synthetic_api_write = (
                allow_synthetic_writes
                and request_path.startswith("/api/")
                and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            )
            if not _same_origin(request.url, origin):
                route.abort()
            elif read_only:
                route.continue_()
            elif synthetic_api_write:
                headers = dict(request.headers)
                headers[CRAWLER_PROBE_HEADER] = CRAWLER_PROBE_VALUE
                route.continue_(headers=headers)
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
                safe_url = _safe_url(request.url)
                url_parts = urlsplit(safe_url)
                request_path = url_parts.path or "/"
                if url_parts.query:
                    request_path = f"{request_path}?{url_parts.query}"
                request_headers = dict(request.headers)
                if (
                    allow_synthetic_writes
                    and request.method in {"POST", "PUT", "PATCH", "DELETE"}
                    and url_parts.path.startswith("/api/")
                ):
                    request_headers[CRAWLER_PROBE_HEADER] = CRAWLER_PROBE_VALUE
                record = {
                    "id": f"req_{len(captured_requests) + 1:04d}",
                    "method": request.method,
                    "url": safe_url,
                    "path": request_path,
                    "request_line": f"{request.method} {request_path} HTTP/1.1",
                    "query_parameters": sorted(
                        {
                            name
                            for name, _ in parse_qsl(
                                urlsplit(request.url).query,
                                keep_blank_values=True,
                            )
                        }
                    ),
                    "query_values": _query_values(safe_url),
                    "resource_type": request.resource_type,
                    "request_headers": _safe_headers(request_headers),
                    "request_body": _sanitize_body(
                        request.post_data,
                        request.headers.get("content-type", ""),
                        urlsplit(request.url).path,
                    ),
                    "response": None,
                    "observed_on": [active_route_url] if active_route_url else [],
                }
                captured_requests.append(record)
                request_records[id(request)] = record
            except Exception as error:
                capture_errors.append(
                    f"No se pudo registrar una petición: {type(error).__name__}"
                )

        def record_response(response: Any) -> None:
            nonlocal captured_body_count
            record = request_records.get(id(response.request))
            if record is None:
                return
            try:
                response_headers = response.all_headers()
                path = urlsplit(response.url).path
                body = None
                content_type = response_headers.get("content-type", "")
                if (
                    path.startswith("/api/")
                    and captured_body_count < MAX_CAPTURED_BODIES
                    and (
                        "json" in content_type.lower()
                        or content_type.lower().startswith("text/")
                    )
                ):
                    content_length = response_headers.get("content-length")
                    if content_length and int(content_length) > MAX_BODY_BYTES:
                        body = {
                            "captured": False,
                            "reason": "body_too_large",
                            "content_type": content_type.split(";", 1)[0].strip().lower(),
                            "data": None,
                            "bytes": int(content_length),
                        }
                    else:
                        body = _sanitize_body(response.body(), content_type, path)
                        captured_body_count += int(body is not None)
                body = _response_body_for_report(body, content_type)
                record["response"] = {
                    "status": response.status,
                    "status_text": response.status_text,
                    "headers": _safe_headers(response_headers),
                    "body": body,
                }
            except Exception as error:
                capture_errors.append(
                    f"No se pudo registrar una respuesta: {type(error).__name__}"
                )

        def record_failed_request(request: Any) -> None:
            record = request_records.get(id(request))
            if record is not None:
                record["failure"] = request.failure or "request_failed"

        page.on("request", record_request)
        page.on("response", record_response)
        page.on("requestfailed", record_failed_request)

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
                active_route_url = navigation_url
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
                    route_result["headers"] = (
                        _safe_headers(response.all_headers()) if response else {}
                    )
                    route_result["forms"] = _discover_forms(page)

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

                    if route_path == "/catalog":
                        add_product = page.locator("[data-add-product]").first
                        try:
                            add_product.wait_for(
                                state="visible",
                                timeout=NAVIGATION_TIMEOUT_MS,
                            )
                            add_product.click(timeout=3_000)
                            page.wait_for_timeout(150)
                            interactions.append(
                                {
                                    "route": route_path,
                                    "action": "seed_local_cart_for_checkout_form",
                                    "writes_to_backend": False,
                                }
                            )
                        except Exception as error:
                            interactions.append(
                                {
                                    "route": route_path,
                                    "action": "seed_local_cart_for_checkout_form",
                                    "writes_to_backend": False,
                                    "error": type(error).__name__,
                                }
                            )

                        search = page.locator("#catalog-search")
                        category = page.locator("#catalog-category")
                        sort = page.locator("#catalog-sort")

                        if sort.count():
                            sort_options = sort.locator("option").evaluate_all(
                                "nodes => nodes.map(node => node.value).filter(Boolean)"
                            )
                            sort_value = next(
                                (value for value in sort_options if value != "featured"),
                                None,
                            )
                            if sort_value:
                                request_start = len(captured_requests)
                                sort.select_option(sort_value)
                                page.wait_for_timeout(FORM_SETTLE_MS)
                                interactions.append(
                                    {
                                        "route": route_path,
                                        "action": "sort_filter",
                                        "value": sort.input_value(),
                                        "request_ids": [
                                            item["id"]
                                            for item in captured_requests[request_start:]
                                        ],
                                    }
                                )

                        if search.count():
                            request_start = len(captured_requests)
                            search.fill("weakpage-crawler")
                            page.wait_for_timeout(FORM_SETTLE_MS)
                            interactions.append(
                                {
                                    "route": route_path,
                                    "action": "search_input",
                                    "value": search.input_value(),
                                    "request_ids": [
                                        item["id"]
                                        for item in captured_requests[request_start:]
                                    ],
                                }
                            )

                            request_start = len(captured_requests)
                            search.fill("")
                            page.wait_for_timeout(FORM_SETTLE_MS)
                            interactions.append(
                                {
                                    "route": route_path,
                                    "action": "search_input_reset",
                                    "value": search.input_value(),
                                    "request_ids": [
                                        item["id"]
                                        for item in captured_requests[request_start:]
                                    ],
                                }
                            )

                        if category.count():
                            category_options = category.locator("option").evaluate_all(
                                "nodes => nodes.map(node => node.value).filter(Boolean)"
                            )
                            category_value = next(
                                (
                                    value
                                    for value in category_options
                                    if value.casefold() != "all"
                                ),
                                None,
                            )
                            if category_value:
                                request_start = len(captured_requests)
                                category.select_option(category_value)
                                page.wait_for_timeout(FORM_SETTLE_MS)
                                interactions.append(
                                    {
                                        "route": route_path,
                                        "action": "category_filter",
                                        "value": category.input_value(),
                                        "request_ids": [
                                            item["id"]
                                            for item in captured_requests[request_start:]
                                        ],
                                    }
                                )

                        if search.count() and category.count():
                            request_start = len(captured_requests)
                            search.fill("weakpage-crawler")
                            page.wait_for_timeout(FORM_SETTLE_MS)
                            interactions.append(
                                {
                                    "route": route_path,
                                    "action": "search_with_category_filter",
                                    "value": search.input_value(),
                                    "category": category.input_value(),
                                    "request_ids": [
                                        item["id"]
                                        for item in captured_requests[request_start:]
                                    ],
                                }
                            )

                    for form in route_result["forms"]:
                        if form_submission_count >= MAX_FORM_SUBMISSIONS:
                            break
                        form_submission_count += 1
                        form_locator = page.locator(
                            f'[data-weak-page-form="{form["marker"]}"]'
                        )
                        fields_tested = []
                        field_errors = []
                        for field in form["fields"]:
                            value = _synthetic_field_value(field)
                            if value is None:
                                continue
                            field_locator = page.locator(
                                f'[data-weak-page-field="{field["marker"]}"]'
                            )
                            try:
                                if value == "__check__":
                                    field_locator.check()
                                elif field["type"] in {"select-one", "select-multiple"}:
                                    field_locator.select_option(value)
                                elif field["type"] in {"color", "range"}:
                                    field_locator.evaluate(
                                        """(element, syntheticValue) => {
                                            element.value = syntheticValue;
                                            element.dispatchEvent(new Event("input", { bubbles: true }));
                                            element.dispatchEvent(new Event("change", { bubbles: true }));
                                        }""",
                                        value,
                                    )
                                else:
                                    field_locator.fill(value)
                            except Exception as error:
                                field_errors.append(
                                    {
                                        "field": field.get("name") or field.get("id"),
                                        "error": type(error).__name__,
                                    }
                                )
                                continue
                            fields_tested.append(field.get("name") or field.get("id"))

                        request_start = len(captured_requests)
                        allow_synthetic_writes = True
                        try:
                            if form["submitters"]:
                                page.locator(
                                    '[data-weak-page-submit="'
                                    f'{form["submitters"][0]["marker"]}"]'
                                ).click(timeout=3_000)
                            else:
                                form_locator.evaluate("form => form.requestSubmit()")
                            page.wait_for_timeout(FORM_SETTLE_MS)
                        except Exception as error:
                            route_result.setdefault(
                                "form_submission_errors", []
                            ).append(
                                {
                                    "form_id": form.get("id", ""),
                                    "error": type(error).__name__,
                                }
                            )
                        finally:
                            allow_synthetic_writes = False

                        submitted_requests = captured_requests[request_start:]
                        interactions.append(
                            {
                                "route": route_path,
                                "action": "synthetic_form_submission",
                                "form_id": form.get("id", ""),
                                "fields_tested": fields_tested,
                                "field_errors": field_errors,
                                "request_ids": [
                                    request["id"] for request in submitted_requests
                                ],
                                "status": (
                                    "request_captured"
                                    if submitted_requests
                                    else "submitted_no_request_observed"
                                ),
                                "response_status": next(
                                    (
                                        request["response"]["status"]
                                        for request in reversed(submitted_requests)
                                        if request.get("response")
                                    ),
                                    None,
                                ),
                                "writes_persisted": False,
                            }
                        )
                except Exception as error:
                    route_result["visited"] = False
                    route_result["error"] = type(error).__name__
                visited.append(route_result)
        finally:
            browser.close()

    return _build_scraping_report(target, captured_requests)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crawler con interacciones sintéticas acotadas del laboratorio weak_page."
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
