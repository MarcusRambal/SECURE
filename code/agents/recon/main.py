import json
import logging
import re
from urllib.parse import parse_qsl, urlsplit

from attack_types import (
    is_access_control_attack,
    is_crypto_attack,
    is_jwt_attack,
    is_sqli_attack,
    is_xss_attack,
    normalize_attack_type,
)
from contract_schemas import HighPriorityTarget, ReconPlannerOutput, ReconSummary

logger = logging.getLogger("recon-stage")
MAX_TARGETS = 50
ACCESS_CONTROL_KEYWORDS = (
    "admin",
    "user",
    "account",
    "profile",
    "basket",
    "order",
    "cart",
    "invoice",
    "document",
    "file",
    "api",
    "rest",
)
CRYPTO_KEYWORDS = (
    "config",
    "auth",
    "token",
    "secret",
    "crypto",
    "key",
    "certificate",
)


def _origin(url: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"URL inválida en el reporte de scraping: {url}") from error
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme.casefold(), parsed.hostname.casefold(), port


def _validate_scraping_report(scraping_report: dict, target_url: str) -> dict:
    if not isinstance(scraping_report, dict):
        raise ValueError("scraping_report debe ser un objeto JSON")
    report_target = scraping_report.get("target")
    if not isinstance(report_target, str) or not report_target.strip():
        raise ValueError("scraping_report.target debe ser una URL")
    if _origin(report_target.strip()) != _origin(target_url):
        raise ValueError(
            "scraping_report.target debe pertenecer al mismo origen que target_url"
        )

    observed_endpoints = scraping_report.get("observed_endpoints")
    requests = scraping_report.get("requests")
    if not isinstance(observed_endpoints, list):
        raise ValueError("scraping_report.observed_endpoints debe ser una lista")
    if not isinstance(requests, list):
        raise ValueError("scraping_report.requests debe ser una lista")

    cleaned_endpoints = []
    seen_endpoints = set()
    for index, endpoint in enumerate(observed_endpoints):
        if not isinstance(endpoint, dict):
            raise ValueError(
                f"scraping_report.observed_endpoints[{index}] debe ser un objeto"
            )
        method = endpoint.get("method")
        path = endpoint.get("path")
        query_parameters = endpoint.get("query_parameters")
        if not isinstance(method, str) or not method.strip():
            raise ValueError(
                f"scraping_report.observed_endpoints[{index}].method debe ser texto"
            )
        if not isinstance(path, str) or not path.strip():
            raise ValueError(
                f"scraping_report.observed_endpoints[{index}].path debe ser texto"
            )
        if not isinstance(query_parameters, list) or not all(
            isinstance(parameter, str) for parameter in query_parameters
        ):
            raise ValueError(
                f"scraping_report.observed_endpoints[{index}].query_parameters "
                "debe ser una lista de textos"
            )
        signature = (
            method.strip().upper(),
            path.strip(),
            tuple(sorted(set(query_parameters))),
        )
        if signature in seen_endpoints:
            continue
        seen_endpoints.add(signature)
        cleaned_endpoints.append(
            {
                "method": signature[0],
                "path": signature[1],
                "query_parameters": list(signature[2]),
            }
        )

    cleaned_requests = []
    seen_requests = {}
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            raise ValueError(f"scraping_report.requests[{index}] debe ser un objeto")
        request_id = request.get("id")
        method = request.get("method")
        url = request.get("url")
        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError(f"scraping_report.requests[{index}].id debe ser texto")
        if not isinstance(method, str) or not method.strip():
            raise ValueError(
                f"scraping_report.requests[{index}].method debe ser texto"
            )
        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"scraping_report.requests[{index}].url debe ser texto")
        if _origin(url.strip()) != _origin(target_url):
            logger.warning(
                "Recon omite request fuera del origen objetivo: %s", request_id
            )
            continue
        for field in ("path", "request_line", "resource_type"):
            if not isinstance(request.get(field), str):
                raise ValueError(
                    f"scraping_report.requests[{index}].{field} debe ser texto"
                )
        if not isinstance(request.get("request_headers"), dict):
            raise ValueError(
                f"scraping_report.requests[{index}].request_headers debe ser objeto"
            )
        if not isinstance(request.get("query_values"), dict):
            raise ValueError(
                f"scraping_report.requests[{index}].query_values debe ser objeto"
            )
        query_parameters = request.get("query_parameters")
        if not isinstance(query_parameters, list) or not all(
            isinstance(parameter, str) for parameter in query_parameters
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].query_parameters debe ser lista"
            )
        observed_on = request.get("observed_on")
        if not isinstance(observed_on, list) or not all(
            isinstance(item, str) for item in observed_on
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].observed_on debe ser lista"
            )
        request_body = request.get("request_body")
        if request_body is not None and not isinstance(request_body, dict):
            raise ValueError(
                f"scraping_report.requests[{index}].request_body debe ser objeto o null"
            )
        response = request.get("response")
        if not isinstance(response, dict):
            raise ValueError(
                f"scraping_report.requests[{index}].response debe ser objeto"
            )
        status = response.get("status")
        if status is not None and (
            not isinstance(status, (int, float)) or isinstance(status, bool)
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].response.status "
                "debe ser numérico o null"
            )
        if (
            not isinstance(response.get("status_text"), str)
            or not isinstance(response.get("headers"), dict)
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].response está mal formado"
            )
        response_body = response.get("body")
        if (
            not isinstance(response_body, dict)
            or not isinstance(response_body.get("captured"), bool)
            or not isinstance(response_body.get("content_type"), str)
            or "data" not in response_body
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].response.body está mal formado"
            )

        normalized = {
            **request,
            "id": request_id.strip(),
            "method": method.strip().upper(),
            "url": url.strip(),
            "observed_on": list(dict.fromkeys(item for item in observed_on if item)),
        }
        signature = json.dumps(
            {
                key: normalized[key]
                for key in (
                    "method",
                    "url",
                    "query_parameters",
                    "query_values",
                    "request_headers",
                    "request_body",
                )
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        duplicate_index = seen_requests.get(signature)
        if duplicate_index is None:
            seen_requests[signature] = len(cleaned_requests)
            cleaned_requests.append(normalized)
            continue
        original = cleaned_requests[duplicate_index]
        original["observed_on"] = list(
            dict.fromkeys([*original["observed_on"], *normalized["observed_on"]])
        )
        original_body = original["response"].get("body", {})
        duplicate_body = normalized["response"].get("body", {})
        if not original_body.get("captured") and duplicate_body.get("captured"):
            original["response"] = normalized["response"]

    return {
        "target": report_target.strip(),
        "observed_endpoints": cleaned_endpoints,
        "requests": cleaned_requests,
    }


def _captured_request(request: dict, attack_type: str = "") -> dict:
    raw_body = request.get("request_body")
    if isinstance(raw_body, dict) and isinstance(raw_body.get("captured"), bool):
        body = raw_body.get("data") if raw_body["captured"] else None
    else:
        body = raw_body
    if is_xss_attack(attack_type):
        allowed_headers = {"content-type", "accept"}
    elif is_access_control_attack(attack_type) or is_crypto_attack(attack_type):
        allowed_headers = {
            "authorization",
            "cookie",
            "content-type",
            "accept",
            "x-auth-token",
        }
    else:
        allowed_headers = {
            "host",
            "content-type",
            "accept",
            "referer",
            "user-agent",
        }
    headers = request.get("request_headers", {})
    headers = headers if isinstance(headers, dict) else {}
    return {
        "id": request["id"],
        "method": request["method"],
        "url": request["url"],
        "headers": {
            name: value
            for name, value in headers.items()
            if isinstance(name, str) and name.casefold() in allowed_headers
        },
        "body": body,
        "observed_on": request.get("observed_on", []),
        "observed_pages": request.get("observed_pages", []),
        "reflected_parameters": request.get("reflected_parameters", []),
    }


def _query_values(request: dict) -> dict:
    values = request.get("query_values")
    if values:
        return values
    return {
        name: value
        for name, value in parse_qsl(
            urlsplit(request["url"]).query,
            keep_blank_values=True,
        )
    }


def _has_input(request: dict) -> bool:
    body = _captured_request(request)["body"]
    return bool(_query_values(request) or body)


def _is_id_bearing_url(url: str) -> bool:
    path = urlsplit(url).path
    return bool(
        "{id}" in url
        or re.search(r"/\d+(?:/|$)", path)
        or re.search(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)",
            path,
        )
    )


def _reflected_parameters(request: dict) -> list[str]:
    """Parámetros cuyo valor observado aparece reflejado en la respuesta capturada."""
    response = request.get("response")
    response = response if isinstance(response, dict) else {}
    body = response.get("body")
    body = body if isinstance(body, dict) else {}
    data = body.get("data")
    if data is None:
        return []
    try:
        serialized = json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError):
        return []
    reflected = []
    for name, value in _query_values(request).items():
        if value and str(value) in serialized:
            reflected.append(name)
    return reflected


def _pages_by_path(requests: list[dict]) -> dict[str, list[str]]:
    """Páginas observadas por ruta de API, correlacionando todas las peticiones."""
    pages: dict[str, list[str]] = {}
    for request in requests:
        path = urlsplit(request["url"]).path.rstrip("/") or "/"
        bucket = pages.setdefault(path, [])
        for page in request.get("observed_on", []):
            if page not in bucket:
                bucket.append(page)
    return pages


def _make_target(
    request: dict,
    index: int,
    attack_type: str,
    reason: str,
) -> HighPriorityTarget:
    captured = _captured_request(request, attack_type)
    if attack_type == "sqli":
        tool = "sqlmap"
    elif attack_type == "xss":
        # El validador de navegador ofrece una confirmación más fuerte que
        # Dalfox para XSS reflejados/almacenados, sin quedarse acotado a la
        # lab weak_page específica.
        tool = "browserXssValidator"
    elif is_access_control_attack(attack_type):
        tool = "access_control_prober"
    else:
        tool = "crypto_inspector"
    return HighPriorityTarget(
        target_id=f"target_{index:03d}",
        request_id=captured["id"],
        vulnerability_target=reason,
        endpoint=captured["url"],
        method=captured["method"],
        request=captured,
        recommended_tool=tool,
    )


def build_recon_output(
    target_url: str,
    attack_type_filter: str,
    scraping_report: dict,
) -> ReconPlannerOutput:
    """Build validation targets deterministically from the normalized scrape."""
    report = _validate_scraping_report(scraping_report, target_url)
    requests = report["requests"]
    normalized_attack = normalize_attack_type(attack_type_filter)
    target_inputs = []

    if is_sqli_attack(attack_type_filter):
        target_inputs = [
            request
            for request in requests
            if _has_input(request)
        ]
    elif is_xss_attack(attack_type_filter):
        target_inputs = [
            request
            for request in requests
            if _has_input(request)
        ]
    elif is_access_control_attack(attack_type_filter):
        target_inputs = [
            request
            for request in requests
            if _is_id_bearing_url(request["url"])
            or any(keyword in request["url"].casefold() for keyword in ACCESS_CONTROL_KEYWORDS)
        ]
    elif is_crypto_attack(attack_type_filter):
        target_inputs = [
            request
            for request in requests
            if any(keyword in request["url"].casefold() for keyword in CRYPTO_KEYWORDS)
        ]
    elif is_jwt_attack(attack_type_filter):
        target_inputs = []
    else:
        target_inputs = []

    xss_pages = _pages_by_path(requests) if is_xss_attack(attack_type_filter) else {}
    targets = []
    for request in target_inputs[:MAX_TARGETS]:
        if is_xss_attack(attack_type_filter):
            path = urlsplit(request["url"]).path.rstrip("/") or "/"
            request = {
                **request,
                "observed_pages": xss_pages.get(path, []),
                "reflected_parameters": _reflected_parameters(request),
            }
        if is_sqli_attack(attack_type_filter):
            reason = "Solicitud observada con datos de entrada; validar posible SQLi"
        elif is_xss_attack(attack_type_filter):
            reason = "Solicitud observada con datos de entrada; validar posible XSS"
        elif is_access_control_attack(attack_type_filter):
            reason = "Request observada sobre una ruta relevante para control de acceso"
        else:
            reason = "Request observada en una superficie criptográfica relevante"
        targets.append(
            _make_target(
                request,
                len(targets) + 1,
                normalized_attack,
                reason,
            )
        )

    summary = ReconSummary(
        target_url=target_url,
        attack_type_filter=normalized_attack,
        total_targets_identified=len(targets),
        total_requests_captured=len(requests),
    )
    result = ReconPlannerOutput(
        recon_summary=summary,
        high_priority_targets=targets,
    )
    logger.info(
        "Recon determinístico completado attack_type=%s requests=%d targets=%d",
        normalized_attack,
        len(requests),
        len(targets),
    )
    return result
