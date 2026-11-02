import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from urllib.parse import parse_qsl, urlsplit

from contract_schemas import HighPriorityTarget, ReconPlannerOutput, ReconSummary
from attack_types import (
    is_access_control_attack,
    is_crypto_attack,
    is_sqli_attack,
    is_xss_attack,
)
from weak_page_xss import (
    classify_weak_page_xss_surface,
    is_weak_page_origin,
    is_weak_page_target,
)
  
logger = logging.getLogger("recon-agent-worker")
MAX_XSS_ENTRY_POINT_TARGETS = 20


def log_preview(value: object, limit: int = 500) -> str:
    """Resume valores grandes para mantener los logs legibles."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text)} chars]"


def clean_scraping_report(scraping_report: dict | None) -> dict:
    """Valida el contrato externo de scraping y elimina registros duplicados."""
    if not isinstance(scraping_report, dict):
        raise ValueError("scraping_report debe ser un objeto JSON")

    target = scraping_report.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("scraping_report.target debe ser una URL o endpoint")

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
                "scraping_report.observed_endpoints"
                f"[{index}].query_parameters debe ser una lista de textos"
            )

        normalized_endpoint = {
            **endpoint,
            "method": method.strip().upper(),
            "path": path.strip(),
            "query_parameters": list(dict.fromkeys(query_parameters)),
        }
        signature = (
            normalized_endpoint["method"],
            normalized_endpoint["path"],
            tuple(sorted(normalized_endpoint["query_parameters"])),
        )
        if signature in seen_endpoints:
            continue
        seen_endpoints.add(signature)
        cleaned_endpoints.append(normalized_endpoint)

    cleaned_requests = []
    request_indexes = {}
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
        if not isinstance(request.get("path"), str):
            raise ValueError(f"scraping_report.requests[{index}].path debe ser texto")
        if not isinstance(request.get("request_line"), str):
            raise ValueError(
                f"scraping_report.requests[{index}].request_line debe ser texto"
            )
        if not isinstance(request.get("resource_type"), str):
            raise ValueError(
                f"scraping_report.requests[{index}].resource_type debe ser texto"
            )
        if not isinstance(request.get("request_headers"), dict):
            raise ValueError(
                f"scraping_report.requests[{index}].request_headers debe ser un objeto"
            )
        if not isinstance(request.get("query_values"), dict):
            raise ValueError(
                f"scraping_report.requests[{index}].query_values debe ser un objeto"
            )
        query_parameters = request.get("query_parameters")
        if not isinstance(query_parameters, list) or not all(
            isinstance(parameter, str) for parameter in query_parameters
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].query_parameters debe ser una lista"
            )
        observed_on = request.get("observed_on")
        if not isinstance(observed_on, list) or not all(
            isinstance(item, str) for item in observed_on
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].observed_on debe ser una lista"
            )
        if request.get("request_body") is not None and not isinstance(
            request["request_body"], dict
        ):
            raise ValueError(
                f"scraping_report.requests[{index}].request_body debe ser objeto o null"
            )
        response = request.get("response")
        if not isinstance(response, dict):
            raise ValueError(
                f"scraping_report.requests[{index}].response debe ser un objeto"
            )
        response_status = response.get("status")
        if response_status is not None and (
            not isinstance(response_status, (int, float))
            or isinstance(response_status, bool)
        ):
            raise ValueError(
                "scraping_report.requests"
                f"[{index}].response.status debe ser numérico o null"
            )
        if not isinstance(response.get("status_text"), str):
            raise ValueError(
                f"scraping_report.requests[{index}].response.status_text debe ser texto"
            )
        if not isinstance(response.get("headers"), dict):
            raise ValueError(
                f"scraping_report.requests[{index}].response.headers debe ser un objeto"
            )
        response_body = response.get("body")
        if (
            not isinstance(response_body, dict)
            or not isinstance(response_body.get("captured"), bool)
            or not isinstance(response_body.get("content_type"), str)
            or "data" not in response_body
        ):
            raise ValueError(
                "scraping_report.requests"
                f"[{index}].response.body debe incluir captured, content_type y data"
            )

        normalized_request = {
            **request,
            "id": request_id.strip(),
            "method": method.strip().upper(),
            "url": url.strip(),
            "observed_on": list(
                dict.fromkeys(
                    item for item in observed_on if item
                )
            ),
        }
        signature_request = {
            key: normalized_request[key]
            for key in (
                "method",
                "url",
                "query_parameters",
                "query_values",
                "request_headers",
                "request_body",
            )
        }
        signature = json.dumps(
            signature_request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        duplicate_index = request_indexes.get(signature)
        if duplicate_index is None:
            request_indexes[signature] = len(cleaned_requests)
            cleaned_requests.append(normalized_request)
            continue

        kept_request = cleaned_requests[duplicate_index]
        kept_request["observed_on"] = list(
            dict.fromkeys(
                [*kept_request["observed_on"], *normalized_request["observed_on"]]
            )
        )
        kept_response_body = kept_request["response"].get("body", {})
        duplicate_response_body = normalized_request["response"].get("body", {})
        if (
            not kept_response_body.get("captured")
            and duplicate_response_body.get("captured")
        ):
            kept_request["response"] = normalized_request["response"]

    return {
        "target": target.strip(),
        "observed_endpoints": cleaned_endpoints,
        "requests": cleaned_requests,
    }




def _request_query_parameters(request: dict) -> dict[str, object]:
    parameters = request.get("query_parameters")
    if isinstance(parameters, dict):
        return parameters
    try:
        pairs = parse_qsl(
            urlsplit(str(request.get("url") or "")).query,
            keep_blank_values=True,
        )
    except ValueError:
        return {}
    values: dict[str, object] = {}
    for name, value in pairs:
        if name in values:
            previous = values[name]
            values[name] = (
                [*previous, value] if isinstance(previous, list) else [previous, value]
            )
        else:
            values[name] = value
    return values

def _request_has_sqli_input(request: dict) -> bool:
    return request.get("body") is not None or bool(
        _request_query_parameters(request)
    )

# Construye el contexto de reconocimiento específico para ataques SQLi.
def build_sqli_recon_context(clean_scraping_report: dict, available_tools: list[dict]) -> dict:
    """Reduce el reporte de scraping limpio a los inputs relevantes para SQLi."""
    sql_inputs = []
    for request in clean_scraping_report.get("requests", []):
        if not isinstance(request, dict):
            continue

        request_body = request.get("request_body")
        if isinstance(request_body, dict) and isinstance(
            request_body.get("captured"), bool
        ):
            body = (
                request_body.get("data", request_body.get("text"))
                if request_body["captured"]
                else None
            )
        else:
            body = request_body

        query_parameters = request.get("query_values")
        if not isinstance(query_parameters, dict) or not query_parameters:
            query_parameters = _request_query_parameters(
                {"url": request.get("url")}
            )

        normalized_request = {
            "id": request.get("id"),
            "method": request.get("method"),
            "url": request.get("url"),
            "path": request.get("path"),
            "resource_type": request.get("resource_type"),
            "headers": request.get("request_headers"),
            "body": body,
            "query_parameters": query_parameters,
        }
        if not _request_has_sqli_input(normalized_request):
            continue

        headers = normalized_request["headers"]
        headers = headers if isinstance(headers, dict) else {}
        sql_inputs.append(
            {
                "id": normalized_request["id"],
                "method": normalized_request["method"],
                "url": normalized_request["url"],
                "path": normalized_request["path"],
                "resource_type": normalized_request["resource_type"],
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and name.casefold()
                    in {"host", "content-type", "accept", "referer", "user-agent"}
                },
                "body": normalized_request["body"],
                "query_parameters": normalized_request["query_parameters"],
            }
        )

    return {
        "attack_type_filter": "sqli",
        "target": clean_scraping_report["target"],
        "total_requests_captured": len(clean_scraping_report.get("requests", [])),
        "sqli_input_entry_points": sql_inputs,
        "available_validation_tools": available_tools,
    }







def _has_xss_input(endpoint: str, request: dict) -> bool:
    try:
        if "=" in urlsplit(endpoint).query:
            return True
    except ValueError:
        return False
    body = request.get("body")
    if isinstance(body, str):
        return bool(body.strip())
    return bool(body)


def _xss_request_signature(method: str, endpoint: str, request: dict) -> tuple:
    """Identify a repeated injection surface without depending on sample values."""
    parts = urlsplit(endpoint)
    query_names = tuple(
        sorted(
            name
            for name, _ in parse_qsl(parts.query, keep_blank_values=True)
            if name
        )
    )
    normalized_url = (
        parts.scheme.casefold(),
        parts.netloc.casefold(),
        parts.path or "/",
    )
    body = request.get("body")
    headers = request.get("headers")
    if isinstance(headers, dict):
        content_type = next(
            (
                str(value).split(";", 1)[0].strip().casefold()
                for name, value in headers.items()
                if isinstance(name, str) and name.casefold() == "content-type"
            ),
            "",
        )
        relevant_headers = tuple(
            sorted(
                (str(name).casefold(), str(value))
                for name, value in headers.items()
                if isinstance(name, str)
                and name.casefold()
                in {"content-type", "authorization", "cookie"}
            )
        )
    else:
        content_type = ""
        relevant_headers = ()

    if isinstance(body, dict):
        body_signature = ("fields", tuple(sorted(_json_field_paths(body))))
    elif isinstance(body, str) and content_type == "application/x-www-form-urlencoded":
        body_signature = (
            "fields",
            tuple(
                sorted(
                    name
                    for name, _ in parse_qsl(body, keep_blank_values=True)
                    if name
                )
            ),
        )
    elif isinstance(body, str) and content_type == "application/json":
        try:
            body_data = json.loads(body)
        except json.JSONDecodeError:
            body_signature = ("raw", body.strip())
        else:
            body_signature = (
                "fields",
                tuple(sorted(_json_field_paths(body_data))),
            )
    elif body:
        body_signature = ("raw", str(body).strip())
    else:
        body_signature = ("empty",)
    return method.upper(), normalized_url, query_names, body_signature, relevant_headers


def _json_field_paths(value: object, prefix: str = "") -> set[str]:
    if isinstance(value, dict):
        paths = set()
        for name, child in value.items():
            path = f"{prefix}.{name}" if prefix else str(name)
            paths.update(_json_field_paths(child, path))
        return paths
    if prefix:
        return {prefix}
    return set()



def build_crypto_recon_context(
    crawler_data: dict,
    deep_crawler_data: dict | None,
    discovered_urls: list[str],
    available_tools: list[dict],
) -> dict:
    """Prepara el contexto de reconocimiento para inspeccion criptografica."""
    entry_points = []
    for request in (deep_crawler_data or {}).get("entry_points", [])[:50]:
        if not isinstance(request, dict):
            continue
        headers = request.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        entry_points.append(
            {
                "id": request.get("id"),
                "method": request.get("method"),
                "url": request.get("url"),
                "path": request.get("path"),
                "resource_type": request.get("resource_type"),
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and name.casefold() in {
                        "authorization", "content-type", "accept", "cookie", "x-auth-token"
                    }
                },
                "body": request.get("body"),
                "response_status": (request.get("response") or {}).get("status"),
            }
        )

    endpoints = [
        {
            "template": endpoint.get("template"),
            "sample_urls": endpoint.get("sample_urls", []),
            "methods": endpoint.get("methods", []),
        }
        for endpoint in crawler_data.get("navigation", {}).get("endpoints", [])[:50]
        if isinstance(endpoint, dict)
    ]

    interesting_urls = [
        url for url in discovered_urls
        if any(keyword in url.lower() for keyword in [
            "config", "admin", "api", "rest", "auth", "login", "token", "user", "secret", "crypto"
        ])
    ][:50]

    return {
        "attack_type_filter": "crypto_inspector",
        "crawler_endpoints": endpoints,
        "interesting_urls": interesting_urls,
        "captured_entry_points": entry_points,
        "deduplicated_urls": discovered_urls[:100],
        "available_validation_tools": available_tools,
    }

    crawler_endpoints = [
        {
            "template": endpoint.get("template"),
            "sample_urls": endpoint.get("sample_urls", []),
            "methods": endpoint.get("methods", []),
        }
        for endpoint in crawler_data.get("navigation", {}).get("endpoints", [])[:50]
        if isinstance(endpoint, dict)
    ]
    sqli_context = {
        "crawler": {
            "target": crawler_data.get("target", {}),
            "endpoints": crawler_endpoints,
        },
        "deduplicated_urls": discovered_urls[:100],
        "available_validation_tools": available_tools,
    }
    if not deep_crawler_data:
        return sqli_context

    entry_points = []
    for request in deep_crawler_data.get("entry_points", [])[:40]:
        if not isinstance(request, dict):
            continue
        headers = request.get("headers", {})
        entry_points.append({
            "id": request.get("id"),
            "method": request.get("method"),
            "url": request.get("url"),
            "path": request.get("path"),
            "resource_type": request.get("resource_type"),
            "headers": {
                name: value
                for name, value in headers.items()
                if name.lower() in {"host", "content-type", "accept"}
            },
            "body": request.get("body"),
            "response_status": (request.get("response") or {}).get("status"),
        })
    sqli_context["deep_crawler"] = {
        "summary": deep_crawler_data.get("summary", {}),
        "entry_points": entry_points,
        "forms": deep_crawler_data.get("forms", [])[:20],
    }
    return sqli_context


def build_xss_recon_context(
    crawler_data: dict,
    deep_crawler_data: dict | None,
    discovered_urls: list[str],
    available_tools: list[dict],
) -> dict:
    """Keep captured query/form inputs and relevant endpoints for XSS planning."""
    is_weak_page = is_weak_page_target(
        str((deep_crawler_data or {}).get("target") or "")
    )
    entry_points = []
    seen_weak_page_surfaces = set()
    requests = (deep_crawler_data or {}).get("entry_points", [])
    for request in requests if isinstance(requests, list) else []:
        if not isinstance(request, dict):
            continue
        if is_weak_page:
            surface = classify_weak_page_xss_surface(
                str(request.get("url") or ""),
                request,
            )
            if not surface or surface in seen_weak_page_surfaces:
                continue
            seen_weak_page_surfaces.add(surface)
        headers = request.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        entry_points.append(
            {
                "id": request.get("id"),
                "method": request.get("method"),
                "url": request.get("url"),
                "path": request.get("path"),
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and name.casefold() in {"content-type", "accept"}
                },
                "body": request.get("body"),
                "observed_on": request.get("observed_on", []),
                "response_status": (request.get("response") or {}).get("status"),
            }
        )
        if len(entry_points) >= 40:
            break

    endpoints = [
        {
            "template": endpoint.get("template"),
            "sample_urls": endpoint.get("sample_urls", []),
            "methods": endpoint.get("methods", []),
        }
        for endpoint in crawler_data.get("navigation", {}).get("endpoints", [])[:50]
        if isinstance(endpoint, dict)
    ]
    context = {
        "attack_type_filter": "xss",
        "crawler_endpoints": endpoints,
        "deduplicated_urls": discovered_urls[:100],
        "captured_entry_points": entry_points,
        "available_validation_tools": available_tools,
    }
    if is_weak_page:
        return {
            **context,
            "crawler_endpoints": [],
            "deduplicated_urls": [],
            "validation_capability": (
                "Para targets con contexto de página observado, propone un validation_plan "
                "declarativo basado solo en requests/rutas/formularios capturados. "
                "Validate ejecutará el plan con el validador de navegador genérico."
            ),
        }
    return context


# Funcion de ayuda para ver el contexto que obtiene el agente
def write_recon_context_snapshot(
    target_url: str,
    attack_type_filter: str,
    context: dict,
    *,
    crawler_report: dict | None = None,
    deep_crawler_report: dict | None = None,
    tool_timings: list[dict] | None = None,
) -> Path:
    """Guarda el contexto compacto enviado al LLM para su inspeccion posterior."""
    output_dir = Path(
        os.getenv("RECON_CONTEXT_OUTPUT_DIR", Path(__file__).with_name("recon_context"))
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_target = "".join(
        character if character.isalnum() else "_" for character in target_url
    ).strip("_")
    output_path = output_dir / f"{timestamp}_{safe_target[:80]}.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "attack_type_filter": attack_type_filter,
        "context": context,
        "crawler_report": crawler_report,
        "deep_crawler_report": deep_crawler_report,
        "tool_timings": tool_timings or [],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def _sqli_entry_points(recon_sources: dict | None) -> list[dict]:
    sources = recon_sources or {}
    requests = sources.get("sqli_input_entry_points")
    if not isinstance(requests, list):
        requests = sources.get("entry_points", [])
    return [request for request in requests if isinstance(request, dict)]


def build_sqli_fallback_output(target_url: str,deep_crawler_data: dict | None,) -> dict:
    """Construye un plan SQLi minimo con peticiones observadas si el LLM no devuelve JSON."""
    requests = [
        request
        for request in _sqli_entry_points(deep_crawler_data)
        if request.get("url") and _request_has_sqli_input(request)
    ]
    targets = []
    for request in requests:
        targets.append({
            "target_id": f"target_{len(targets) + 1:03d}",
            "request_id": request.get("id") or "",
            "vulnerability_target": "sqli (observed request)",
            "endpoint": request["url"],
            "method": request.get("method", "GET"),
            "request": {
                key: request.get(key)
                for key in ("id", "method", "url", "headers", "body")
            },
            "recommended_tool": "sqlmap",
        })
        if len(targets) >= 10:
            break
    return {
        "recon_summary": {
            "target_url": target_url,
            "attack_type_filter": "sqli",
            "total_targets_identified": len(targets),
            "total_requests_captured": (deep_crawler_data or {}).get(
                "total_requests_captured", len(requests)
            ),
        },
        "high_priority_targets": targets,
    }


def ensure_sqli_entry_point_coverage(data: dict, deep_crawler_data: dict | None) -> dict:
    """Keep SQLi targets grounded in observed inputs and cover every observed input."""
    output = dict(data)
    requests = [
        request
        for request in _sqli_entry_points(deep_crawler_data)
        if (
            request.get("url")
            and _request_has_sqli_input(request)
        )
    ]
    requests_by_id = {
        request["id"]: request
        for request in requests
        if isinstance(request.get("id"), str) and request["id"]
    }
    targets = []
    covered_request_ids = set()

    for target in output.get("high_priority_targets", []):
        if not isinstance(target, dict):
            continue
        target_request = target.get("request")
        target_request = target_request if isinstance(target_request, dict) else {}
        request_id = target.get("request_id") or target_request.get("id")
        captured_request = requests_by_id.get(request_id)
        if captured_request is None:
            endpoint = target.get("endpoint") or target_request.get("url")
            method = str(target.get("method") or target_request.get("method") or "").upper()
            matches = [
                request
                for request in requests
                if request.get("url") == endpoint
                and str(request.get("method") or "").upper() == method
            ]
            if len(matches) == 1:
                captured_request = matches[0]

        if captured_request is None:
            logger.warning(
                "Recon descarta target SQLi sin request observada endpoint=%s",
                target.get("endpoint"),
            )
            continue

        captured_id = captured_request.get("id")
        if captured_id and captured_id in covered_request_ids:
            continue
        grounded_target = {
            **target,
            "request_id": captured_id or "",
            "endpoint": captured_request["url"],
            "method": captured_request.get("method", "GET"),
            "request": _build_request_from_capture(captured_request),
        }
        targets.append(grounded_target)
        if captured_id:
            covered_request_ids.add(captured_id)

    for request in requests:
        request_id = request.get("id")
        if request_id and request_id in covered_request_ids:
            continue

        targets.append({
            "target_id": f"target_{len(targets) + 1:03d}",
            "request_id": request_id or "",
            "vulnerability_target": (
                "Solicitud observada con datos de entrada; validar posible SQLi"
            ),
            "endpoint": request["url"],
            "method": request.get("method", "GET"),
            "request": {
                key: request.get(key)
                for key in ("id", "method", "url", "headers", "body")
            },
            "recommended_tool": "sqlmap",
        })
        if request_id:
            covered_request_ids.add(request_id)

    output["high_priority_targets"] = targets
    summary = dict(output.get("recon_summary", {}))
    if isinstance((deep_crawler_data or {}).get("target"), str):
        summary["target_url"] = deep_crawler_data["target"]
    summary["attack_type_filter"] = "sqli"
    summary["total_targets_identified"] = len(targets)
    summary["total_requests_captured"] = (deep_crawler_data or {}).get(
        "total_requests_captured", summary.get("total_requests_captured", len(requests))
    )
    output["recon_summary"] = summary
    return output


def ensure_xss_entry_point_coverage(
    data: dict,
    deep_crawler_data: dict | None,
    max_targets: int = MAX_XSS_ENTRY_POINT_TARGETS,
) -> dict:
    """Include observed XSS-capable requests even when Recon's LLM omits them."""
    output = dict(data)
    is_weak_page = is_weak_page_target(
        str((deep_crawler_data or {}).get("target") or "")
    )
    targets = [
        target for target in output.get("high_priority_targets", [])
        if isinstance(target, dict)
    ]
    if is_weak_page:
        scoped_targets = []
        seen_surfaces = set()
        for target in targets:
            target_request = target.get("request")
            target_request = (
                target_request if isinstance(target_request, dict) else {}
            )
            endpoint = (
                target_request.get("url")
                or target.get("endpoint")
                or target.get("url")
                or ""
            )
            if not isinstance(endpoint, str) or not is_weak_page_origin(endpoint):
                continue
            request = {
                **target_request,
                "method": target_request.get("method") or target.get("method"),
            }
            surface = classify_weak_page_xss_surface(endpoint, request)
            if surface and surface not in seen_surfaces:
                scoped_targets.append(target)
                seen_surfaces.add(surface)
        targets = scoped_targets
    requests = []
    seen_weak_page_surfaces = set()
    for request in (deep_crawler_data or {}).get("entry_points", []):
        if not isinstance(request, dict) or not isinstance(request.get("url"), str):
            continue
        if is_weak_page:
            surface = classify_weak_page_xss_surface(request["url"], request)
            if not surface or surface in seen_weak_page_surfaces:
                continue
            seen_weak_page_surfaces.add(surface)
        if _has_xss_input(request["url"], request):
            requests.append(request)

    covered_request_ids = {
        request_id
        for target in targets
        for request_id in (
            target.get("request_id"),
            (target.get("request") or {}).get("id")
            if isinstance(target.get("request"), dict)
            else None,
        )
        if request_id
    }
    covered_signatures = set()
    for target in targets:
        captured_request = _find_matching_captured_request(target, deep_crawler_data)
        target_request = target.get("request")
        target_request = target_request if isinstance(target_request, dict) else {}
        request = (
            _build_request_from_capture(captured_request)
            if captured_request
            else target_request
        )
        endpoint = (
            request.get("url")
            or target.get("endpoint")
            or target.get("url")
        )
        if not isinstance(endpoint, str) or not endpoint:
            continue
        method = str(request.get("method") or target.get("method") or "GET").upper()
        if _has_xss_input(endpoint, request):
            covered_signatures.add(_xss_request_signature(method, endpoint, request))

    for request in requests:
        if len(covered_signatures) >= max_targets:
            break
        request_id = request.get("id")
        method = str(request.get("method") or "GET").upper()
        surface = (
            classify_weak_page_xss_surface(request["url"], request)
            if is_weak_page
            else None
        )
        if surface and surface in seen_surfaces:
            continue
        signature = _xss_request_signature(method, request["url"], request)
        if (
            (request_id and request_id in covered_request_ids)
            or signature in covered_signatures
        ):
            continue
        targets.append(
            {
                "target_id": f"target_xss_{len(targets) + 1:03d}",
                "request_id": request_id or "",
                "vulnerability_target": (
                    "Solicitud observada con parámetro o body; validar posible XSS"
                ),
                "endpoint": request["url"],
                "method": method,
                "request": {
                    key: request.get(key)
                    for key in (
                        "id",
                        "method",
                        "url",
                        "headers",
                        "body",
                        "observed_on",
                    )
                },
                "recommended_tool": "dalfox",
            }
        )
        if surface:
            targets[-1]["validation_plan"] = _build_weak_page_browser_plan(
                surface,
                request,
            )
        covered_signatures.add(signature)
        if surface:
            seen_surfaces.add(surface)
        if request_id:
            covered_request_ids.add(request_id)

    output["high_priority_targets"] = targets
    summary = dict(output.get("recon_summary", {}))
    summary["total_targets_identified"] = len(targets)
    summary["total_requests_captured"] = len(
        (deep_crawler_data or {}).get("entry_points", [])
    )
    output["recon_summary"] = summary
    return output


def update_recon_context_snapshot(
    snapshot_path: Path,
    llm_output: dict,
    final_output: dict,
) -> None:
    """Append the Recon decision and normalized output to its saved context."""
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    payload["llm_output"] = llm_output
    payload["final_output"] = final_output
    snapshot_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )






def build_crypto_fallback_output(
    target_url: str,
    deep_crawler_data: dict | None,
    discovered_urls: list[str] | None = None,
) -> dict:
    """Construye un plan criptografico minimo con endpoints observados si el LLM no devuelve JSON."""
    targets = []
    requests = (deep_crawler_data or {}).get("entry_points", [])
    priority_keywords = [
        "config", "admin", "login", "auth", "token", "user", "api", "rest", "crypto"
    ]
    seen_urls = set()

    for request in requests:
        if not isinstance(request, dict) or not request.get("url"):
            continue
        req_url = request["url"]
        if req_url in seen_urls:
            continue
        if any(kw in req_url.lower() for kw in priority_keywords):
            seen_urls.add(req_url)
            targets.append({
                "target_id": f"target_{len(targets) + 1:03d}",
                "request_id": request.get("id") or "",
                "vulnerability_target": "Posible fallo criptográfico / configuración expuesta",
                "endpoint": req_url,
                "method": request.get("method", "GET"),
                "request": {
                    key: request.get(key)
                    for key in ("id", "method", "url", "headers", "body")
                },
                "recommended_tool": "crypto_inspector",
            })
            if len(targets) >= 10:
                break

    if not targets:
        for request in requests[:5]:
            if not isinstance(request, dict) or not request.get("url"):
                continue
            req_url = request["url"]
            if req_url in seen_urls:
                continue
            seen_urls.add(req_url)
            targets.append({
                "target_id": f"target_{len(targets) + 1:03d}",
                "request_id": request.get("id") or "",
                "vulnerability_target": "Solicitud observada; inspeccionar datos y tokens criptográficos",
                "endpoint": req_url,
                "method": request.get("method", "GET"),
                "request": {
                    key: request.get(key)
                    for key in ("id", "method", "url", "headers", "body")
                },
                "recommended_tool": "crypto_inspector",
            })

    if not targets and discovered_urls:
        for url in discovered_urls:
            if any(kw in url.lower() for kw in priority_keywords) and url not in seen_urls:
                seen_urls.add(url)
                targets.append({
                    "target_id": f"target_{len(targets) + 1:03d}",
                    "request_id": "",
                    "vulnerability_target": "Endpoint observado relevante para análisis criptográfico",
                    "endpoint": url,
                    "method": "GET",
                    "request": {"method": "GET", "url": url},
                    "recommended_tool": "crypto_inspector",
                })
                if len(targets) >= 5:
                    break

    if not targets:
        targets.append({
            "target_id": "target_001",
            "request_id": "",
            "vulnerability_target": "Inspección criptográfica general del objetivo",
            "endpoint": target_url,
            "method": "GET",
            "request": {"method": "GET", "url": target_url},
            "recommended_tool": "crypto_inspector",
        })

    return {
        "recon_summary": {
            "target_url": target_url,
            "attack_type_filter": "crypto_inspector",
            "total_targets_identified": len(targets),
            "total_requests_captured": len(requests),
        },
        "high_priority_targets": targets,
    }


def ensure_crypto_entry_point_coverage(
    data: dict,
    deep_crawler_data: dict | None,
    target_url: str,
    discovered_urls: list[str] | None = None,
) -> dict:
    """Asegura que existan objetivos criptograficos observados para validar si el LLM omitio targets."""
    output = dict(data)
    targets = [
        target for target in output.get("high_priority_targets", [])
        if isinstance(target, dict)
    ]
    if targets:
        return output

    logger.info(
        "[RECON] El LLM devolvió 0 targets para crypto; aplicando cobertura automática con peticiones observadas."
    )
    fallback = build_crypto_fallback_output(target_url, deep_crawler_data, discovered_urls)
    output["high_priority_targets"] = fallback["high_priority_targets"]
    summary = dict(output.get("recon_summary", {}))
    summary["total_targets_identified"] = len(output["high_priority_targets"])
    output["recon_summary"] = summary
    return output


ACCESS_CONTROL_DEFAULT_TARGETS = (
    ("/rest/basket/1", "CRITICAL", "IDOR: acceso a la cesta de otro usuario"),
    ("/api/Users", "HIGH", "Exposición de listado de usuarios"),
    (
        "/rest/admin/application-configuration",
        "HIGH",
        "Endpoint administrativo expuesto",
    ),
)


def build_access_control_default_targets(target_url: str) -> list[dict]:
    """Endpoints BAC mínimos usados cuando el LLM no propone objetivos.

    No dependen del crawling ni del LLM: garantizan que Validate siempre tenga
    algo que probar (IDOR, exposición de usuarios y admin expuesto).
    """
    base_url = str(target_url or "").rstrip("/")
    targets: list[dict] = []
    for index, (path, priority, reason) in enumerate(
        ACCESS_CONTROL_DEFAULT_TARGETS, start=1
    ):
        endpoint = f"{base_url}{path}"
        targets.append(
            {
                "target_id": f"target_{index:03d}",
                "request_id": "",
                "vulnerability_target": reason,
                "endpoint": endpoint,
                "method": "GET",
                "priority": priority,
                "request": {"method": "GET", "url": endpoint},
                "recommended_tool": "access_control_prober",
            }
        )
    return targets


def build_access_control_fallback_output(
    target_url: str,
    deep_crawler_data: dict | None,
    discovered_urls: list[str] | None = None,
) -> dict:
    """Plan mínimo de control de acceso usando solo requests/endpoints observados."""
    requests = [
        request
        for request in (deep_crawler_data or {}).get("entry_points", [])
        if isinstance(request, dict) and request.get("url")
    ]
    priority_keywords = (
        "admin", "user", "account", "profile", "basket", "order", "cart",
        "invoice", "document", "file", "api", "rest",
    )
    seen_urls: set[str] = set()
    targets: list[dict] = []

    def add_target(endpoint: str, method: str, request: dict | None, reason: str) -> None:
        if endpoint in seen_urls:
            return
        seen_urls.add(endpoint)
        targets.append(
            {
                "target_id": f"target_{len(targets) + 1:03d}",
                "request_id": (request or {}).get("id") or "",
                "vulnerability_target": reason,
                "endpoint": endpoint,
                "method": str(method or "GET").upper(),
                "request": request
                or {"method": str(method or "GET").upper(), "url": endpoint},
                "recommended_tool": "access_control_prober",
            }
        )

    # 1. Requests observadas que ya apuntan a objetos concretos.
    for request in requests:
        url = request["url"]
        if _is_id_bearing_url(url):
            add_target(
                url,
                request.get("method", "GET"),
                {key: request.get(key) for key in ("id", "method", "url", "headers", "body")},
                "Recurso observado con identificador de objeto; validar IDOR/control de acceso",
            )

    # 2. Requests observadas de superficies de usuario/admin.
    for request in requests:
        url = request["url"]
        if any(keyword in url.lower() for keyword in priority_keywords):
            add_target(
                url,
                request.get("method", "GET"),
                {key: request.get(key) for key in ("id", "method", "url", "headers", "body")},
                "Endpoint observado de usuario/administración; validar control de acceso",
            )
        if len(targets) >= 10:
            break

    # 3. URLs descubiertas relevantes.
    for url in discovered_urls or []:
        if any(keyword in url.lower() for keyword in priority_keywords):
            add_target(
                url,
                "GET",
                None,
                "Endpoint observado relevante para control de acceso",
            )
        if len(targets) >= 10:
            break

    # 4. Último recurso: endpoints BAC conocidos, para que el prober pruebe
    #    IDOR, exposición de usuarios y escalada vertical aunque no haya rutas
    #    observadas con ID.
    if not targets:
        targets.extend(build_access_control_default_targets(target_url))

    return {
        "recon_summary": {
            "target_url": target_url,
            "attack_type_filter": "access_control",
            "total_targets_identified": len(targets),
            "total_requests_captured": len(requests),
        },
        "high_priority_targets": targets,
    }


def _access_control_target_key(target: dict) -> tuple[str, str]:
    """Clave de deduplicación método + ruta para objetivos de control de acceso."""
    endpoint = (
        target.get("endpoint")
        or (target.get("request") or {}).get("url")
        or ""
    )
    return (
        str(target.get("method") or "GET").upper(),
        _normalize_request_path(str(endpoint)),
    )


def _is_useful_access_control_target(target: dict) -> bool:
    """Descarta rutas SPA (hash) que no representan recursos del backend."""
    endpoint = str(
        target.get("endpoint")
        or (target.get("request") or {}).get("url")
        or ""
    )
    return "#/" not in endpoint and endpoint.strip() != ""


def ensure_access_control_target_coverage(
    data: dict,
    deep_crawler_data: dict | None,
    target_url: str,
    discovered_urls: list[str] | None = None,
    max_targets: int = 12,
) -> dict:
    """Garantiza que los recursos observados con identificador lleguen a validación.

    El LLM de recon puede devolver objetivos genéricos (herramientas de web/sqli)
    e ignorar ``potential_idor_endpoints``. Para control de acceso los hallazgos
    deterministas dependen de que las peticiones observadas se ejecuten, así que
    se fusionan siempre, priorizando los recursos con ID.
    """
    output = dict(data)
    llm_targets = [
        target
        for target in output.get("high_priority_targets", [])
        if isinstance(target, dict)
    ]
    fallback = build_access_control_fallback_output(
        target_url, deep_crawler_data, discovered_urls
    )
    observed_targets = fallback["high_priority_targets"]

    merged: list[dict] = []
    seen: set[tuple[str, str]] = set()
    # 1. Recursos observados con ID (IDOR) primero.
    # 2. Resto de endpoints observados relevantes.
    # 3. Objetivos propuestos por el LLM (normalizados a la herramienta correcta).
    for target in observed_targets + llm_targets:
        candidate = dict(target)
        candidate["recommended_tool"] = "access_control_prober"
        if not _is_useful_access_control_target(candidate):
            continue
        key = _access_control_target_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        merged.append(candidate)
        if len(merged) >= max_targets:
            break

    if merged:
        if len(merged) > len(llm_targets):
            logger.info(
                "[RECON] Cobertura access_control ampliada: LLM=%d observados=%d final=%d",
                len(llm_targets),
                len(observed_targets),
                len(merged),
            )
        output["high_priority_targets"] = merged

    summary = dict(output.get("recon_summary", {}))
    summary["attack_type_filter"] = "access_control"
    summary["total_targets_identified"] = len(output.get("high_priority_targets", []))
    output["recon_summary"] = summary
    return output


def _normalize_request_path(value: str) -> str:
    value = value.strip()
    parts = value.split(maxsplit=1)
    if len(parts) == 2 and parts[0].upper() in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
    }:
        value = parts[1]
    parsed_url = urlsplit(value)
    path = parsed_url.path if parsed_url.scheme or parsed_url.netloc else value
    return path.split("?", maxsplit=1)[0].rstrip("/") or "/"


def _find_matching_captured_request(
    target: dict, deep_crawler_data: dict | None
) -> dict | None:
    requests = [
        request
        for request in _sqli_entry_points(deep_crawler_data)
        if isinstance(request, dict) and request.get("url")
    ]
    target_request = target.get("request")
    request_ids = {
        value
        for value in (
            target.get("request_id"),
            target.get("target_id"),
            target_request.get("id") if isinstance(target_request, dict) else None,
        )
        if value is not None
    }

    for request in requests:
        if request.get("id") in request_ids:
            return request

    target_method = str(target.get("method") or "").upper()
    target_endpoint = target.get("endpoint")
    if not isinstance(target_endpoint, str) or not target_endpoint:
        return None

    target_path = _normalize_request_path(target_endpoint)
    matches = [
        request
        for request in requests
        if str(request.get("method") or "").upper() == target_method
        and _normalize_request_path(str(request["url"])) == target_path
    ]
    return matches[0] if len(matches) == 1 else None


def _build_request_from_capture(captured_request: dict) -> dict:
    return {
        key: captured_request.get(key)
        for key in ("method", "url", "headers", "body", "observed_on")
    }


def _build_weak_page_browser_plan(surface: str, request: dict) -> dict | None:
    observed_on = request.get("observed_on")
    source_url = next(
        (
            value
            for value in (observed_on if isinstance(observed_on, list) else [])
            if isinstance(value, str) and value
        ),
        None,
    )
    if not source_url:
        return None

    endpoint = str(request.get("url") or "")
    endpoint_parts = urlsplit(endpoint)
    if surface == "dom_reflected_search":
        return {
            "mode": "reflected_dom",
            "source_url": source_url,
            "parameter": "q",
            "input_selector": '[name="q"], #catalog-search, input[type="search"]',
            "trigger": "fill",
            "request": {
                "method": "GET",
                "path": endpoint_parts.path,
                "query_parameter": "q",
            },
        }
    if surface == "stored_contact":
        body = request.get("body")
        fields = sorted(body) if isinstance(body, dict) else []
        return {
            "mode": "stored_dom",
            "source_url": source_url,
            "parameter": "message",
            "marker_prefix": "weakpage-xss-probe-",
            "form_selector": "form",
            "form_fields": fields,
            "submit_selector": 'button[type="submit"], input[type="submit"]',
            "request_headers": {
                "x-weak-page-xss-validation": "stored-contact",
            },
            "request": {
                "method": "POST",
                "path": endpoint_parts.path,
            },
            "verification_url_template": (
                "/#/contact-inbox?probeId={id}&marker={marker}"
            ),
            "verification_request": {
                "method": "GET",
                "path_template": f"{endpoint_parts.path}/xss-inbox/{{id}}",
                "headers": {"x-weak-page-xss-validation": "stored-contact"},
            },
            "verification_selector": "#contact-inbox-items",
            "cleanup": {
                "method": "DELETE",
                "path_template": f"{endpoint_parts.path}/{{id}}",
                "body": {"marker": "{marker}"},
                "headers": {
                    "content-type": "application/json",
                    "x-weak-page-xss-validation": "stored-contact",
                },
            },
        }
    return None


def build_recon_output_from_dict(data: dict,target_url: str,attack_type_filter: str,deep_crawler_data: dict | None = None,) -> ReconPlannerOutput:
    """Valida y normaliza la respuesta JSON producida por el LLM de Recon."""
    summary_data = data.get("recon_summary", {})
    targets_data = data.get("high_priority_targets", [])
    summary = ReconSummary(
        target_url=(
            target_url
            if is_sqli_attack(attack_type_filter)
            else summary_data.get("target_url", target_url)
        ),
        attack_type_filter=(
            "access_control"
            if is_access_control_attack(attack_type_filter)
            else "sqli"
            if is_sqli_attack(attack_type_filter)
            else summary_data.get("attack_type_filter", attack_type_filter)
        ),
        total_targets_identified=summary_data.get(
            "total_targets_identified", len(targets_data)
        ),
        total_requests_captured=summary_data.get("total_requests_captured", 0),
    )
    targets: List[HighPriorityTarget] = []
    seen_xss_requests = set()
    for index, target in enumerate(targets_data, start=1):
        if not isinstance(target, dict):
            continue
        captured_request = (
            _find_matching_captured_request(target, deep_crawler_data)
            if (
                is_sqli_attack(attack_type_filter)
                or is_xss_attack(attack_type_filter)
                or is_crypto_attack(attack_type_filter)
                or is_access_control_attack(attack_type_filter)
            )
            else None
        )
        request_id = target.get("request_id") or ""
        request = target.get("request") or {}
        method = target.get("method", "GET")
        if is_crypto_attack(attack_type_filter):
            default_tool = "crypto_inspector"
        elif is_access_control_attack(attack_type_filter):
            default_tool = "access_control_prober"
        elif is_xss_attack(attack_type_filter):
            default_tool = "dalfox"
        else:
            default_tool = "sqlmap"
        if captured_request:
            request_id = captured_request.get("id") or request_id
            request = _build_request_from_capture(captured_request)
            method = captured_request.get("method") or method
        request = request if isinstance(request, dict) else {}
        if captured_request:
            request["observed_on"] = captured_request.get("observed_on", [])
        method = str(request.get("method") or method or "GET").upper()
        endpoint = request.get("url") or target.get("endpoint", target_url)
        is_xss = attack_type_filter.casefold() == "xss"
        validation_plan = target.get("validation_plan")
        if not validation_plan and is_xss:
            surface = classify_weak_page_xss_surface(
                endpoint,
                {**request, "method": method},
            )
            if surface:
                validation_plan = _build_weak_page_browser_plan(
                    surface,
                    {
                        **request,
                        "url": endpoint,
                        "observed_on": request.get("observed_on", []),
                    },
                )
        if is_xss:
            if not isinstance(endpoint, str) or not _has_xss_input(endpoint, request):
                logger.info(
                    "Recon omite target XSS sin query inyectable ni body method=%s endpoint=%s",
                    method,
                    endpoint,
                )
                continue
            signature = _xss_request_signature(method, endpoint, request)
            if signature in seen_xss_requests:
                logger.info(
                    "Recon elimina target XSS duplicado method=%s endpoint=%s",
                    method,
                    endpoint,
                )
                continue
            seen_xss_requests.add(signature)

        targets.append(
            HighPriorityTarget(
                target_id=target.get("target_id", f"target_{index:03d}"),
                request_id=request_id,
                vulnerability_target=target.get(
                    "vulnerability_target", f"{attack_type_filter} Vulnerability"
                ),
                endpoint=endpoint,
                method=method,
                request=request,
                validation_plan=validation_plan,
                recommended_tool=(
                    "browserXssValidator"
                    if is_xss and validation_plan
                    else "dalfox"
                    if is_xss
                    else target.get("recommended_tool", default_tool)
                ),
            )
        )
    summary.total_targets_identified = len(targets)
    output = ReconPlannerOutput(
        recon_summary=summary,
        high_priority_targets=targets,
    )
    logger.info(
        "ReconPlannerOutput preparado con %d objetivos prioritarios",
        len(output.high_priority_targets),
    )
    return output

def _is_id_bearing_url(url: str) -> bool:
    """Heurística para rutas que referencian un objeto concreto (ID/UUID)."""
    if not isinstance(url, str) or not url:
        return False
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


def build_access_control_recon_context(
    crawler_data: dict,
    deep_crawler_data: dict | None,
    discovered_urls: list[str],
    available_tools: list[dict],
) -> dict:
    """Prepara endpoints y requests observadas para planificar pruebas de control de acceso."""
    entry_points = []
    for request in (deep_crawler_data or {}).get("entry_points", [])[:50]:
        if not isinstance(request, dict):
            continue
        headers = request.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        entry_points.append(
            {
                "id": request.get("id"),
                "method": request.get("method"),
                "url": request.get("url"),
                "path": request.get("path"),
                "resource_type": request.get("resource_type"),
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and name.casefold()
                    in {"authorization", "cookie", "content-type", "accept", "x-auth-token"}
                },
                "body": request.get("body"),
                "response_status": (request.get("response") or {}).get("status"),
            }
        )

    endpoints = [
        {
            "template": endpoint.get("template"),
            "sample_urls": endpoint.get("sample_urls", []),
            "methods": endpoint.get("methods", []),
        }
        for endpoint in crawler_data.get("navigation", {}).get("endpoints", [])[:50]
        if isinstance(endpoint, dict)
    ]

    interesting_urls = [
        url
        for url in discovered_urls
        if any(
            keyword in url.lower()
            for keyword in (
                "admin", "user", "account", "profile", "basket", "order",
                "cart", "invoice", "document", "file", "api", "rest",
            )
        )
    ][:100]

    return {
        "attack_type_filter": "access_control",
        "crawler_endpoints": endpoints,
        "interesting_urls": interesting_urls,
        "potential_idor_endpoints": [
            url for url in discovered_urls if _is_id_bearing_url(url)
        ][:50],
        "captured_entry_points": entry_points,
        "deduplicated_urls": discovered_urls[:100],
        "available_validation_tools": available_tools,
        "instructions": (
            "Identifica endpoints y requests observadas que operen sobre objetos de "
            "usuario (IDs numéricos, UUIDs, baskets, pedidos, perfiles, documentos). "
            "Prioriza los que permitan comparar el acceso de dos identidades distintas. "
            "No inventes endpoints ni credenciales: la fase de validación obtiene los "
            "tokens y ejecuta access_control_prober."
        ),
    }
