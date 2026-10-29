import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from urllib.parse import parse_qsl, urlsplit

from contract_schemas import HighPriorityTarget, ReconPlannerOutput, ReconSummary

logger = logging.getLogger("recon-agent-worker")
MAX_XSS_ENTRY_POINT_TARGETS = 20


def log_preview(value: object, limit: int = 500) -> str:
    """Resume valores grandes para mantener los logs legibles."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text)} chars]"


def deduplicate_urls(*url_groups: list[str]) -> list[str]:
    """Combina descubrimientos manteniendo el primer origen de cada URL."""
    unique_urls: list[str] = []
    seen: set[str] = set()
    for group in url_groups:
        for url in group:
            normalized_url = url.strip().rstrip(".,);]")
            if normalized_url and normalized_url not in seen:
                seen.add(normalized_url)
                unique_urls.append(normalized_url)
    return unique_urls


def extract_urls_from_katana(raw_output: str) -> list[str]:
    """Extrae URLs tanto de la salida plana como de líneas JSON de Katana."""
    return deduplicate_urls(
        re.findall(r"https?://[^\s\"<>]+", raw_output or "")
    )


def extract_urls_from_crawler(crawler_data: dict) -> list[str]:
    """Obtiene URLs descubiertas desde el contrato JSON del crawler."""
    request_urls = [
        request.get("url", "")
        for request in crawler_data.get("captured_requests", [])
        if isinstance(request, dict)
    ]
    route_urls = [
        route.get("route_url", "")
        for route in crawler_data.get("discovered_forms_structure", [])
        if isinstance(route, dict)
    ]
    endpoint_urls = [
        sample_url
        for endpoint in crawler_data.get("navigation", {}).get("endpoints", [])
        if isinstance(endpoint, dict)
        for sample_url in endpoint.get("sample_urls", [])
    ]
    state_urls = [
        state.get("url", "")
        for state in crawler_data.get("navigation", {}).get("states", [])
        if isinstance(state, dict)
    ]
    return deduplicate_urls(request_urls, route_urls, endpoint_urls, state_urls)


def extract_urls_from_deep_crawler(deep_crawler_data: dict) -> list[str]:
    """Obtiene URLs y entry points observados por el crawler profundo."""
    endpoint_urls = [
        endpoint.get("final_url", "")
        for endpoint in deep_crawler_data.get("endpoints", [])
        if isinstance(endpoint, dict)
    ]
    request_urls = [
        request.get("url", "")
        for request in deep_crawler_data.get("entry_points", [])
        if isinstance(request, dict)
    ]
    return deduplicate_urls(endpoint_urls, request_urls)


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

# Construye el contexto de reconocimiento específico para ataques SQLi.
def build_sqli_recon_context(crawler_data: dict, deep_crawler_data: dict | None ,discovered_urls: list[str],available_tools: list[dict]) -> dict:
    """Reduce resultados de crawlers a los datos que sirven para planificar ataques."""
    if deep_crawler_data is not None:
        requests = (deep_crawler_data or {}).get("entry_points", [])
        sql_inputs = []
        for request in requests:
            if not isinstance(request, dict) or request.get("body") is None:
                continue
            headers = request.get("headers", {})
            sql_inputs.append({
                "id": request.get("id"),
                "method": request.get("method"),
                "url": request.get("url"),
                "path": request.get("path"),
                "resource_type": request.get("resource_type"),
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if name.lower() in {
                        "host", "content-type", "accept", "referer", "user-agent"
                    }
                },
                "body": request.get("body"),
            })
        return {
            "attack_type_filter": "sqli",
            "sqli_input_entry_points": sql_inputs,
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
    entry_points = []
    for request in (deep_crawler_data or {}).get("entry_points", [])[:40]:
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
                "headers": {
                    name: value
                    for name, value in headers.items()
                    if isinstance(name, str)
                    and name.casefold() in {"content-type", "accept"}
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
    return {
        "attack_type_filter": "xss",
        "crawler_endpoints": endpoints,
        "deduplicated_urls": discovered_urls[:100],
        "captured_entry_points": entry_points,
        "available_validation_tools": available_tools,
    }


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


def build_sqli_fallback_output(target_url: str,deep_crawler_data: dict | None,) -> dict:
    """Construye un plan SQLi minimo con peticiones observadas si el LLM no devuelve JSON."""
    requests = (deep_crawler_data or {}).get("entry_points", [])
    targets = []
    for request in requests[:10]:
        if not isinstance(request, dict) or not request.get("url"):
            continue
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
    return {
        "recon_summary": {
            "target_url": target_url,
            "attack_type_filter": "sqli",
            "total_targets_identified": len(targets),
            "total_requests_captured": len(requests),
        },
        "high_priority_targets": targets,
    }


def ensure_sqli_entry_point_coverage(data: dict, deep_crawler_data: dict | None) -> dict:
    """Incluye cada request observada con body aunque el LLM haya omitido alguna."""
    output = dict(data)
    targets = [
        target for target in output.get("high_priority_targets", [])
        if isinstance(target, dict)
    ]
    requests = [
        request
        for request in (deep_crawler_data or {}).get("entry_points", [])
        if isinstance(request, dict) and request.get("url") and request.get("body") is not None
    ]
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
    covered_request_objects = set()
    for target in targets:
        captured_request = _find_matching_captured_request(target, deep_crawler_data)
        if captured_request:
            if captured_request.get("id"):
                covered_request_ids.add(captured_request["id"])
            else:
                covered_request_objects.add(id(captured_request))

    for request in requests:
        request_id = request.get("id")
        if (
            (request_id and request_id in covered_request_ids)
            or id(request) in covered_request_objects
        ):
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
    summary["total_targets_identified"] = len(targets)
    output["recon_summary"] = summary
    return output


def ensure_xss_entry_point_coverage(
    data: dict,
    deep_crawler_data: dict | None,
    max_targets: int = MAX_XSS_ENTRY_POINT_TARGETS,
) -> dict:
    """Include observed XSS-capable requests even when Recon's LLM omits them."""
    output = dict(data)
    targets = [
        target for target in output.get("high_priority_targets", [])
        if isinstance(target, dict)
    ]
    requests = []
    for request in (deep_crawler_data or {}).get("entry_points", []):
        if not isinstance(request, dict) or not isinstance(request.get("url"), str):
            continue
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
                    for key in ("id", "method", "url", "headers", "body")
                },
                "recommended_tool": "dalfox",
            }
        )
        covered_signatures.add(signature)
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
        for request in (deep_crawler_data or {}).get("entry_points", [])
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
        for key in ("method", "url", "headers", "body")
    }


def build_recon_output_from_dict(data: dict,target_url: str,attack_type_filter: str,deep_crawler_data: dict | None = None,) -> ReconPlannerOutput:
    """Valida y normaliza la respuesta JSON producida por el LLM de Recon."""
    summary_data = data.get("recon_summary", {})
    targets_data = data.get("high_priority_targets", [])
    summary = ReconSummary(
        target_url=summary_data.get("target_url", target_url),
        attack_type_filter=summary_data.get("attack_type_filter", attack_type_filter),
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
            if attack_type_filter.casefold() in {"sqli", "xss"}
            else None
        )
        request_id = target.get("request_id") or ""
        request = target.get("request") or {}
        method = target.get("method", "GET")
        default_tool = (
            "dalfox" if attack_type_filter.casefold() == "xss" else "sqlmap"
        )
        if captured_request:
            request_id = captured_request.get("id") or request_id
            request = _build_request_from_capture(captured_request)
            method = captured_request.get("method") or method
        request = request if isinstance(request, dict) else {}
        method = str(request.get("method") or method or "GET").upper()
        endpoint = request.get("url") or target.get("endpoint", target_url)
        is_xss = attack_type_filter.casefold() == "xss"
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
                recommended_tool=(
                    "dalfox"
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
