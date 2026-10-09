import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from contract_schemas import HighPriorityTarget, ReconPlannerOutput, ReconSummary

logger = logging.getLogger("recon-agent-worker")


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

# Funcion de ayuda para ver el contexto que obtiene el agente
def write_recon_context_snapshot(target_url: str,attack_type_filter: str,context: dict,) -> Path:
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
        captured_request = _find_matching_sqli_request(target, deep_crawler_data)
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


def _find_matching_sqli_request(target: dict,deep_crawler_data: dict | None,) -> dict | None:
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
    for index, target in enumerate(targets_data, start=1):
        if not isinstance(target, dict):
            continue
        captured_request = (
            _find_matching_sqli_request(target, deep_crawler_data)
            if attack_type_filter.lower() == "sqli"
            else None
        )
        request_id = target.get("request_id") or ""
        request = target.get("request") or {}
        method = target.get("method", "GET")
        if captured_request:
            request_id = captured_request.get("id") or request_id
            request = _build_request_from_capture(captured_request)
            method = captured_request.get("method") or method

        targets.append(
            HighPriorityTarget(
                target_id=target.get("target_id", f"target_{index:03d}"),
                request_id=request_id,
                vulnerability_target=target.get(
                    "vulnerability_target", f"{attack_type_filter} Vulnerability"
                ),
                endpoint=target.get("endpoint", target_url),
                method=str(method or "GET").upper(),
                request=request,
                recommended_tool=target.get("recommended_tool", "sqlmap"),
            )
        )
    output = ReconPlannerOutput(
        recon_summary=summary,
        high_priority_targets=targets,
    )
    logger.info(
        "ReconPlannerOutput preparado con %d objetivos prioritarios",
        len(output.high_priority_targets),
    )
    return output
