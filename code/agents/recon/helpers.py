import json
import logging
import re
from typing import List

from contract_schemas import HighPriorityTarget, ReconPlannerOutput, ReconSummary

logger = logging.getLogger("recon-agent-worker")


def log_preview(value: object, limit: int = 500) -> str:
    """Resume valores grandes para mantener los logs legibles."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text)} chars]"


def clean_json_response(raw_response: str) -> str:
    """Extrae exclusivamente el JSON del bloque Markdown final del LLM."""
    match = re.search(r"```json\s*(.*?)\s*```", raw_response, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        raise ValueError("La respuesta del LLM no contiene un bloque ```json```")
    return match.group(1).strip()


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
    return deduplicate_urls(request_urls, route_urls)


def build_planner_output_from_dict(data: dict, target_url: str, attack_type_filter: str) -> ReconPlannerOutput:
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
        har_session_file=summary_data.get("har_session_file"),
    )
    targets: List[HighPriorityTarget] = []
    for index, target in enumerate(targets_data, start=1):
        if not isinstance(target, dict):
            continue
        targets.append(
            HighPriorityTarget(
                target_id=target.get("target_id", f"target_{index:03d}"),
                vulnerability_target=target.get(
                    "vulnerability_target", f"{attack_type_filter} Vulnerability"
                ),
                endpoint=target.get("endpoint", target_url),
                method=target.get("method", "GET").upper(),
                request=target.get("request"),
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


