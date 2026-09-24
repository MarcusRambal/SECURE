import json

from contract_schemas import ReporterInput
from config import REPORTER_MAX_ENDPOINTS, REPORTER_MAX_EVIDENCE_CHARS


def _limit_items(items: list, limit: int) -> list:
    return items if limit <= 0 else items[:limit]


def _limit_text(text: str, limit: int) -> str:
    return text if limit <= 0 or len(text) <= limit else text[:limit] + "..."


def build_fallback_markdown_report(reporter_input: ReporterInput, raw_error: str) -> str:
    """Construye un informe Markdown de respaldo sin depender del LLM."""
    vulnerabilities = reporter_input.validation_data.vulnerabilities
    targets = reporter_input.recon_data.high_priority_targets
    unconfirmed = reporter_input.validation_data.unconfirmed_findings

    parts = [
        "# Informe de Auditoria de Ciberseguridad\n",
        f"**ID de Tarea:** `{reporter_input.task_id}`",
        f"**Objetivo Auditado:** `{reporter_input.target_url}`",
        f"**Modalidad:** `{reporter_input.attack_type}`\n",
    ]

    if reporter_input.recon_used_fallback or reporter_input.validate_used_fallback:
        parts.append(
            "> **Advertencia de Analisis Degradado:** Fases previas utilizaron mecanismos "
            "de respaldo. La cobertura del reporte puede ser parcial.\n"
        )

    parts.append(
        "> **Nota del Sistema:** Este informe se genero mediante la plantilla de respaldo "
        "debido a una anomalia durante la generacion narrativa del LLM."
    )
    parts.append(f"> **Error:** `{raw_error[:200]}`\n")

    parts.append("## Resumen Ejecutivo\n")
    parts.append(f"* **Objetivos Prioritarios Identificados:** {len(targets)}")
    parts.append(f"* **Vulnerabilidades Confirmadas:** {len(vulnerabilities)}")
    parts.append(f"* **Pruebas Sin Confirmacion:** {len(unconfirmed)}\n")

    parts.append("## Detalle de Hallazgos\n")
    if not vulnerabilities:
        parts.append("*No se confirmaron vulnerabilidades explotables durante esta auditoria de seguridad.*\n")
    else:
        for vulnerability in vulnerabilities:
            parts.append(f"### [{vulnerability.severity}] {vulnerability.type}")
            parts.append(f"- **Endpoint:** `{vulnerability.endpoint}`")
            parts.append(f"- **Parametro:** `{vulnerability.parameter or 'N/A'}`")
            parts.append(f"- **Certeza:** `{vulnerability.confidence}`")
            parts.append(f"- **Evidencia:** `{vulnerability.evidence}`")
            parts.append("- **Comando Reproducible:**")
            parts.append("```bash")
            parts.append(vulnerability.reproducible_command)
            parts.append("```")
            parts.append(f"- **Herramientas Utilizadas:** {', '.join(vulnerability.tools_used)}\n")
            parts.append("---\n")

    if unconfirmed:
        parts.append("## Pruebas sin Confirmacion\n")
        parts.append(
            f"Se ejecutaron {len(unconfirmed)} pruebas/evaluaciones adicionales "
            "que no arrojaron evidencia suficiente de explotacion directa.\n"
        )

    return "\n".join(parts)


def build_reporter_context(reporter_input: ReporterInput) -> str:
    """Genera un resumen JSON compacto del contrato actual de Recon y Validate."""
    recon_summary = reporter_input.recon_data.recon_summary
    targets = reporter_input.recon_data.high_priority_targets
    context = {
        "task_id": reporter_input.task_id,
        "target_url": reporter_input.target_url,
        "attack_type": reporter_input.attack_type,
        "degradation_warnings": {
            "recon_used_fallback": reporter_input.recon_used_fallback,
            "validate_used_fallback": reporter_input.validate_used_fallback,
        },
        "recon_summary": {
            "total_targets_identified": recon_summary.total_targets_identified,
            "total_requests_captured": recon_summary.total_requests_captured,
            "high_priority_targets": [
                {
                    "target_id": target.target_id,
                    "vulnerability_target": target.vulnerability_target,
                    "endpoint": target.endpoint,
                    "method": target.method,
                    "recommended_tool": target.recommended_tool,
                }
                for target in _limit_items(targets, REPORTER_MAX_ENDPOINTS)
            ],
        },
        "validation_summary": {
            "vulnerabilities": [
                {
                    "type": vulnerability.type,
                    "severity": vulnerability.severity,
                    "endpoint": vulnerability.endpoint,
                    "parameter": vulnerability.parameter,
                    "confidence": vulnerability.confidence,
                    "evidence": _limit_text(
                        vulnerability.evidence, REPORTER_MAX_EVIDENCE_CHARS
                    ),
                    "reproducible_command": vulnerability.reproducible_command,
                    "tools_used": vulnerability.tools_used,
                }
                for vulnerability in reporter_input.validation_data.vulnerabilities
            ],
            "unconfirmed_count": len(reporter_input.validation_data.unconfirmed_findings),
            "scan_started_at": reporter_input.validation_data.scan_started_at,
            "scan_finished_at": reporter_input.validation_data.scan_finished_at,
        },
    }
    return json.dumps(context, indent=2, ensure_ascii=False)


def build_fallback_reporter_input(payload: dict) -> ReporterInput:
    """Crea un ReporterInput valido para informar errores de contrato sin ocultarlos."""
    target_url = payload.get("target_url", "N/A")
    attack_type = payload.get("attack_type", "full")
    return ReporterInput(
        task_id=payload.get("task_id", "N/A"),
        target_url=target_url,
        attack_type=attack_type,
        recon_data={
            "recon_summary": {
                "target_url": target_url,
                "attack_type_filter": attack_type,
                "total_targets_identified": 0,
                "total_requests_captured": 0,
            },
            "high_priority_targets": [],
        },
        validation_data={"target_url": target_url, "vulnerabilities": []},
    )
