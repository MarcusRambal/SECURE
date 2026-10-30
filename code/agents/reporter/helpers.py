import json

from contract_schemas import ReporterInput
from config import REPORTER_MAX_ENDPOINTS, REPORTER_MAX_EVIDENCE_CHARS

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _limit_items(items: list, limit: int) -> list:
    return items if limit <= 0 else items[:limit]


def _limit_text(text: str, limit: int) -> str:
    return text if limit <= 0 or len(text) <= limit else text[:limit] + "..."


def _sort_by_severity(vulnerabilities: list) -> list:
    """CRITICAL primero; el resto en orden descendente de severidad."""
    return sorted(
        vulnerabilities,
        key=lambda vulnerability: (
            SEVERITY_ORDER.index(vulnerability.severity)
            if vulnerability.severity in SEVERITY_ORDER
            else len(SEVERITY_ORDER)
        ),
    )


def _severity_counts(vulnerabilities: list) -> dict:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for vulnerability in vulnerabilities:
        if vulnerability.severity in counts:
            counts[vulnerability.severity] += 1
    return counts


def build_fallback_markdown_report(reporter_input: ReporterInput, raw_error: str) -> str:
    """Construye un informe Markdown de respaldo sin depender del LLM."""
    vulnerabilities = _sort_by_severity(list(reporter_input.validation_data.vulnerabilities))
    targets = reporter_input.recon_data.high_priority_targets
    unconfirmed = reporter_input.validation_data.unconfirmed_findings
    counts = _severity_counts(vulnerabilities)

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
    parts.append(f"* **Hallazgos Confirmados:** {len(vulnerabilities)}")
    parts.append(
        "* **Hallazgos por Severidad:** "
        + ", ".join(f"{severity}={count}" for severity, count in counts.items())
    )
    parts.append(f"* **Pruebas Sin Confirmacion:** {len(unconfirmed)}\n")

    parts.append("## Detalle de Hallazgos\n")
    if not vulnerabilities:
        parts.append("*No se confirmaron vulnerabilidades explotables durante esta auditoria de seguridad.*\n")
    else:
        for index, vulnerability in enumerate(vulnerabilities, start=1):
            parts.append(f"### {index}. [{vulnerability.severity}] {vulnerability.type}")
            parts.append(f"- **ID del Hallazgo:** `{vulnerability.finding_id or 'N/A'}`")
            parts.append(f"- **Endpoint:** `{vulnerability.endpoint}`")
            parts.append(f"- **Parametro:** `{vulnerability.parameter or 'N/A'}`")
            if vulnerability.method:
                parts.append(f"- **Método HTTP:** `{vulnerability.method}`")
            parts.append(f"- **Certeza:** `{vulnerability.confidence}`")
            parts.append(
                f"- **Mapeo Estandar:** CWE=`{vulnerability.cwe or 'No reportado por la herramienta'}` | "
                f"OWASP=`{vulnerability.owasp or 'No reportado por la herramienta'}`"
            )
            parts.append(f"- **Rol del Contexto:** `{vulnerability.context_role or 'N/A'}`")
            parts.append(f"- **Evidencia:** `{vulnerability.evidence}`")
            if vulnerability.attack_demonstrated:
                parts.append(f"- **Ataque Demostrado:** `{vulnerability.attack_demonstrated}`")
            if vulnerability.attack_result:
                parts.append(
                    f"- **Contrasena Recuperada:** `{vulnerability.attack_result}`"
                    if str(vulnerability.attack_demonstrated).casefold() == "dictionary_attack"
                    else f"- **Resultado del Ataque:** `{vulnerability.attack_result}`"
                )
            if vulnerability.attack_chain:
                parts.append("- **Cadena de Ataque:**")
                for step in vulnerability.attack_chain:
                    parts.append(f"  {step}")
            parts.append("- **Comando Reproducible:**")
            if vulnerability.verification_steps:
                parts.append(
                    f"- **Cómo verificar:** {vulnerability.verification_steps}"
                )
            command_label = (
                "Comando ejecutado (requiere el archivo HTTP temporal)"
                if "/tmp/dalfox-req.txt" in vulnerability.reproducible_command
                else "Comando reproducible"
            )
            parts.append(f"- **{command_label}:**")
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
    findings = _sort_by_severity(list(reporter_input.validation_data.vulnerabilities))
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
            "total_findings": len(findings),
            "severity_summary": _severity_counts(findings),
            "findings_order": list(SEVERITY_ORDER),
            "findings": [
                {
                    "finding_id": vulnerability.finding_id,
                    "type": vulnerability.type,
                    "severity": vulnerability.severity,
                    "endpoint": vulnerability.endpoint,
                    "parameter": vulnerability.parameter,
                    "method": vulnerability.method,
                    "confidence": vulnerability.confidence,
                    "cwe": vulnerability.cwe,
                    "owasp": vulnerability.owasp,
                    "context_role": vulnerability.context_role,
                    "attack_demonstrated": vulnerability.attack_demonstrated,
                    "attack_result": vulnerability.attack_result,
                    "attack_chain": vulnerability.attack_chain,
                    "evidence": _limit_text(
                        vulnerability.evidence, REPORTER_MAX_EVIDENCE_CHARS
                    ),
                    "verification_steps": vulnerability.verification_steps,
                    "reproducible_command": vulnerability.reproducible_command,
                    "tools_used": vulnerability.tools_used,
                }
                for vulnerability in findings
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
