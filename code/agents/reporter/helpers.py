import json
import re
import unicodedata

from contract_schemas import ReporterInput
from config import REPORTER_MAX_ENDPOINTS, REPORTER_MAX_EVIDENCE_CHARS

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ACCESS_CONTROL_TOOL = "access_control_prober"
CRYPTO_TOOL = "crypto_inspector"
REPORTED_TOOLS = (CRYPTO_TOOL, ACCESS_CONTROL_TOOL)
_HASH_PATTERN = re.compile(
    r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)


def _fold_text(text: str) -> str:
    """Normaliza mayusculas y acentos para comparar texto generado por el LLM."""
    decomposed = unicodedata.normalize("NFKD", str(text or ""))
    return "".join(
        character for character in decomposed if not unicodedata.combining(character)
    ).casefold()


def _limit_items(items: list, limit: int) -> list:
    return items if limit <= 0 else items[:limit]


def _limit_text(text: str, limit: int) -> str:
    return text if limit <= 0 or len(text) <= limit else text[:limit] + "..."


def _severity_of(vulnerability) -> str:
    severity = str(getattr(vulnerability, "severity", "") or "").upper()
    return severity if severity in SEVERITY_ORDER else "INFO"


def _sort_by_severity(vulnerabilities: list) -> list:
    """CRITICAL primero; el resto en orden descendente de severidad."""
    return sorted(
        vulnerabilities,
        key=lambda vulnerability: (
            SEVERITY_ORDER.index(_severity_of(vulnerability)),
            str(getattr(vulnerability, "endpoint", "") or ""),
        ),
    )


def _severity_counts(vulnerabilities: list) -> dict:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for vulnerability in vulnerabilities:
        counts[_severity_of(vulnerability)] += 1
    return counts


def _tool_names(vulnerability) -> list[str]:
    """Devuelve las herramientas normalizadas que produjeron un hallazgo."""
    tools = getattr(vulnerability, "tools_used", None) or []
    if not tools:
        single_tool = getattr(vulnerability, "tool", None)
        if single_tool:
            tools = [single_tool]
    if isinstance(tools, str):
        tools = [tool.strip() for tool in tools.split(",")]
    if not tools:
        # Compatibilidad con hallazgos crudos que solo traen id/title.
        marker = " ".join(
            [
                str(getattr(vulnerability, "finding_id", "") or ""),
                str(getattr(vulnerability, "type", "") or ""),
            ]
        ).casefold()
        if marker.strip().startswith("bac-") or any(
            term in marker
            for term in ("idor", "privilege escalation", "403 bypass", "exposed sensitive file")
        ):
            tools = [ACCESS_CONTROL_TOOL]
        elif marker.strip().startswith("crypto-") or "crypto_inspector" in marker:
            tools = [CRYPTO_TOOL]
    return [str(tool).strip().casefold() for tool in tools if str(tool).strip()]


def _primary_tool(vulnerability) -> str:
    """Herramienta principal del hallazgo; access_control_prober tiene prioridad."""
    tools = _tool_names(vulnerability)
    if ACCESS_CONTROL_TOOL in tools:
        return ACCESS_CONTROL_TOOL
    if CRYPTO_TOOL in tools:
        return CRYPTO_TOOL
    return tools[0] if tools else "unknown"


def _is_access_control(vulnerability) -> bool:
    return ACCESS_CONTROL_TOOL in _tool_names(vulnerability)


def _is_crypto(vulnerability) -> bool:
    return CRYPTO_TOOL in _tool_names(vulnerability)


def _attack_chain(vulnerability) -> list[str]:
    chain = getattr(vulnerability, "attack_chain", None) or []
    if isinstance(chain, str):
        chain = [chain]
    return [str(step) for step in chain if str(step).strip()]


def _is_recovered_password(vulnerability) -> bool:
    return (
        str(getattr(vulnerability, "attack_demonstrated", "") or "").casefold()
        == "dictionary_attack"
        and bool(getattr(vulnerability, "attack_result", None))
        and str(getattr(vulnerability, "context_role", "") or "").casefold()
        != "static_checksum"
    )


def _is_broken_hash(vulnerability) -> bool:
    """Detecta hallazgos criptográficos de hashes/checksums rotos u obsoletos."""
    if not _is_crypto(vulnerability):
        return False
    haystack = " ".join(
        [
            str(getattr(vulnerability, "type", "") or ""),
            str(getattr(vulnerability, "finding_id", "") or ""),
            str(getattr(vulnerability, "evidence", "") or ""),
            str(getattr(vulnerability, "context_role", "") or ""),
        ]
    ).casefold()
    return str(getattr(vulnerability, "context_role", "") or "").casefold() == "static_checksum" or any(
        term in haystack for term in ("hash", "md5", "sha1", "checksum", "digest")
    )


def _hash_value(vulnerability) -> str:
    """Extrae el token de hash de la evidencia; si no existe, usa la evidencia."""
    for field in ("attack_result", "evidence", "parameter", "type"):
        match = _HASH_PATTERN.search(str(getattr(vulnerability, field, "") or ""))
        if match:
            return match.group(0)
    return _evidence_for_report(vulnerability)


def _strip_executive_summary(markdown_text: str) -> str:
    """Quita el resumen ejecutivo para no confundir sus metricas con resaltados."""
    output: list[str] = []
    skipping = False
    for line in markdown_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## ") and "resumen ejecutivo" in _fold_text(stripped):
            skipping = True
            continue
        if skipping and stripped.startswith("## "):
            skipping = False
        if not skipping:
            output.append(line)
    return "\n".join(output)


def _access_control_confirmation_label(vulnerability) -> str:
    haystack = " ".join(
        [
            str(getattr(vulnerability, "type", "") or ""),
            str(getattr(vulnerability, "finding_id", "") or ""),
        ]
    ).casefold()
    if "idor" in haystack:
        return "IDOR confirmado activamente (acceso a un objeto de otro usuario)"
    if "vertical" in haystack or "escal" in haystack:
        return "Escalada vertical de privilegios confirmada activamente"
    if "bypass" in haystack:
        return "Bypass de control de acceso (403) confirmado activamente"
    if "exposed" in haystack or "file" in haystack or "directory" in haystack:
        return "Archivo o directorio sensible expuesto confirmado activamente"
    return "Control de acceso vulnerable confirmado activamente"


def _tool_metrics(findings: list) -> dict:
    metrics = {
        tool: {"total": 0, "CRITICAL": 0, "HIGH": 0, "critical_and_high": 0}
        for tool in REPORTED_TOOLS
    }
    for vulnerability in findings:
        for tool in _tool_names(vulnerability) or ["unknown"]:
            bucket = metrics.setdefault(
                tool,
                {"total": 0, "CRITICAL": 0, "HIGH": 0, "critical_and_high": 0},
            )
            bucket["total"] += 1
            severity = _severity_of(vulnerability)
            if severity in ("CRITICAL", "HIGH"):
                bucket[severity] += 1
                bucket["critical_and_high"] += 1
    return metrics


def _executive_summary(findings: list) -> dict:
    counts = _severity_counts(findings)
    by_tool = _tool_metrics(findings)
    reported_findings = [
        vulnerability
        for vulnerability in findings
        if _primary_tool(vulnerability) in REPORTED_TOOLS
    ]
    reported_critical = sum(
        1
        for vulnerability in reported_findings
        if _severity_of(vulnerability) == "CRITICAL"
    )
    reported_high = sum(
        1
        for vulnerability in reported_findings
        if _severity_of(vulnerability) == "HIGH"
    )
    return {
        "scope": "Hallazgos combinados de crypto_inspector y access_control_prober",
        "total_findings": len(findings),
        "critical_total": counts["CRITICAL"],
        "high_total": counts["HIGH"],
        "critical_and_high_total": counts["CRITICAL"] + counts["HIGH"],
        "reported_tools_total": len(reported_findings),
        "reported_tools_critical_total": reported_critical,
        "reported_tools_high_total": reported_high,
        "reported_tools_critical_and_high_total": reported_critical + reported_high,
        "severity_summary": counts,
        "by_tool": by_tool,
        "access_control_active_confirmations": sum(
            1 for vulnerability in findings if _is_access_control(vulnerability)
        ),
        "recovered_credentials": sum(
            1 for vulnerability in findings if _is_recovered_password(vulnerability)
        ),
        "broken_hashes": sum(
            1 for vulnerability in findings if _is_broken_hash(vulnerability)
        ),
    }


def _evidence_for_report(vulnerability) -> str:
    evidence = str(getattr(vulnerability, "evidence", "") or "")
    limit = REPORTER_MAX_EVIDENCE_CHARS
    # La evidencia CRITICAL/HIGH no debe recortarse tanto como la de baja severidad.
    if _severity_of(vulnerability) in ("CRITICAL", "HIGH") and limit > 0:
        limit = max(limit, 1200)
    return _limit_text(evidence, limit)


def _finding_context_payload(vulnerability) -> dict:
    attack_chain = _attack_chain(vulnerability)
    access_control = _is_access_control(vulnerability)
    return {
        "finding_id": getattr(vulnerability, "finding_id", None),
        "tool": _primary_tool(vulnerability),
        "tools_used": _tool_names(vulnerability),
        "type": getattr(vulnerability, "type", "Unknown"),
        "severity": _severity_of(vulnerability),
        "endpoint": getattr(vulnerability, "endpoint", ""),
        "parameter": getattr(vulnerability, "parameter", None),
        "confidence": getattr(vulnerability, "confidence", None),
        "cwe": getattr(vulnerability, "cwe", None),
        "owasp": getattr(vulnerability, "owasp", None),
        "context_role": getattr(vulnerability, "context_role", None),
        "attack_demonstrated": getattr(vulnerability, "attack_demonstrated", None),
        "attack_result": getattr(vulnerability, "attack_result", None),
        "attack_chain": attack_chain,
        "attack_chain_required": True,
        "active_confirmation": access_control,
        "confirmation_note": (
            _access_control_confirmation_label(vulnerability) if access_control else None
        ),
        "recovered_password": (
            getattr(vulnerability, "attack_result", None)
            if _is_recovered_password(vulnerability)
            else None
        ),
        "broken_hash": _is_broken_hash(vulnerability),
        "evidence": _evidence_for_report(vulnerability),
        "reproducible_command": getattr(vulnerability, "reproducible_command", ""),
    }


def _render_finding_markdown(vulnerability, index: int) -> list[str]:
    """Ficha determinista de un hallazgo, usada por fallback y anexo de garantía."""
    severity = _severity_of(vulnerability)
    attack_chain = _attack_chain(vulnerability)
    tool = _primary_tool(vulnerability)
    parts = [f"### {index}. [{severity}] {getattr(vulnerability, 'type', 'Unknown')}"]
    parts.append(
        f"- **ID del Hallazgo:** `{getattr(vulnerability, 'finding_id', None) or 'N/A'}`"
    )
    parts.append(f"- **Herramienta:** `{tool}`")
    parts.append(f"- **Endpoint:** `{getattr(vulnerability, 'endpoint', '')}`")
    parts.append(
        f"- **Parametro:** `{getattr(vulnerability, 'parameter', None) or 'N/A'}`"
    )
    parts.append(
        f"- **Certeza:** `{getattr(vulnerability, 'confidence', None) or 'N/A'}`"
    )
    parts.append(
        f"- **Mapeo Estandar:** CWE=`{getattr(vulnerability, 'cwe', None) or 'No reportado por la herramienta'}` | "
        f"OWASP=`{getattr(vulnerability, 'owasp', None) or 'No reportado por la herramienta'}`"
    )
    parts.append(
        f"- **Rol del Contexto:** `{getattr(vulnerability, 'context_role', None) or 'N/A'}`"
    )
    if str(getattr(vulnerability, "context_role", "") or "").casefold() == "static_checksum":
        parts.append(
            "- **Clasificacion:** Falso positivo controlado / checksum estático "
            "(no explotable por sí mismo)."
        )

    if _is_access_control(vulnerability):
        parts.append(
            f"- **Confirmacion Activa:** ✅ **{_access_control_confirmation_label(vulnerability)}**. "
            "La herramienta reprodujo la explotacion contra el objetivo."
        )

    if _is_recovered_password(vulnerability):
        parts.append(
            f"- **Contrasena Recuperada:** `{getattr(vulnerability, 'attack_result', None)}`"
        )
    elif getattr(vulnerability, "attack_result", None):
        parts.append(
            f"- **Resultado del Ataque:** `{getattr(vulnerability, 'attack_result', None)}`"
        )

    if _is_broken_hash(vulnerability):
        parts.append(f"- **Hash Roto/Obsoleto:** `{_hash_value(vulnerability)}`")

    parts.append(f"- **Evidencia:** `{_evidence_for_report(vulnerability)}`")

    parts.append("- **Cadena de Ataque:**")
    if attack_chain:
        for step in attack_chain:
            parts.append(f"  {step}")
    else:
        parts.append("  No documentada por la herramienta.")

    parts.append("- **Comando Reproducible:**")
    parts.append("```bash")
    parts.append(str(getattr(vulnerability, "reproducible_command", "") or "No disponible"))
    parts.append("```")
    tools_used = _tool_names(vulnerability)
    parts.append(
        f"- **Herramientas Utilizadas:** {', '.join(tools_used) if tools_used else 'N/A'}\n"
    )
    parts.append("---\n")
    return parts


def build_report_metrics(reporter_input: ReporterInput) -> dict:
    """Metricas combinadas para logging y para el resumen ejecutivo."""
    findings = _sort_by_severity(list(reporter_input.validation_data.vulnerabilities))
    return _executive_summary(findings)


def build_fallback_markdown_report(reporter_input: ReporterInput, raw_error: str) -> str:
    """Construye un informe Markdown de respaldo sin depender del LLM."""
    vulnerabilities = _sort_by_severity(list(reporter_input.validation_data.vulnerabilities))
    targets = reporter_input.recon_data.high_priority_targets
    unconfirmed = reporter_input.validation_data.unconfirmed_findings
    summary = _executive_summary(vulnerabilities)

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
    parts.append(f"* **Hallazgos Confirmados:** {summary['total_findings']}")
    parts.append(f"* **CRITICAL (total):** {summary['critical_total']}")
    parts.append(f"* **HIGH (total):** {summary['high_total']}")
    parts.append(
        "* **CRITICAL + HIGH (crypto_inspector + access_control_prober):** "
        f"{summary['reported_tools_critical_and_high_total']}"
    )
    parts.append(
        "* **Hallazgos por Severidad:** "
        + ", ".join(
            f"{severity}={count}"
            for severity, count in summary["severity_summary"].items()
        )
    )
    parts.append(
        f"* **Confirmaciones Activas de Control de Acceso:** "
        f"{summary['access_control_active_confirmations']}"
    )
    parts.append(
        f"* **Credenciales Recuperadas:** {summary['recovered_credentials']}"
    )
    parts.append(f"* **Hashes Rotos/Obsoletos:** {summary['broken_hashes']}")
    parts.append(f"* **Pruebas Sin Confirmacion:** {len(unconfirmed)}\n")

    parts.append("### Desglose por Herramienta\n")
    parts.append("| Herramienta | CRITICAL | HIGH | CRITICAL + HIGH | Total |")
    parts.append("|---|---:|---:|---:|---:|")
    for tool in REPORTED_TOOLS:
        metrics = summary["by_tool"].get(tool, {})
        parts.append(
            f"| `{tool}` | {metrics.get('CRITICAL', 0)} | {metrics.get('HIGH', 0)} | "
            f"{metrics.get('critical_and_high', 0)} | {metrics.get('total', 0)} |"
        )
    parts.append(
        f"| **TOTAL combinado** | **{summary['reported_tools_critical_total']}** | "
        f"**{summary['reported_tools_high_total']}** | "
        f"**{summary['reported_tools_critical_and_high_total']}** | "
        f"**{summary['reported_tools_total']}** |\n"
    )

    parts.append("## Detalle de Hallazgos\n")
    if not vulnerabilities:
        parts.append(
            "*No se confirmaron vulnerabilidades explotables durante esta auditoria de seguridad.*\n"
        )
    else:
        for index, vulnerability in enumerate(vulnerabilities, start=1):
            parts.extend(_render_finding_markdown(vulnerability, index))

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
    summary = _executive_summary(findings)
    unconfirmed = reporter_input.validation_data.unconfirmed_findings
    context = {
        "task_id": reporter_input.task_id,
        "target_url": reporter_input.target_url,
        "attack_type": reporter_input.attack_type,
        "degradation_warnings": {
            "recon_used_fallback": reporter_input.recon_used_fallback,
            "validate_used_fallback": reporter_input.validate_used_fallback,
        },
        "executive_summary": summary,
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
            "source_tools": list(REPORTED_TOOLS),
            "total_findings": len(findings),
            "severity_summary": summary["severity_summary"],
            "findings_order": list(SEVERITY_ORDER),
            "by_tool": summary["by_tool"],
            "findings": [
                _finding_context_payload(vulnerability) for vulnerability in findings
            ],
            "unconfirmed_count": len(unconfirmed),
            "unconfirmed_findings": [
                {
                    "tool": str(
                        finding.get("tool")
                        or finding.get("tool_used")
                        or "unknown"
                    ),
                    "type": finding.get("type"),
                    "endpoint": finding.get("endpoint"),
                    "reason": finding.get("reason")
                    or finding.get("command_note")
                    or finding.get("evidence"),
                }
                for finding in unconfirmed[:REPORTER_MAX_ENDPOINTS]
                if isinstance(finding, dict)
            ],
            "scan_started_at": reporter_input.validation_data.scan_started_at,
            "scan_finished_at": reporter_input.validation_data.scan_finished_at,
        },
    }
    return json.dumps(context, indent=2, ensure_ascii=False)


def _finding_is_mentioned(text_folded: str, vulnerability) -> bool:
    finding_id = _fold_text(getattr(vulnerability, "finding_id", ""))
    if finding_id and finding_id in text_folded:
        return True
    finding_type = _fold_text(getattr(vulnerability, "type", ""))
    endpoint = _fold_text(getattr(vulnerability, "endpoint", ""))
    return bool(
        finding_type
        and endpoint
        and finding_type in text_folded
        and endpoint in text_folded
    )


def _has_executive_summary_heading(markdown_text: str) -> bool:
    return any(
        line.lstrip().startswith("#") and "resumen ejecutivo" in line.casefold()
        for line in markdown_text.splitlines()
    )


def _executive_summary_markdown(
    summary: dict, unconfirmed_count: int
) -> list[str]:
    """Resumen ejecutivo determinista para completar informes incompletos."""
    combined_critical = summary["reported_tools_critical_total"]
    combined_high = summary["reported_tools_high_total"]
    lines = [
        "## 📊 Resumen Ejecutivo",
        "",
        f"- **Hallazgos confirmados:** {summary['total_findings']}",
        f"- **CRITICAL total:** {summary['critical_total']}",
        f"- **HIGH total:** {summary['high_total']}",
        "- **CRITICAL + HIGH (crypto_inspector + access_control_prober):** "
        f"{summary['reported_tools_critical_and_high_total']}",
        "- **Confirmaciones activas de control de acceso:** "
        f"{summary['access_control_active_confirmations']}",
        f"- **Credenciales recuperadas:** {summary['recovered_credentials']}",
        f"- **Hashes rotos/obsoletos:** {summary['broken_hashes']}",
        f"- **Pruebas sin confirmación:** {unconfirmed_count}",
        "",
        "| Herramienta | CRITICAL | HIGH | CRITICAL + HIGH | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for tool in REPORTED_TOOLS:
        metrics = summary["by_tool"].get(tool, {})
        lines.append(
            f"| `{tool}` | {metrics.get('CRITICAL', 0)} | {metrics.get('HIGH', 0)} | "
            f"{metrics.get('critical_and_high', 0)} | {metrics.get('total', 0)} |"
        )
    lines.append(
        f"| **TOTAL combinado** | **{combined_critical}** | **{combined_high}** | "
        f"**{summary['reported_tools_critical_and_high_total']}** | "
        f"**{summary['reported_tools_total']}** |"
    )
    lines.append("")
    return lines


def _insert_executive_summary(markdown_text: str, summary_lines: list[str]) -> str:
    summary_block = "\n".join(summary_lines).strip()
    lines = markdown_text.splitlines()
    # Insertar antes de la primera sección de contenido, conservando los metadatos.
    content_heading = next(
        (
            index
            for index, line in enumerate(lines)
            if line.lstrip().startswith("## ")
            and "metadatos" not in line.casefold()
        ),
        None,
    )
    if content_heading is not None:
        before = lines[:content_heading]
        after = lines[content_heading:]
        return "\n".join([*before, summary_block, "", *after]).strip() + "\n"

    title_index = next(
        (index for index, line in enumerate(lines) if line.strip()), None
    )
    if title_index is not None and lines[title_index].startswith("# "):
        before = lines[: title_index + 1]
        after = lines[title_index + 1 :]
        return "\n".join([*before, "", summary_block, "", *after]).strip() + "\n"
    return f"{summary_block}\n\n{markdown_text.strip()}\n"


def _missing_highlight_lines(
    text_folded: str, vulnerability
) -> list[str]:
    """Devuelve los resaltados obligatorios que el LLM no incluyó."""
    lines: list[str] = []
    if _is_access_control(vulnerability):
        label = _access_control_confirmation_label(vulnerability)
        if "confirmada activamente" not in text_folded and _fold_text(label) not in text_folded:
            lines.append(
                f"- **Confirmacion Activa:** ✅ **{label}**. "
                "La herramienta reprodujo la explotacion contra el objetivo."
            )

    if _is_recovered_password(vulnerability):
        if "contrasena recuperada" not in text_folded:
            lines.append(
                f"- **Contrasena Recuperada:** "
                f"`{getattr(vulnerability, 'attack_result', None)}`"
            )
    elif getattr(vulnerability, "attack_result", None):
        if "resultado del ataque" not in text_folded:
            lines.append(
                f"- **Resultado del Ataque:** "
                f"`{getattr(vulnerability, 'attack_result', None)}`"
            )

    if _is_broken_hash(vulnerability):
        if (
            "hash roto" not in text_folded
            and "hash/checksum" not in text_folded
            and "obsoleto" not in text_folded
        ):
            lines.append(
                f"- **Hash Roto/Obsoleto:** `{_hash_value(vulnerability)}`"
            )

    if str(getattr(vulnerability, "context_role", "") or "").casefold() == "static_checksum":
        if (
            "falso positivo" not in text_folded
            and "checksum estatico" not in text_folded
        ):
            lines.append(
                "- **Clasificacion:** Falso positivo controlado / checksum estático "
                "(no explotable por sí mismo)."
            )
    return lines


def finalize_report_markdown(
    markdown_text: str, reporter_input: ReporterInput
) -> str:
    """Garantiza que todos los hallazgos y sus cadenas de ataque aparezcan en el informe.

    El LLM puede omitir hallazgos de access_control_prober o resumir en exceso.
    Si se detecta una omision, se anexa una ficha determinista generada desde el
    contrato, sin inventar datos.
    """
    findings = _sort_by_severity(list(reporter_input.validation_data.vulnerabilities))
    summary = _executive_summary(findings)
    unconfirmed_count = len(reporter_input.validation_data.unconfirmed_findings)
    needs_summary = not _has_executive_summary_heading(markdown_text)

    def analyze(text_folded: str, body_folded: str):
        missing = [
            vulnerability
            for vulnerability in findings
            if not _finding_is_mentioned(text_folded, vulnerability)
        ]
        incomplete = []
        for vulnerability in findings:
            if vulnerability in missing:
                continue
            highlight_lines = _missing_highlight_lines(body_folded, vulnerability)
            chain = _attack_chain(vulnerability)
            chain_missing = bool(chain) and not all(
                _fold_text(step) in text_folded for step in chain
            )
            if highlight_lines or chain_missing:
                incomplete.append((vulnerability, highlight_lines, chain_missing))
        return missing, incomplete

    text_folded = _fold_text(markdown_text)
    body_folded = _fold_text(_strip_executive_summary(markdown_text))
    missing, incomplete = analyze(text_folded, body_folded)

    if not needs_summary and not missing and not incomplete:
        return markdown_text

    if needs_summary:
        markdown_text = _insert_executive_summary(
            markdown_text,
            _executive_summary_markdown(summary, unconfirmed_count),
        )
        text_folded = _fold_text(markdown_text)
        body_folded = _fold_text(_strip_executive_summary(markdown_text))
        missing, incomplete = analyze(text_folded, body_folded)

    if not missing and not incomplete:
        return markdown_text

    parts = [
        markdown_text.rstrip(),
        "",
        "---",
        "",
        "## 🧾 Anexo Determinista de Hallazgos",
        "",
        (
            "> Este anexo se agrega automaticamente para garantizar que ningun "
            "hallazgo confirmado, resaltado obligatorio o cadena de ataque quede "
            "fuera del informe."
        ),
        "",
    ]

    if missing:
        parts.append("### Hallazgos no incluidos por la redaccion\n")
        for index, vulnerability in enumerate(missing, start=1):
            parts.extend(_render_finding_markdown(vulnerability, index))

    if incomplete:
        parts.append("### Hallazgos con contenido incompleto\n")
        for vulnerability, highlight_lines, chain_missing in incomplete:
            parts.append(
                f"#### {getattr(vulnerability, 'type', 'Hallazgo')} — "
                f"`{getattr(vulnerability, 'finding_id', None) or 'N/A'}`"
            )
            parts.append(f"- **Endpoint:** `{getattr(vulnerability, 'endpoint', '')}`")
            parts.append(f"- **Herramienta:** `{_primary_tool(vulnerability)}`")
            parts.extend(highlight_lines)
            if chain_missing:
                parts.append("- **Cadena de Ataque:**")
                for step in _attack_chain(vulnerability):
                    parts.append(f"  {step}")
            parts.append("")

    return "\n".join(parts)


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
