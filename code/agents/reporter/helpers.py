import json
import logging
import re
import unicodedata

from langdetect import DetectorFactory, LangDetectException, detect_langs

from contract_schemas import ReporterInput
from config import REPORTER_MAX_ENDPOINTS, REPORTER_MAX_EVIDENCE_CHARS

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW")
ACCESS_CONTROL_TOOL = "access_control_prober"
CRYPTO_TOOL = "crypto_inspector"
REPORTED_TOOLS = (CRYPTO_TOOL, ACCESS_CONTROL_TOOL)
OWASP_XSS_REFERENCE = {
    "cwe": "CWE-79",
    "owasp": "A05:2025",
    "source": "https://owasp.org/Top10/2025/A05_2025-Injection/",
}
_XSS_FINDING_TYPES = {
    "cross-site scripting (xss)",
    "reflected dom cross-site scripting (xss)",
    "stored cross-site scripting (xss)",
}
_HASH_PATTERN = re.compile(
    r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)
logger = logging.getLogger("reporter-agent-worker")
DetectorFactory.seed = 0
_ENGLISH_REPORT_LABEL = re.compile(
    r"(?im)^\s*(?:#{1,6}\s*|[-*]\s*|\|\s*)"
    r"(?:[^\w\s*|]+\s*)?(?:\d+[.)]\s*)?"
    r"(?:\*\*)?(?:executive summary|summary|security audit report|security assessment|"
    r"overview|scope|findings|vulnerabilities|recommendations|remediation|"
    r"conclusions|next steps|evidence|description|impact|severity|"
    r"attack chain|reproducible command)(?:\*\*)?(?:\s*:|\s*\||\s*$)"
)


def report_has_english_narrative(markdown_text: str, reporter_input: ReporterInput) -> bool:
    """Detecta prosa inglesa evidente sin analizar datos técnicos originales."""
    text = re.sub(r"```[^\n]*\n[\s\S]*?(?:```|$)", " ", markdown_text)
    original_values = []
    for finding in reporter_input.validation_data.vulnerabilities:
        original_values.extend(
            [
                finding.type,
                finding.evidence,
                _evidence_for_report(finding),
                finding.reproducible_command,
                finding.verification_steps,
                finding.attack_result,
                *finding.attack_chain,
            ]
        )
    for finding in reporter_input.validation_data.unconfirmed_findings:
        if isinstance(finding, dict):
            original_values.extend(finding.values())
    for value in original_values:
        if isinstance(value, str) and len(value.strip()) >= 8:
            text = text.replace(value, " ")
    text = re.sub(r"`[^`]*`", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    if _ENGLISH_REPORT_LABEL.search(text):
        return True

    for line in text.splitlines():
        words = re.findall(r"[^\W\d_]+", line, re.UNICODE)
        if len(words) < 4 or len(line) < 28:
            continue
        try:
            languages = detect_langs(line[:3000])
        except LangDetectException:
            logger.warning("[REPORTER] No se pudo detectar el idioma de un fragmento.")
            continue
        if languages and languages[0].lang == "en" and languages[0].prob >= 0.95:
            return True
    return False


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


def _severity_of(vulnerability) -> str | None:
    severity = str(getattr(vulnerability, "severity", "") or "").upper()
    if severity == "CRITICAL":
        return "HIGH"
    if severity == "INFO":
        return None
    if severity in SEVERITY_ORDER:
        return severity
    raise ValueError(f"Severidad no reconocida: {severity!r}")


def _sort_by_severity(vulnerabilities: list) -> list:
    """Ordena las vulnerabilidades por severidad de presentación."""
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


def _split_findings(reporter_input: ReporterInput) -> tuple[list, list]:
    vulnerabilities = []
    informational = []
    for finding in reporter_input.validation_data.vulnerabilities:
        if _severity_of(finding) is None:
            informational.append(finding)
        else:
            vulnerabilities.append(finding)
    return _sort_by_severity(vulnerabilities), informational


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
    return (
        _severity_of(vulnerability) is not None
        and ACCESS_CONTROL_TOOL in _tool_names(vulnerability)
    )


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
        tool: {"total": 0, **{severity: 0 for severity in SEVERITY_ORDER}}
        for tool in REPORTED_TOOLS
    }
    for vulnerability in findings:
        for tool in _tool_names(vulnerability) or ["unknown"]:
            bucket = metrics.setdefault(
                tool,
                {"total": 0, **{severity: 0 for severity in SEVERITY_ORDER}},
            )
            bucket["total"] += 1
            severity = _severity_of(vulnerability)
            bucket[severity] += 1
    return metrics


def _executive_summary(findings: list, informational_count: int) -> dict:
    counts = _severity_counts(findings)
    by_tool = _tool_metrics(findings)
    reported_findings = [
        vulnerability
        for vulnerability in findings
        if _primary_tool(vulnerability) in REPORTED_TOOLS
    ]
    reported_high = sum(
        1
        for vulnerability in reported_findings
        if _severity_of(vulnerability) == "HIGH"
    )
    return {
        "scope": "Hallazgos combinados de crypto_inspector y access_control_prober",
        "total_findings": len(findings),
        "high_total": counts["HIGH"],
        "informational_count": informational_count,
        "reported_tools_total": len(reported_findings),
        "reported_tools_high_total": reported_high,
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
    # La evidencia de alta severidad conserva un límite más amplio.
    if _severity_of(vulnerability) == "HIGH" and limit > 0:
        limit = max(limit, 1200)
    return _limit_text(evidence, limit)


def _classification_reference(vulnerability) -> dict | None:
    finding_type = str(getattr(vulnerability, "type", "") or "").strip().casefold()
    cwe = str(getattr(vulnerability, "cwe", "") or "").strip()
    owasp = str(getattr(vulnerability, "owasp", "") or "").strip()
    if (
        finding_type not in _XSS_FINDING_TYPES
        or owasp
        or (cwe and cwe.casefold() != "cwe-79")
    ):
        return None
    return dict(OWASP_XSS_REFERENCE)


def _evidence_lines(vulnerability) -> list[str]:
    evidence = _evidence_for_report(vulnerability)
    segments = evidence.split("; El validador ")
    if len(segments) == 1:
        return [f"- **Evidencia:** `{evidence}`"]
    segments = [segments[0], *(f"El validador {part}" for part in segments[1:])]
    split_segments = [segment.split(" Prueba enviada: ", 1) for segment in segments]
    if not all(len(parts) == 2 and parts[0] == split_segments[0][0] for parts in split_segments):
        return [f"- **Evidencia:** `{evidence}`"]
    return [
        f"- **Evidencia:** `{split_segments[0][0]}`",
        *(f"- **Prueba enviada:** `{parts[1]}`" for parts in split_segments),
    ]


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
        "method": getattr(vulnerability, "method", None),
        "parameter": getattr(vulnerability, "parameter", None),
        "confidence": getattr(vulnerability, "confidence", None),
        "cwe": getattr(vulnerability, "cwe", None),
        "owasp": getattr(vulnerability, "owasp", None),
        "classification_reference": _classification_reference(vulnerability),
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
        "verification_steps": getattr(vulnerability, "verification_steps", None),
        "reproducible_command": getattr(vulnerability, "reproducible_command", ""),
    }


def _render_finding_markdown(vulnerability, index: int) -> list[str]:
    """Ficha determinista de un hallazgo, usada por fallback y anexo de garantía."""
    severity = _severity_of(vulnerability) or "Informativo"
    attack_chain = _attack_chain(vulnerability)
    tool = _primary_tool(vulnerability)
    parts = [f"### {index}. [{severity}] {getattr(vulnerability, 'type', 'Unknown')}"]
    if getattr(vulnerability, "finding_id", None):
        parts.append(f"- **ID del hallazgo:** `{vulnerability.finding_id}`")
    parts.append(f"- **Herramienta:** `{tool}`")
    parts.append(f"- **Endpoint:** `{getattr(vulnerability, 'endpoint', '')}`")
    if getattr(vulnerability, "method", None):
        parts.append(f"- **Método:** `{vulnerability.method}`")
    if getattr(vulnerability, "parameter", None):
        parts.append(f"- **Parámetro:** `{vulnerability.parameter}`")
    parts.append(
        f"- **Certeza:** `{getattr(vulnerability, 'confidence', None) or 'N/A'}`"
    )
    cwe = getattr(vulnerability, "cwe", None)
    owasp = getattr(vulnerability, "owasp", None)
    if cwe or owasp:
        parts.append(
            "- **Clasificación reportada por la herramienta:** "
            + " · ".join(value for value in (cwe, owasp) if value)
        )
    reference = _classification_reference(vulnerability)
    if reference:
        parts.append(
            "- **Clasificación orientativa por tipo de hallazgo:** "
            f"{reference['cwe']} · OWASP Top 10 {reference['owasp']} (Inyección)."
        )
        parts.append(
            "- **Mitigación orientativa:** Evitar insertar datos no confiables como HTML; "
            "codificar la salida según su contexto y sanitizar el HTML cuando sea necesario."
        )
    if getattr(vulnerability, "context_role", None):
        parts.append(f"- **Rol del contexto:** `{vulnerability.context_role}`")
    if str(getattr(vulnerability, "context_role", "") or "").casefold() == "static_checksum":
        parts.append(
            "- **Clasificación:** Falso positivo controlado / checksum estático "
            "(no explotable por sí mismo)."
        )

    if _is_access_control(vulnerability):
        parts.append(
            f"- **Confirmación activa:** ✅ **{_access_control_confirmation_label(vulnerability)}**. "
            "La herramienta reprodujo la explotación contra el objetivo."
        )

    if _is_recovered_password(vulnerability):
        parts.append(
            f"- **Contraseña recuperada:** `{getattr(vulnerability, 'attack_result', None)}`"
        )
    elif getattr(vulnerability, "attack_result", None):
        parts.append(
            f"- **Resultado del Ataque:** `{getattr(vulnerability, 'attack_result', None)}`"
        )

    if _is_broken_hash(vulnerability):
        parts.append(f"- **Hash Roto/Obsoleto:** `{_hash_value(vulnerability)}`")

    parts.extend(_evidence_lines(vulnerability))

    if attack_chain:
        parts.append("- **Cadena de ataque original:**")
        for step in attack_chain:
            parts.append(f"  {step}")

    command = str(getattr(vulnerability, "reproducible_command", "") or "")
    if command:
        if command.startswith("browserXssValidator ") and command.rstrip().endswith(" --plan"):
            parts.append("- **Referencia de ejecución:** no es un comando reproducible; falta el plan.")
        else:
            parts.append("- **Comando reproducible:**")
        parts.extend(["```bash", command, "```"])
    parts.append("---\n")
    return parts


def build_report_metrics(reporter_input: ReporterInput) -> dict:
    """Metricas combinadas para logging y para el resumen ejecutivo."""
    findings, informational = _split_findings(reporter_input)
    return _executive_summary(findings, len(informational))


def build_fallback_markdown_report(reporter_input: ReporterInput, raw_error: str) -> str:
    """Construye un informe Markdown de respaldo sin depender del LLM."""
    vulnerabilities, informational = _split_findings(reporter_input)
    unconfirmed = reporter_input.validation_data.unconfirmed_findings
    summary = _executive_summary(vulnerabilities, len(informational))

    parts = [
        "# Informe de auditoría de ciberseguridad\n",
        f"**ID de Tarea:** `{reporter_input.task_id}`\n",
        f"**Objetivo Auditado:** `{reporter_input.target_url}`\n",
        f"**Modalidad:** `{reporter_input.attack_type}`\n",
    ]

    if reporter_input.recon_used_fallback or reporter_input.validate_used_fallback:
        parts.append(
            "> **Advertencia de análisis degradado:** Fases previas utilizaron mecanismos "
            "de respaldo. La cobertura del reporte puede ser parcial.\n"
        )

    parts.append(
        "> **Informe de respaldo:** No fue posible generar la narración con el modelo. "
        "Se presentan los datos disponibles y, cuando aplica, una clasificación orientativa."
    )
    parts.append(f"> **Detalle técnico original:** `{raw_error[:200]}`\n")

    parts.append("## Resumen Ejecutivo\n")
    parts.append(
        f"* **Objetivos prioritarios:** "
        f"{reporter_input.recon_data.recon_summary.total_targets_identified}"
    )
    parts.extend(_summary_lines(summary, len(unconfirmed)))
    parts.append("")

    parts.append("## Detalle de Hallazgos\n")
    if not vulnerabilities:
        parts.append(
            "*No se confirmaron vulnerabilidades explotables durante esta auditoría de seguridad.*\n"
        )
    else:
        for index, vulnerability in enumerate(vulnerabilities, start=1):
            parts.extend(_render_finding_markdown(vulnerability, index))

    if informational:
        parts.append("## Hallazgos informativos\n")
        for index, finding in enumerate(informational, start=1):
            parts.extend(_render_finding_markdown(finding, index))

    if unconfirmed:
        parts.append("## Pruebas sin confirmación\n")
        parts.append(
            f"Se ejecutaron {len(unconfirmed)} pruebas/evaluaciones adicionales "
            "que no arrojaron evidencia suficiente de explotación directa.\n"
        )

    return "\n".join(parts)


def build_reporter_context(reporter_input: ReporterInput) -> str:
    """Genera un resumen JSON compacto del contrato actual de Recon y Validate."""
    recon_summary = reporter_input.recon_data.recon_summary
    targets = reporter_input.recon_data.high_priority_targets
    findings, informational = _split_findings(reporter_input)
    summary = _executive_summary(findings, len(informational))
    unconfirmed = reporter_input.validation_data.unconfirmed_findings
    unconfirmed_tools = []
    for finding in unconfirmed:
        if not isinstance(finding, dict):
            continue
        tools = finding.get("tools_used")
        if isinstance(tools, list):
            unconfirmed_tools.extend(tool for tool in tools if isinstance(tool, str) and tool)
        for key in ("tool", "tool_used"):
            tool = finding.get(key)
            if isinstance(tool, str) and tool:
                unconfirmed_tools.append(tool)
    source_tools = list(dict.fromkeys(
        tool.casefold()
        for tool in [*(tool for finding in [*findings, *informational] for tool in _tool_names(finding)), *unconfirmed_tools]
    ))

    def unconfirmed_tool(finding: dict) -> str:
        tool = finding.get("tool") or finding.get("tool_used")
        if isinstance(tool, str) and tool:
            return tool
        tools = finding.get("tools_used")
        if isinstance(tools, list):
            return next((tool for tool in tools if isinstance(tool, str) and tool), "unknown")
        return "unknown"

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
            "source_tools": source_tools,
            "total_findings": len(findings),
            "severity_summary": summary["severity_summary"],
            "findings_order": list(SEVERITY_ORDER),
            "by_tool": summary["by_tool"],
            "findings": [
                _finding_context_payload(vulnerability) for vulnerability in findings
            ],
            "informational_count": len(informational),
            "informational_findings": [
                _finding_context_payload(finding) for finding in informational
            ],
            "unconfirmed_count": len(unconfirmed),
            "unconfirmed_findings": [
                {
                    "tool": unconfirmed_tool(finding),
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
    return ["## Resumen Ejecutivo", "", *_summary_lines(summary, unconfirmed_count), ""]


def _summary_lines(summary: dict, unconfirmed_count: int) -> list[str]:
    severity = ", ".join(
        f"{name}: {count}"
        for name, count in summary["severity_summary"].items()
        if count
    ) or "sin hallazgos"
    tools = ", ".join(
        f"{tool}: {metrics['total']}"
        for tool, metrics in summary["by_tool"].items()
        if metrics["total"]
    )
    lines = [
        f"- **Hallazgos confirmados:** {summary['total_findings']}",
        f"- **Severidad:** {severity}",
        f"- **Pruebas sin confirmación:** {unconfirmed_count}",
    ]
    if summary["informational_count"]:
        lines.append(f"- **Hallazgos informativos:** {summary['informational_count']}")
    if tools:
        lines.append(f"- **Hallazgos por herramienta:** {tools}")
    for label, key in (
        ("Confirmaciones activas de control de acceso", "access_control_active_confirmations"),
        ("Credenciales recuperadas", "recovered_credentials"),
        ("Hashes rotos u obsoletos", "broken_hashes"),
    ):
        if summary[key]:
            lines.append(f"- **{label}:** {summary[key]}")
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
                f"- **Confirmación activa:** ✅ **{label}**. "
                "La herramienta reprodujo la explotación contra el objetivo."
            )

    if _is_recovered_password(vulnerability):
        if "contrasena recuperada" not in text_folded:
            lines.append(
                f"- **Contraseña recuperada:** "
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
                "- **Clasificación:** Falso positivo controlado / checksum estático "
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
    vulnerabilities, informational = _split_findings(reporter_input)
    findings = [*vulnerabilities, *informational]
    if any(_classification_reference(finding) for finding in findings) and not all(
        OWASP_XSS_REFERENCE[key].casefold() in markdown_text.casefold()
        for key in ("owasp", "cwe")
    ):
        markdown_text = (
            f"{markdown_text.rstrip()}\n\n## Referencia de clasificación\n\n"
            "Los hallazgos XSS sin clasificación de la herramienta corresponden "
            "orientativamente a CWE-79 y OWASP Top 10 A05:2025 (Inyección). "
            "La clasificación se deriva del tipo de hallazgo; no fue reportada "
            "por la herramienta.\n"
        )
    incomplete_browser_command = any(
        (command := str(getattr(finding, "reproducible_command", "") or ""))
        and command.startswith("browserXssValidator ")
        and command.rstrip().endswith(" --plan")
        and command in markdown_text
        for finding in findings
    )
    if incomplete_browser_command and "no es un comando reproducible" not in markdown_text.casefold():
        markdown_text = (
            f"{markdown_text.rstrip()}\n\n"
            "> **Nota:** La referencia de ejecución del navegador no es un comando "
            "reproducible por sí sola: requiere el plan original.\n"
        )
    summary = _executive_summary(vulnerabilities, len(informational))
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
        "> Este anexo completa los hallazgos y datos omitidos en la narración.",
        "",
    ]

    missing_vulnerabilities = [finding for finding in missing if _severity_of(finding) is not None]
    missing_informational = [finding for finding in missing if _severity_of(finding) is None]
    if missing_vulnerabilities:
        parts.append("### Hallazgos no incluidos en la redacción\n")
        for index, vulnerability in enumerate(missing_vulnerabilities, start=1):
            parts.extend(_render_finding_markdown(vulnerability, index))

    if missing_informational:
        parts.append("### Hallazgos informativos no incluidos en la redacción\n")
        for index, finding in enumerate(missing_informational, start=1):
            parts.extend(_render_finding_markdown(finding, index))

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
