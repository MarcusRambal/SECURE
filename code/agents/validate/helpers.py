import json
import logging
import re
from datetime import datetime, timezone

from pydantic import ValidationError

from config import (
    TOOL_COMMAND_TEMPLATES,
)

from contract_schemas import ValidateOutput, Vulnerability

logger = logging.getLogger("validate-agent-worker")




def build_real_command(tool_name: str, args: dict) -> str:
    """Construye el comando CLI exacto según la plantilla real y los argumentos ejecutados."""
    template = TOOL_COMMAND_TEMPLATES.get(tool_name)
    if not template:
        return f"{tool_name} {json.dumps(args)}"
    try:
        # Copia local para no mutar el diccionario original
        local_args = dict(args)
        if "{tags}" in template and "tags" not in local_args:
            local_args["tags"] = "xss,sqli,rce"
        return template.format(**local_args)
    except Exception:
        return f"{tool_name} {json.dumps(args)}"


def extract_evidence_line(raw_outputs: list[str], pattern: str, max_len: int = 300) -> str:
    """Extrae la primera línea de evidencia concreta truncada a max_len."""
    regex = re.compile(pattern, re.IGNORECASE)
    for output in raw_outputs:
        for line in output.splitlines():
            if regex.search(line):
                return line.strip()[:max_len]
    return ""


def clean_json_response(raw_response: str) -> str:
    """Limpia la salida del LLM eliminando bloques de código Markdown."""
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _build_output_from_args(args: dict,target_url: str,started_at: str,executed_commands: list[dict],) -> ValidateOutput:

    """Construye un ValidateOutput desde los argumentos del submit tool o del recovery.

    Reemplaza el campo reproducible_command por el comando real ejecutado según
    la primera herramienta listada en tools_used.
    """
    vulns_raw = args.get("vulnerabilities", []) or []
    vulnerabilities: list[Vulnerability] = []

    for v in vulns_raw:
        if not isinstance(v, dict):
            continue

        tools_used = v.get("tools_used", []) or []
        if isinstance(tools_used, str):
            tools_used = [t.strip() for t in tools_used.split(",") if t.strip()]

        # Determinar comando reproducible real
        real_cmd = "Comando no verificado"
        if tools_used:
            tool_used = tools_used[0]
            real_cmd = next(
                (c["command"] for c in executed_commands if c["tool"] == tool_used),
                f"Comando no verificado en ejecución real ({tool_used})",
            )
        else:
            real_cmd = (f"Comando no verificado (sin tools_used) para {v.get('endpoint', target_url)}")

        parameter = v.get("parameter", "") or None

        try:
            vulnerabilities.append(
                Vulnerability(
                    type=v.get("type", "Unknown"),
                    severity=v.get("severity", "MEDIUM"),
                    endpoint=v.get("endpoint", target_url),
                    parameter=parameter,
                    evidence=v.get("evidence", "Sin evidencia textual"),
                    reproducible_command=real_cmd,
                    confidence=v.get("confidence", "MEDIUM"),
                    tools_used=tools_used,
                )
            )
        except ValidationError as e:
            logger.warning(f"⚠️ Vulnerabilidad descartada por schema inválido: {e}")

    return ValidateOutput(
        target_url=args.get("target_url", target_url),
        vulnerabilities=vulnerabilities,
        unconfirmed_findings=[],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


def build_fallback_validate_output(
    target_url: str,
    raw_tool_outputs: list[str],
    executed_commands: list[dict],
    started_at: str,
) -> ValidateOutput:
    """Construye un resultado parcial usando evidencia de las herramientas."""
    detections = [
        ("SQL Injection", "sqlmap", r"sqlmap identified|dbms:|syntax error", "HIGH"),
        ("Cross-Site Scripting (XSS)", "dalfox", r"\[POC\]|\[V\]|\[FOUND\]|xss payload", "MEDIUM"),
        (
            "OS Command Injection",
            "commix",
            r"vulnerable to.*command injection|is vulnerable|os command",
            "CRITICAL",
        ),
        ("Template Vulnerability (Nuclei)", "nuclei", r"\[(critical|high|medium|low)\]", "HIGH"),
    ]
    vulnerabilities = []

    for vulnerability_type, tool_name, pattern, severity in detections:
        evidence = extract_evidence_line(raw_tool_outputs, pattern)
        if not evidence:
            continue
        command = next(
            (item["command"] for item in executed_commands if item["tool"] == tool_name),
            f"{tool_name} -u '{target_url}'",
        )
        if tool_name == "nuclei":
            evidence_lower = evidence.lower()
            severity = next(
                (level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if f"[{level.lower()}]" in evidence_lower),
                severity,
            )
        vulnerabilities.append(
            Vulnerability(
                type=vulnerability_type,
                severity=severity,
                endpoint=target_url,
                evidence=evidence,
                reproducible_command=command,
                confidence="HIGH",
                tools_used=[tool_name],
            )
        )

    return ValidateOutput(
        target_url=target_url,
        vulnerabilities=vulnerabilities,
        unconfirmed_findings=[
            {"fallback_note": "Respuesta LLM corrupta. Hallazgos recuperados desde logs."}
        ],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


