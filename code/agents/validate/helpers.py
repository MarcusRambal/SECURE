import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

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
        if tool_name == "sqlmap":
            if local_args.get("request"):
                local_args.setdefault("file_path", "/tmp/secure-request.txt")
            elif local_args.get("target_url"):
                template = template.replace('-r "{file_path}"', '-u "{target_url}"')
        if "{tags}" in template and "tags" not in local_args:
            local_args["tags"] = "xss,sqli,rce"
        return template.format(**local_args)
    except Exception:
        return f"{tool_name} {json.dumps(args)}"


def prepare_sqlmap_request(request: dict,target_url: str,endpoint: str,method: str,) -> dict:
    """Adapta una request capturada al origen que SQLMap puede alcanzar."""
    prepared_request = dict(request)
    target_parts = urlsplit(target_url)
    captured_url = prepared_request.get("url") or endpoint
    captured_parts = urlsplit(captured_url)

    if target_parts.netloc:
        request_url = urlunsplit((
            target_parts.scheme or captured_parts.scheme,
            target_parts.netloc,
            captured_parts.path or "/",
            captured_parts.query,
            "",
        ))
        prepared_request["url"] = request_url

    prepared_request["method"] = prepared_request.get("method") or method or "GET"
    headers = prepared_request.get("headers")
    headers = dict(headers) if isinstance(headers, dict) else {}

    if target_parts.netloc:
        host_header = next(
            (name for name in headers if name.lower() == "host"),
            "host",
        )
        headers[host_header] = target_parts.netloc

        target_origin = urlunsplit((
            target_parts.scheme or captured_parts.scheme,
            target_parts.netloc,
            "/",
            "",
            "",
        ))
        for name, value in headers.items():
            if name.lower() == "referer" and isinstance(value, str):
                referer_parts = urlsplit(value)
                if referer_parts.netloc:
                    headers[name] = urlunsplit((
                        target_parts.scheme or referer_parts.scheme,
                        target_parts.netloc,
                        referer_parts.path or "/",
                        referer_parts.query,
                        "",
                    ))
                else:
                    headers[name] = urljoin(target_origin, value)

    prepared_request["headers"] = headers
    return prepared_request


def write_validate_context_snapshot(
    target_url: str,
    attack_type: str,
    agent_context: dict,
    sqlmap_executions: list[dict],
) -> Path:
    """Guarda el contexto enviado al LLM y las requests entregadas a SQLMap."""
    output_dir = Path(
        os.getenv(
            "VALIDATE_CONTEXT_OUTPUT_DIR",
            Path(__file__).with_name("validate_context"),
        )
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    safe_target = "".join(
        character if character.isalnum() else "_" for character in target_url
    ).strip("_")
    safe_attack_type = "".join(
        character if character.isalnum() else "_" for character in attack_type
    ).strip("_")
    output_path = output_dir / (
        f"{timestamp}_{safe_attack_type}_{safe_target[:60]}.json"
    )
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "attack_type": attack_type,
        "agent_context": agent_context,
        "sqlmap_executions": sqlmap_executions,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    return output_path


def extract_evidence_line(raw_outputs: list[str], pattern: str, max_len: int = 300) -> str:
    """Extrae la primera línea de evidencia concreta truncada a max_len."""
    regex = re.compile(pattern, re.IGNORECASE)
    for output in raw_outputs:
        for line in output.splitlines():
            if regex.search(line):
                return line.strip()[:max_len]
    return ""


def _match_executed_command(finding: dict,candidates: list[dict],) -> dict | None:
    references = {
        value
        for value in (finding.get("request_id"), finding.get("target_id"))
        if value is not None
    }
    for candidate in candidates:
        candidate_references = {
            value
            for value in (candidate.get("request_id"), candidate.get("target_id"))
            if value is not None
        }
        if references & candidate_references:
            return candidate

    parameter = finding.get("parameter")
    if isinstance(parameter, str) and parameter.strip():
        parameter_matches = [
            candidate
            for candidate in candidates
            if parameter.casefold() in str(candidate.get("output", "")).casefold()
        ]
        if len(parameter_matches) == 1:
            return parameter_matches[0]

    endpoint = finding.get("endpoint")
    if isinstance(endpoint, str) and endpoint:
        endpoint_matches = [
            candidate
            for candidate in candidates
            if endpoint == candidate.get("endpoint")
        ]
        if len(endpoint_matches) == 1:
            return endpoint_matches[0]

    return candidates[0] if len(candidates) == 1 else None


def build_validate_output_from_dict(args: dict,target_url: str,started_at: str,executed_commands: list[dict],) -> ValidateOutput:

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

    unconfirmed_findings = []
    for finding in args.get("unconfirmed_findings", []) or []:
        if not isinstance(finding, dict):
            continue

        normalized_finding = dict(finding)
        tools_used = normalized_finding.get("tools_used") or normalized_finding.get("tool_used") or []
        if isinstance(tools_used, str):
            tools_used = [tool.strip() for tool in tools_used.split(",") if tool.strip()]
        if tools_used:
            normalized_finding["tools_used"] = tools_used
        normalized_finding.pop("tool_used", None)

        tool_commands = [
            item
            for item in executed_commands
            if item.get("tool") in tools_used and item.get("command")
        ]
        matched_command = _match_executed_command(normalized_finding, tool_commands)
        if matched_command:
            normalized_finding["endpoint"] = matched_command.get("endpoint", target_url)
            normalized_finding.pop("request_id", None)
            if matched_command.get("request_id") is not None:
                normalized_finding["request_id"] = matched_command["request_id"]
            normalized_finding.pop("target_id", None)
            if matched_command.get("target_id") is not None:
                normalized_finding["target_id"] = matched_command["target_id"]
            normalized_finding["reproducible_command"] = matched_command["command"]
        else:
            normalized_finding.pop("request_id", None)
            normalized_finding.pop("target_id", None)
            normalized_finding.pop("endpoint", None)
            normalized_finding.pop("reproducible_command", None)
            normalized_finding["command_note"] = (
                "No se asigno un target o comando: el hallazgo no pudo "
                "correlacionarse con una ejecucion real unica."
            )

        unconfirmed_findings.append(normalized_finding)

    return ValidateOutput(
        target_url=target_url,
        vulnerabilities=vulnerabilities,
        unconfirmed_findings=unconfirmed_findings,
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


def build_fallback_validate_output(target_url: str,raw_tool_outputs: list[str],executed_commands: list[dict],started_at: str,) -> ValidateOutput:
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


