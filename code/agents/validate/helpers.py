import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

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


def get_sqli_test_parameters(endpoint: str, request: dict) -> list[tuple[str, str]]:
    """Return supported query, form, and JSON field names from a captured request."""
    parameters = []
    seen = set()
    try:
        query_names = [
            name for name, _ in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)
        ]
    except ValueError:
        query_names = []
    for name in query_names:
        key = (name, "query")
        if key not in seen:
            parameters.append(key)
            seen.add(key)

    headers = request.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    content_type = next(
        (
            str(value).split(";", 1)[0].strip().casefold()
            for name, value in headers.items()
            if isinstance(name, str) and name.casefold() == "content-type"
        ),
        "",
    )
    body = request.get("body")

    if content_type == "application/x-www-form-urlencoded":
        body_names = (
            [name for name, _ in parse_qsl(body, keep_blank_values=True)]
            if isinstance(body, str)
            else list(body) if isinstance(body, dict) else []
        )
        for name in body_names:
            key = (name, "form_body")
            if isinstance(name, str) and key not in seen:
                parameters.append(key)
                seen.add(key)
        return parameters

    if content_type != "application/json":
        return parameters

    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return parameters

    def visit_json(value: object, prefix: str = "") -> None:
        if isinstance(value, dict):
            for name, child in value.items():
                if not isinstance(name, str) or "." in name or "[]" in name:
                    continue
                path = f"{prefix}.{name}" if prefix else name
                visit_json(child, path)
        elif prefix and not isinstance(value, list):
            key = (prefix, "json_body")
            if key not in seen:
                parameters.append(key)
                seen.add(key)

    visit_json(body)
    return parameters


def sanitize_endpoint_for_context(endpoint: str) -> str:
    """Redact user info and query values before persisting or displaying a URL."""
    try:
        parts = urlsplit(endpoint)
        query = urlencode(
            [
                (name, "[REDACTED]")
                for name, _ in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
    except ValueError:
        return "[invalid-url]"

    return urlunsplit(
        (parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, query, "")
    )


def build_validate_sqli_context(sqlmap_executions: list[dict]) -> dict:
    """Builds SQLi context from the validation tools that actually ran."""
    return {
        "attack_type_filter": "sqli",
        "sqlmap_executions": [
            execution
            for execution in sqlmap_executions
            if isinstance(execution, dict) and execution.get("tool") == "sqlmap"
        ],
        "sqli_agent_executions": [
            execution
            for execution in sqlmap_executions
            if isinstance(execution, dict) and execution.get("tool") == "sqli_agent"
        ],
        "sqli_map_executions": [
            execution
            for execution in sqlmap_executions
            if isinstance(execution, dict) and execution.get("tool") == "sqli_map"
        ],
    }


def write_validate_context_snapshot(
    target_url: str,
    attack_type: str,
    agent_context: dict,
    sqlmap_executions: list[dict],
    task_id: str | None = None,
) -> Path:
    """Guarda el contexto del agente y las requests de validación ejecutadas."""
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
        "task_id": task_id,
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


def extract_sqlmap_findings(executions: list[dict]) -> list[dict]:
    """Extrae únicamente los hallazgos positivos explícitos de SQLMap."""
    findings = []
    positive_parameter_pattern = re.compile(
        r"""(?im)\bparameter\s+['"]?([^'"\s]+)['"]?\s+"""
        r"""(?:appears\s+to\s+be\b[^\r\n]*?\binjectable\b|"""
        r"""is\s+(?:['"][^'"]+['"]\s+)?injectable\b|is\s+vulnerable\b)"""
    )
    parameter_line_pattern = re.compile(
        r"(?im)^\s*Parameter:\s*(.+?)\s*$"
    )
    positive_marker_pattern = re.compile(
        r"(?i)sqlmap identified the following injection point\(s\)"
    )
    relevant_line_pattern = re.compile(
        r"(?im)sqlmap identified the following injection point\(s\)|"
        r"^\s*(?:Parameter|Type|Title|Payload):|"
        r"\bparameter\b.*\b(?:injectable|vulnerable)\b"
    )

    for execution in executions:
        if execution.get("tool") != "sqlmap":
            continue
        output = execution.get("output")
        if not isinstance(output, str):
            continue

        positive_parameter_matches = list(positive_parameter_pattern.finditer(output))
        has_positive_marker = bool(positive_marker_pattern.search(output))
        if not has_positive_marker and not positive_parameter_matches:
            continue

        parameters = []
        for match in parameter_line_pattern.finditer(output):
            parameter = re.sub(r"\s+\([^)]*\)\s*$", "", match.group(1)).strip()
            if parameter and parameter not in parameters:
                parameters.append(parameter)
        for match in positive_parameter_matches:
            parameter = match.group(1).strip()
            if parameter and parameter not in parameters:
                parameters.append(parameter)
        if not parameters:
            parameters = [None]

        evidence_lines = [
            line.strip()
            for line in output.splitlines()
            if relevant_line_pattern.search(line)
        ]
        evidence = "\n".join(evidence_lines)[:1200]
        if not evidence:
            evidence = "SQLMap reportó explícitamente un punto de inyección."

        for parameter in parameters:
            findings.append(
                {
                    "type": "SQL Injection",
                    "severity": "HIGH",
                    "endpoint": execution.get("endpoint"),
                    "parameter": parameter,
                    "evidence": evidence,
                    "confidence": "HIGH",
                    "tools_used": ["sqlmap"],
                    "target_id": execution.get("target_id"),
                    "request_id": execution.get("request_id"),
                    "reproducible_command": execution.get("command"),
                }
            )
    return findings


def merge_sqlmap_findings(model_output: dict, executions: list[dict]) -> dict:
    """Conserva detecciones positivas de SQLMap aunque el LLM omita clasificarlas."""
    vulnerabilities = list(model_output.get("vulnerabilities", []) or [])
    known_findings = {
        (
            str(finding.get("type", "")).casefold(),
            str(finding.get("endpoint", "")).casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        for finding in vulnerabilities
        if isinstance(finding, dict)
    }

    for finding in extract_sqlmap_findings(executions):
        key = (
            finding["type"].casefold(),
            str(finding.get("endpoint") or "").casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        if key not in known_findings:
            vulnerabilities.append(finding)
            known_findings.add(key)

    return {**model_output, "vulnerabilities": vulnerabilities}


def extract_sqli_map_findings(executions: list[dict]) -> list[dict]:
    """Extract positive detection-only reports from the SQLMap skill."""
    findings = []
    for execution in executions:
        if execution.get("tool") != "sqli_map":
            continue
        try:
            report = json.loads(execution.get("output", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        result = report.get("result") if isinstance(report, dict) else None
        if not isinstance(result, dict) or result.get("injectable") is not True:
            continue

        techniques = result.get("techniques")
        technique_text = (
            ", ".join(technique for technique in techniques if isinstance(technique, str))
            if isinstance(techniques, list)
            else ""
        )
        summary = result.get("summary")
        evidence = (
            "; ".join(line for line in summary if isinstance(line, str))[:1200]
            if isinstance(summary, list)
            else ""
        )
        if not evidence:
            evidence = "SQLMap detection reported this parameter as injectable"
        if technique_text:
            evidence += f" (techniques: {technique_text})"
        database = result.get("database")
        if isinstance(database, str) and database and database.casefold() != "unknown":
            evidence += f" (database: {database})"

        findings.append(
            {
                "type": "SQL Injection",
                "severity": "HIGH",
                "endpoint": execution.get("endpoint"),
                "parameter": execution.get("parameter"),
                "evidence": evidence,
                "confidence": "HIGH",
                "tools_used": ["sqli_map"],
                "target_id": execution.get("target_id"),
                "request_id": execution.get("request_id"),
                "reproducible_command": execution.get("command"),
            }
        )
    return findings


def merge_sqli_map_findings(model_output: dict, executions: list[dict]) -> dict:
    """Retain positive SQLMap-skill results if the model omits them."""
    vulnerabilities = list(model_output.get("vulnerabilities", []) or [])
    known_findings = {
        (
            str(finding.get("type", "")).casefold(),
            str(finding.get("endpoint", "")).casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        for finding in vulnerabilities
        if isinstance(finding, dict)
    }

    for finding in extract_sqli_map_findings(executions):
        key = (
            finding["type"].casefold(),
            str(finding.get("endpoint") or "").casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        if key not in known_findings:
            vulnerabilities.append(finding)
            known_findings.add(key)

    return {**model_output, "vulnerabilities": vulnerabilities}


def extract_sqli_agent_findings(executions: list[dict]) -> list[dict]:
    """Extract only positive error, boolean, or timing checks from the SQLi agent."""
    findings = []
    techniques = ("error_based", "boolean_based", "time_based")

    for execution in executions:
        if execution.get("tool") != "sqli_agent":
            continue
        try:
            report = json.loads(execution.get("output", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(report, dict) or report.get("error"):
            continue

        confirmed = [
            report[technique]
            for technique in techniques
            if isinstance(report.get(technique), dict)
            and report[technique].get("injectable") is True
        ]
        if not confirmed:
            continue

        evidence = []
        for result in confirmed:
            technique = result.get("technique", "SQLi")
            detail = f"{technique} validation reported injectable=true"
            login_check = result.get("login_or_bypass")
            if isinstance(login_check, dict) and login_check.get("injectable"):
                detail += (
                    "; OR tautology accepted and contradiction rejected "
                    f"(HTTP {login_check.get('true_status_code')} vs "
                    f"{login_check.get('false_status_code')})"
                )
            if result.get("database"):
                detail += f" (database: {result['database']})"
            if "baseline_length" in result:
                detail += (
                    f" (baseline/true/false response lengths: "
                    f"{result['baseline_length']}/{result['true_length']}/"
                    f"{result['false_length']})"
                )
            evidence.append(detail)

        findings.append(
            {
                "type": "SQL Injection",
                "severity": "HIGH",
                "endpoint": execution.get("endpoint"),
                "parameter": execution.get("parameter"),
                "evidence": "; ".join(evidence),
                "confidence": (
                    "HIGH"
                    if any(
                        item.get("technique") == "error_based"
                        or (
                            isinstance(item.get("login_or_bypass"), dict)
                            and item["login_or_bypass"].get("injectable")
                        )
                        for item in confirmed
                    )
                    else "MEDIUM"
                ),
                "tools_used": ["sqli_agent"],
                "target_id": execution.get("target_id"),
                "request_id": execution.get("request_id"),
                "reproducible_command": execution.get("command"),
            }
        )
    return findings


def merge_sqli_agent_findings(model_output: dict, executions: list[dict]) -> dict:
    """Retain positive SQLi-agent evidence if the model omits it."""
    vulnerabilities = list(model_output.get("vulnerabilities", []) or [])
    known_findings = {
        (
            str(finding.get("type", "")).casefold(),
            str(finding.get("endpoint", "")).casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        for finding in vulnerabilities
        if isinstance(finding, dict)
    }

    for finding in extract_sqli_agent_findings(executions):
        key = (
            finding["type"].casefold(),
            str(finding.get("endpoint") or "").casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        if key not in known_findings:
            vulnerabilities.append(finding)
            known_findings.add(key)

    return {**model_output, "vulnerabilities": vulnerabilities}


def _match_executed_command(finding: dict,candidates: list[dict],) -> dict | None:
    references = {
        value
        for value in (finding.get("request_id"), finding.get("target_id"))
        if value is not None and str(value).strip()
    }
    for candidate in candidates:
        candidate_references = {
            value
            for value in (candidate.get("request_id"), candidate.get("target_id"))
            if value is not None and str(value).strip()
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
            tool_commands = [
                command
                for command in executed_commands
                if command.get("tool") == tool_used and command.get("command")
            ]
            matched_command = _match_executed_command(v, tool_commands)
            real_cmd = (
                matched_command["command"]
                if matched_command
                else v.get("reproducible_command")
                or f"Comando no verificado en ejecución real ({tool_used})"
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

    for finding in extract_sqlmap_findings(executed_commands):
        vulnerabilities.append(
            Vulnerability(
                type=finding["type"],
                severity=finding["severity"],
                endpoint=finding.get("endpoint") or target_url,
                parameter=finding.get("parameter"),
                evidence=finding["evidence"],
                reproducible_command=finding.get("reproducible_command")
                or "Comando no verificado",
                confidence=finding["confidence"],
                tools_used=finding["tools_used"],
            )
        )

    for finding in extract_sqli_map_findings(executed_commands):
        vulnerabilities.append(
            Vulnerability(
                type=finding["type"],
                severity=finding["severity"],
                endpoint=finding.get("endpoint") or target_url,
                parameter=finding.get("parameter"),
                evidence=finding["evidence"],
                reproducible_command=finding.get("reproducible_command")
                or "MCP sqli_map --action detect",
                confidence=finding["confidence"],
                tools_used=finding["tools_used"],
            )
        )

    for finding in extract_sqli_agent_findings(executed_commands):
        vulnerabilities.append(
            Vulnerability(
                type=finding["type"],
                severity=finding["severity"],
                endpoint=finding.get("endpoint") or target_url,
                parameter=finding.get("parameter"),
                evidence=finding["evidence"],
                reproducible_command=finding.get("reproducible_command")
                or "MCP sqli_agent",
                confidence=finding["confidence"],
                tools_used=finding["tools_used"],
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
