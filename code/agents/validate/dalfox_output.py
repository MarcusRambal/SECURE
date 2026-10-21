"""Normalize Dalfox CLI output and build a minimal validator context.

Dalfox's CLI output is not a stable JSON contract. Only its POC lines are
interpreted; raw stdout, request bodies, headers, and unrelated log lines are
never included in the validator context.
"""

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from context_utils import sanitize_endpoint_for_context


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BRACKET_TAG = re.compile(r"\[([^\]]+)\]")
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


@dataclass(frozen=True)
class DalfoxFinding:
    endpoint: str
    method: str | None
    parameter: str | None
    verification: str
    context: str | None
    payload: str | None


@dataclass(frozen=True)
class DalfoxResult:
    status: str
    findings: tuple[DalfoxFinding, ...]
    message: str | None = None


def _extract_parameter_and_payload(endpoint: str) -> tuple[str | None, str | None]:
    try:
        parameters = parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)
    except ValueError:
        return None, None
    if not parameters:
        return None, None

    for parameter, value in parameters:
        if any(marker in value.casefold() for marker in ("<", ">", "alert", "javascript:", "onerror")):
            return parameter, value
    return parameters[0]


def parse_dalfox_output(raw_output: str) -> DalfoxResult:
    """Parse common Dalfox ``[POC][V|R][METHOD][context] URL`` output lines."""
    if not isinstance(raw_output, str):
        raise TypeError("Dalfox output must be text")

    cleaned_output = _ANSI_ESCAPE.sub("", raw_output)
    findings: list[DalfoxFinding] = []
    seen: set[tuple[str, str | None, str]] = set()
    for raw_line in cleaned_output.splitlines():
        line = raw_line.strip()
        tags = [tag.strip() for tag in _BRACKET_TAG.findall(line)]
        if not any(tag.casefold() == "poc" for tag in tags):
            continue

        url_match = _URL.search(line)
        if not url_match:
            continue
        endpoint = url_match.group(0).rstrip(".,);]")
        method = next(
            (tag.upper() for tag in tags if tag.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}),
            None,
        )
        verification_tag = next(
            (tag.casefold() for tag in tags if tag.casefold() in {"v", "r"}),
            "",
        )
        verification = {
            "v": "verified",
            "r": "reflected",
        }.get(verification_tag, "unverified")
        context = next(
            (tag for tag in tags if tag.casefold().startswith("in")),
            None,
        )
        parameter, payload = _extract_parameter_and_payload(endpoint)
        key = (endpoint, parameter, verification)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            DalfoxFinding(
                endpoint=endpoint,
                method=method,
                parameter=parameter,
                verification=verification,
                context=context,
                payload=payload,
            )
        )

    if findings:
        return DalfoxResult("FINDINGS", tuple(findings))
    if not cleaned_output.strip():
        return DalfoxResult("ERROR", (), "Dalfox returned empty output")
    if cleaned_output.lstrip().casefold().startswith("skipped:"):
        return DalfoxResult("SKIPPED", (), "Input skipped by the Dalfox adapter")
    error_line = next(
        (
            line.strip()
            for line in cleaned_output.splitlines()
            if re.match(
                r"^\s*(?:\[(?:err|error|fatal)\]|err(?:or)?:|fatal:|failed:|"
                r"(?:c[oó]digo de salida|exit code)\s*:\s*[2-9]\b)",
                line,
                re.I,
            )
        ),
        None,
    )
    if error_line:
        return DalfoxResult("ERROR", (), "Dalfox reported an execution error")
    return DalfoxResult("NO_FINDINGS", ())


def build_dalfox_validator_context(
    result: DalfoxResult,
    *,
    target_id: str | None,
    request_id: str | None,
    endpoint: str,
    method: str,
) -> dict:
    """Project normalized results to fields that help the validator decide."""
    findings = [
        {
            "endpoint": sanitize_endpoint_for_context(finding.endpoint),
            "parameter": finding.parameter,
            "verification": finding.verification,
            "context": finding.context,
            "payload": finding.payload,
            "evidence": (
                f"Dalfox reported a {finding.verification} POC"
                + (f" in {finding.context}" if finding.context else "")
                + (f" for parameter {finding.parameter}" if finding.parameter else "")
            ),
        }
        for finding in result.findings
    ]
    record = {
        "tool": "dalfox",
        "status": result.status,
        "target_id": target_id,
        "request_id": request_id,
        "endpoint": sanitize_endpoint_for_context(endpoint),
        "method": method.upper(),
        "findings": findings,
    }
    if result.message:
        record["reason"] = result.message
    return record


def merge_verified_dalfox_findings(
    model_output: dict, executions: list[dict]
) -> dict:
    """Retain findings explicitly tagged verified by Dalfox even if omitted by the LLM."""
    vulnerabilities = [
        dict(finding) if isinstance(finding, dict) else finding
        for finding in (model_output.get("vulnerabilities", []) or [])
    ]
    known = {
        (
            str(finding.get("type", "")).casefold(),
            str(finding.get("endpoint", "")).casefold(),
            str(finding.get("parameter") or "").casefold(),
        )
        for finding in vulnerabilities
        if isinstance(finding, dict)
    }

    for execution in executions:
        if execution.get("tool") != "dalfox":
            continue
        try:
            normalized = json.loads(execution.get("output", ""))
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(normalized, dict) or normalized.get("status") != "FINDINGS":
            continue
        for finding in normalized.get("findings", []):
            if not isinstance(finding, dict) or finding.get("verification") != "verified":
                continue
            endpoint = finding.get("endpoint") or execution.get("endpoint")
            parameter = finding.get("parameter")
            key = (
                "cross-site scripting (xss)",
                str(endpoint).casefold(),
                str(parameter or "").casefold(),
            )
            if key in known:
                continue
            vulnerabilities.append(
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "evidence": finding.get("evidence")
                    or "Dalfox reported a verified XSS proof of concept.",
                    "reproducible_command": execution.get("command", ""),
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                }
            )
            known.add(key)
    return {**model_output, "vulnerabilities": vulnerabilities}
