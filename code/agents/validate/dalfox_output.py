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
    evidence: str | None = None


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


def _load_json_findings(output: str) -> tuple[bool, list | None, bool]:
    try:
        report = json.loads(output)
    except json.JSONDecodeError:
        report = None
        json_lines = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                json_lines.append(item)
            elif isinstance(item, list):
                json_lines.extend(entry for entry in item if isinstance(entry, dict))
        if json_lines:
            return True, json_lines, False
        return False, None, False

    if isinstance(report, dict):
        if report.get("error"):
            return True, [], True
        findings = report.get("findings")
        if isinstance(findings, list):
            return True, [item for item in findings if isinstance(item, dict)], False
        if any(key in report for key in ("data", "url", "endpoint")):
            return True, [report], False
    if isinstance(report, list):
        return True, [item for item in report if isinstance(item, dict)], False
    return False, None, False


def parse_dalfox_output(raw_output: str) -> DalfoxResult:
    """Parse Dalfox JSON reports and legacy ``[POC]`` output lines."""
    if not isinstance(raw_output, str):
        raise TypeError("Dalfox output must be text")

    cleaned_output = _ANSI_ESCAPE.sub("", raw_output)
    is_json_report, raw_findings, is_json_error = _load_json_findings(
        cleaned_output
    )
    if is_json_error:
        return DalfoxResult("ERROR", (), "Dalfox reported an execution error")
    if is_json_report and raw_findings is not None:
        findings = []
        seen = set()
        verification_by_type = {
            "V": "verified",
            "A": "ast_detected",
            "R": "reflected",
            "I": "informational",
        }
        for item in raw_findings:
            endpoint = item.get("data") or item.get("url") or item.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint:
                continue
            finding_type = str(item.get("type") or "").upper()
            verification = verification_by_type.get(finding_type, "unverified")
            parameter = item.get("param")
            parameter = parameter if isinstance(parameter, str) and parameter else None
            method = str(item["method"]).upper() if item.get("method") else None
            key = (endpoint, method, parameter, verification)
            if key in seen:
                continue
            seen.add(key)
            context = item.get("inject_type") or item.get("detection_method")
            evidence_parts = [
                item.get("evidence"),
                item.get("confidence_reason"),
                item.get("type_description"),
            ]
            evidence = "; ".join(
                part.strip()
                for part in evidence_parts
                if isinstance(part, str) and part.strip()
            ) or None
            findings.append(
                DalfoxFinding(
                    endpoint=endpoint,
                    method=method,
                    parameter=parameter,
                    verification=verification,
                    context=str(context) if context else None,
                    payload=(
                        str(item["payload"])
                        if item.get("payload") is not None
                        else None
                    ),
                    evidence=evidence,
                )
            )
        return DalfoxResult(
            "FINDINGS" if findings else "NO_FINDINGS",
            tuple(findings),
        )

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
        key = (endpoint, method, parameter, verification)
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
            "method": finding.method,
            "parameter": finding.parameter,
            "verification": finding.verification,
            "context": finding.context,
            "payload": finding.payload,
            "evidence": "; ".join(
                part
                for part in (
                    finding.evidence
                    or f"Dalfox reported a {finding.verification} POC",
                    f"in {finding.context}" if finding.context else "",
                    f"for parameter {finding.parameter}" if finding.parameter else "",
                )
                if part
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
            method = str(
                finding.get("method") or execution.get("method") or ""
            ).upper() or None
            matching = [
                existing
                for existing in vulnerabilities
                if isinstance(existing, dict)
                and (
                    "xss" in str(existing.get("type", "")).casefold()
                    or "cross-site scripting"
                    in str(existing.get("type", "")).casefold()
                )
                and str(existing.get("endpoint", "")).casefold()
                == str(endpoint).casefold()
                and str(existing.get("parameter") or "").casefold()
                == str(parameter or "").casefold()
            ]
            exact_method = [
                existing
                for existing in matching
                if method
                and str(existing.get("method") or "").upper() == method
            ]
            existing = (
                exact_method[0]
                if len(exact_method) == 1
                else matching[0]
                if len(matching) == 1
                and (
                    not matching[0].get("method")
                    or not method
                    or str(matching[0].get("method")).upper() == method
                )
                else None
            )
            verification_steps = _build_verification_steps(
                method,
                str(parameter) if parameter else None,
                str(finding.get("context")) if finding.get("context") else None,
            )
            if existing is not None:
                if not existing.get("method"):
                    existing["method"] = method
                if not existing.get("verification_steps"):
                    existing["verification_steps"] = verification_steps
                evidence = str(finding.get("evidence") or "").strip()
                current_evidence = str(existing.get("evidence") or "")
                if evidence and evidence.casefold() not in current_evidence.casefold():
                    existing["evidence"] = (
                        f"{current_evidence}; {evidence}".strip("; ")
                    )[:3000]
                continue
            vulnerabilities.append(
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "method": method,
                    "evidence": finding.get("evidence")
                    or "Dalfox reported a verified XSS proof of concept.",
                    "verification_steps": verification_steps,
                    "reproducible_command": execution.get("command", ""),
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                }
            )
    return {**model_output, "vulnerabilities": vulnerabilities}


def _build_verification_steps(
    method: str | None,
    parameter: str | None,
    context: str | None,
) -> str:
    request_method = method or "captured HTTP method"
    parameter_detail = f" and parameter `{parameter}`" if parameter else ""
    context_detail = f" in `{context}`" if context else ""
    if request_method == "POST":
        return (
            f"Dalfox marked an XSS proof as verified for the captured POST request"
            f"{parameter_detail}{context_detail}. In the authorized test environment, "
            "repeat the captured request and confirm the same behavior in the rendered "
            "response. A POST result alone does not establish stored XSS; that requires "
            "a separate readback of the submitted value. The raw HTTP input file used "
            "by the tool was temporary, so the recorded command cannot be replayed as-is."
        )
    return (
        f"Dalfox marked an XSS proof as verified for the captured {request_method} "
        f"request{parameter_detail}{context_detail}. In the authorized test environment, "
        "repeat the same request and confirm JavaScript execution in the rendered page; "
        "text reflection alone is not sufficient."
    )
