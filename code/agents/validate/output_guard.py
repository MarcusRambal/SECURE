import re
from urllib.parse import parse_qsl, urlsplit


_SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
_CONFIDENCE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _canonical_type(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "", str(value).casefold())
    if "xss" in normalized or "crosssitescripting" in normalized:
        subtype = next(
            (name for name in ("stored", "reflected", "dom") if name in normalized),
            None,
        )
        return f"xss:{subtype}" if subtype else "xss"
    if normalized == "sqli" or ("sql" in normalized and "inject" in normalized):
        return "sqli"
    if "command" in normalized and "inject" in normalized:
        return "commandinjection"
    return normalized


def _endpoint_identity(endpoint: str) -> tuple[str, str, int | None, str]:
    parts = urlsplit(endpoint)
    scheme = parts.scheme.casefold()
    hostname = (parts.hostname or "").casefold()
    port = parts.port
    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    return scheme, hostname, port, parts.path or "/"


def _parameter_identity(finding: dict) -> str | None:
    parameter = finding.get("parameter")
    if isinstance(parameter, str) and parameter.strip():
        return parameter.strip()

    endpoint = finding.get("endpoint")
    if not isinstance(endpoint, str):
        return None
    try:
        parameters = {
            name for name, _ in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)
            if name
        }
    except ValueError:
        return None
    return next(iter(parameters)) if len(parameters) == 1 else None


def _merge_findings(primary: dict, duplicate: dict) -> dict:
    merged = dict(primary)

    duplicate_type = _canonical_type(duplicate.get("type"))
    if duplicate_type == "xss":
        merged["type"] = "Cross-Site Scripting (XSS)"
    elif duplicate_type.startswith("xss:"):
        if len(str(duplicate.get("type", ""))) > len(str(primary.get("type", ""))):
            merged["type"] = duplicate["type"]
    elif duplicate_type == "sqli":
        merged["type"] = "SQL Injection"
    elif len(str(duplicate.get("type", ""))) > len(str(primary.get("type", ""))):
        merged["type"] = duplicate["type"]

    if _SEVERITY_RANK.get(duplicate.get("severity"), -1) > _SEVERITY_RANK.get(
        merged.get("severity"), -1
    ):
        merged["severity"] = duplicate["severity"]
    if _CONFIDENCE_RANK.get(duplicate.get("confidence"), -1) > _CONFIDENCE_RANK.get(
        merged.get("confidence"), -1
    ):
        merged["confidence"] = duplicate["confidence"]

    verification_steps = []
    for finding in (primary, duplicate):
        steps = finding.get("verification_steps")
        if (
            isinstance(steps, str)
            and steps.strip()
            and steps.casefold() not in {item.casefold() for item in verification_steps}
        ):
            verification_steps.append(steps.strip())
    if verification_steps:
        merged["verification_steps"] = "\n\n".join(verification_steps)

    tools = []
    for finding in (primary, duplicate):
        for tool in finding.get("tools_used", []) or []:
            if isinstance(tool, str) and tool and tool not in tools:
                tools.append(tool)
    merged["tools_used"] = tools

    evidence = []
    for finding in (primary, duplicate):
        text = finding.get("evidence")
        if isinstance(text, str) and text.strip() and text.casefold() not in {
            item.casefold() for item in evidence
        }:
            evidence.append(text.strip())
    merged["evidence"] = "; ".join(evidence)[:3000]

    command = duplicate.get("reproducible_command")
    current_command = str(merged.get("reproducible_command") or "")
    if (
        isinstance(command, str)
        and command.strip()
        and (
            not current_command.strip()
            or "no verificado" in current_command.casefold()
        )
    ):
        merged["reproducible_command"] = command

    return merged


def guard_validate_output(output: dict) -> tuple[dict, int]:
    """Consolidate duplicate confirmed findings while preserving distinct parameters."""
    if not isinstance(output, dict):
        raise TypeError("Validation output must be a JSON object")

    vulnerabilities = output.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise TypeError("Validation vulnerabilities must be a list")
    if any(not isinstance(finding, dict) for finding in vulnerabilities):
        raise TypeError("Each confirmed vulnerability must be a JSON object")

    grouped: dict[
        tuple[str, tuple[str, str, int | None, str]],
        list[tuple[int, dict]],
    ] = {}
    for index, finding in enumerate(vulnerabilities):
        endpoint = finding.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("Each confirmed vulnerability must have an endpoint")
        key = (
            _canonical_type(finding.get("type")),
            _endpoint_identity(endpoint),
        )
        grouped.setdefault(key, []).append((index, dict(finding)))

    consolidated: list[tuple[int, dict]] = []
    removed = 0
    for findings in grouped.values():
        merged = findings[0][1]
        for _, duplicate in findings[1:]:
            merged = _merge_findings(merged, duplicate)
            removed += 1

        parameters = []
        methods = []
        for _, finding in findings:
            parameter = _parameter_identity(finding)
            if parameter and parameter not in parameters:
                parameters.append(parameter)
            method = finding.get("method")
            if isinstance(method, str) and method.strip():
                normalized_method = method.strip().upper()
                if normalized_method not in methods:
                    methods.append(normalized_method)
        if parameters:
            merged["parameter"] = ", ".join(parameters)
        if methods:
            merged["method"] = ", ".join(methods)
        consolidated.append((findings[0][0], merged))

    consolidated.sort(key=lambda item: item[0])
    return (
        {
            **output,
            "vulnerabilities": [finding for _, finding in consolidated],
        },
        removed,
    )
