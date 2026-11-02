import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


logger = logging.getLogger("crawler_reports")
TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
CRAWLER_OUTPUT_DIR = TOOLS_DIR / "crawler" / "outputs"
DEEP_CRAWLER_OUTPUT_DIR = TOOLS_DIR / "deep_crawler" / "outputs"
_SENSITIVE_NAME = re.compile(
    r"password|passwd|username|user[_-]?name|credential|token|secret|"
    r"api[_-]?key|auth(?:orization|entication)?|bearer|jwt|cookie|"
    r"session|csrf|xsrf|code",
    re.IGNORECASE,
)


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        query = urlencode(
            [
                (name, "[REDACTED]" if _SENSITIVE_NAME.search(name) else item)
                for name, item in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc.rsplit("@", 1)[-1],
                parts.path,
                query,
                "",
            )
        )
    except ValueError:
        return "[invalid-url]"


def _sanitize_report(value: object, key: str = "") -> object:
    if _SENSITIVE_NAME.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(name): _sanitize_report(item, str(name))
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_report(item, key) for item in value]
    if isinstance(value, str) and (
        key.casefold() in {"url", "requested_url", "final_url", "action", "path"}
        or value.startswith(("http://", "https://"))
    ):
        return _redact_url(value)
    return value


def _persist_json_report(result: dict, output_dir: Path, tool_name: str) -> dict:
    raw_output = result.get("output")
    execution_status = str(result.get("status", "UNKNOWN"))
    try:
        report = json.loads(raw_output) if isinstance(raw_output, str) else None
    except json.JSONDecodeError as error:
        report = {
            "error": f"{tool_name} did not return valid JSON",
            "diagnostic": str(error),
            "execution_status": execution_status,
        }
    if not isinstance(report, dict):
        report = {
            "error": f"{tool_name} did not return a JSON object",
            "execution_status": execution_status,
        }

    report_error = bool(report.get("error")) or execution_status != "SUCCESS"
    sanitized_report = _sanitize_report(report)
    if not isinstance(sanitized_report, dict):
        raise TypeError("Sanitized crawler report must remain a JSON object")

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    filename = f"{timestamp}_{uuid.uuid4().hex}.json"
    relative_path = f"tools/{tool_name}/outputs/{filename}"
    sanitized_report["saved_report"] = relative_path
    output_path = output_dir / filename
    try:
        output_path.write_text(
            json.dumps(sanitized_report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        logger.exception("Could not persist %s JSON report", tool_name)
        return {
            **result,
            "status": "FAILED",
            "output": json.dumps(
                {
                    "error": f"{tool_name} report persistence failed",
                    "diagnostic": type(error).__name__,
                },
                ensure_ascii=False,
            ),
        }

    return {
        **result,
        "status": "FAILED" if report_error else execution_status,
        "output": json.dumps(sanitized_report, ensure_ascii=False),
        "saved_report": relative_path,
    }


def persist_crawler_report(result: dict, arguments: dict) -> dict:
    return _persist_json_report(result, CRAWLER_OUTPUT_DIR, "crawler")


def persist_deep_crawler_report(result: dict, arguments: dict) -> dict:
    return _persist_json_report(result, DEEP_CRAWLER_OUTPUT_DIR, "deep_crawler")
