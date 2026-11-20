import json
import logging
import re
import shlex
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from docker_runner import docker_runner
from handlers.sqlmap_handler import build_raw_request
from handlers.report_writer import save_skill_report


IMAGE = "local-sqli-map:latest"
REQUEST_FILE = "/tmp/sqli-map-request.txt"
REPORT_MARKER = "SQLI_MAP_REPORT="
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "tools" / "sqli_map" / "outputs"
SQLMAP_CONTAINER_TIMEOUT_SECONDS = 1800
SQLMAP_EXTRACT_TIMEOUT_SECONDS = 3600
MAX_EVIDENCE_ROWS = 5

logger = logging.getLogger(__name__)
def _stringify_dump_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))[:250]
    return str(value)[:250]


def _extract_report(result: dict) -> Optional[dict]:
    for line in result.get("output", "").splitlines():
        if not line.startswith(REPORT_MARKER):
            continue
        try:
            report = json.loads(line[len(REPORT_MARKER):])
        except json.JSONDecodeError:
            return None
        return report if isinstance(report, dict) else None
    return None


def _table_evidence(report: dict) -> list[dict]:
    dumps = report.get("dumps")
    if not isinstance(dumps, list):
        return []

    evidence = []
    for dump in dumps:
        if not isinstance(dump, dict) or not isinstance(dump.get("table"), str):
            continue
        rows = dump.get("rows")
        rows = rows if isinstance(rows, list) else []
        columns = sorted({
            column
            for row in rows
            if isinstance(row, dict)
            for column in row
            if isinstance(column, str)
        })
        reported_count = dump.get("row_count")
        row_count = (
            reported_count
            if isinstance(reported_count, int) and not isinstance(reported_count, bool)
            and reported_count >= 0
            else len(rows)
        )
        item = {
            "database": dump.get("database") if isinstance(dump.get("database"), str) else None,
            "table": dump["table"],
            "row_count": row_count,
            "truncated": dump.get("truncated") is True,
            "columns": columns,
            "preview": [
                [_stringify_dump_value(row.get(column)) for column in columns]
                for row in rows[:MAX_EVIDENCE_ROWS]
                if isinstance(row, dict)
            ],
            "status": "error" if dump.get("error") else ("retrieved" if row_count else "empty"),
            "values_redacted": False,
        }
        evidence.append(item)
    return evidence


def _set_dump_evidence(report: dict, tables: list[dict], source: str) -> None:
    report["dumps"] = [dict(table) for table in tables]
    report["evidence"] = {
        "type": "database_table_extraction",
        "source": source,
        "values_redacted": any(
            table.get("values_redacted") is True for table in tables
        ),
        "tables": [dict(table) for table in tables],
    }


def _sanitize_diagnostics(output: str) -> list[str]:
    diagnostics = []
    for line in (line.strip() for line in output.splitlines() if line.strip()):
        line = re.sub(
            r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:.*$",
            r"\1: [REDACTED]", line,
        )
        line = re.sub(
            r"(?i)\b(token|password|secret)\s*([=:])\s*([^\s,;]+)",
            r"\1\2[REDACTED]", line,
        )

        def redact_url(match: re.Match[str]) -> str:
            try:
                parts = urlsplit(match.group(0))
                query = urlencode([
                    (name, "[REDACTED]")
                    for name, _ in parse_qsl(parts.query, keep_blank_values=True)
                ])
                return urlunsplit((
                    parts.scheme, parts.netloc.rsplit("@", 1)[-1],
                    parts.path, query, "",
                ))
            except ValueError:
                return "[invalid-url]"

        line = re.sub(r"https?://[^\s\"'<>]+", redact_url, line)
        diagnostics.append(line[:300])
        if len(diagnostics) == 8:
            break
    return diagnostics


def _strip_urls(report: dict) -> None:
    report.pop("url", None)
    result_report = report.get("result")
    if isinstance(result_report, dict):
        result_report.pop("url", None)
    dumps = report.get("dumps")
    if isinstance(dumps, list):
        for dump in dumps:
            if isinstance(dump, dict):
                dump.pop("url", None)


def _persist_report(report: dict, arguments: dict) -> str:
    try:
        output_path = save_skill_report(
            OUTPUT_DIR, "sqli_map", report,
            arguments.get("target_url"), arguments.get("param"),
        )
    except OSError as error:
        logger.exception("Could not save the sqli_map JSON report")
        report["persistence_error"] = f"Report save failed ({type(error).__name__})"
    else:
        logger.info("Saved sqli_map report to %s", output_path)
        report["saved_report"] = str(output_path)
    return json.dumps(report, ensure_ascii=False)


async def execute_sqli_map(arguments: dict) -> str:
    parameter = arguments.get("param")
    if not isinstance(parameter, str) or not parameter.strip():
        raise ValueError("A non-empty SQLi parameter is required")

    action = arguments.get("action", "detect")
    if not isinstance(action, str) or action not in {"detect", "validate", "extract"}:
        raise ValueError("Unsupported SQLMap action")

    target_url = arguments.get("target_url")
    request = arguments.get("request")
    input_files = {}
    command_args = ["--action", action, "--param", parameter]

    if isinstance(request, dict):
        request = dict(request)
        if isinstance(target_url, str) and target_url:
            request["url"] = target_url
            headers = request.get("headers")
            if isinstance(headers, dict):
                target_host = urlsplit(target_url).netloc
                for name in headers:
                    if name.casefold() == "host":
                        headers[name] = target_host
                        break
        if not isinstance(request.get("url"), str) or not request["url"]:
            raise ValueError("A request URL or target_url is required")
        input_files[REQUEST_FILE] = build_raw_request(request)
        command_args.extend(["--request-file", REQUEST_FILE])
    elif isinstance(target_url, str) and target_url:
        command_args.extend(["--url", target_url])
    else:
        raise ValueError("A captured request or target_url is required")

    timeout = (
        SQLMAP_EXTRACT_TIMEOUT_SECONDS if action == "extract"
        else SQLMAP_CONTAINER_TIMEOUT_SECONDS
    )

    if action == "extract" and arguments.get("skip_dump", False):
        command_args.append("--skip-dump")

    result = await docker_runner.execute_tool(
        image=IMAGE,
        command=shlex.join(command_args),
        timeout=timeout,
        input_files=input_files,
    )

    if result.get("status") != "SUCCESS":
        runner_output = result.get("output")
        diagnostics = (
            _sanitize_diagnostics(runner_output)
            if isinstance(runner_output, str) else []
        )
        return _persist_report(
            {
                "error": "SQLMap container failed",
                "status": result.get("status", "UNKNOWN"),
                "diagnostics": diagnostics,
            },
            arguments,
        )

    parsed_report = _extract_report(result)
    if parsed_report is None:
        return _persist_report(
            {"error": "SQLMap report was missing or invalid"}, arguments
        )

    if action == "extract":
        _set_dump_evidence(parsed_report, _table_evidence(parsed_report), "current")

    _strip_urls(parsed_report)
    return _persist_report(parsed_report, arguments)