import asyncio
import hashlib
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
# Host-side dedup state: hashes of targets for which extract already dumped.
DUMP_STATE_FILE = OUTPUT_DIR / ".dump_state.json"
SQLMAP_CONTAINER_TIMEOUT_SECONDS = 1800
SQLMAP_EXTRACT_TIMEOUT_SECONDS = 3600

logger = logging.getLogger(__name__)
# One lock per target so concurrent extract calls never double-dump.
_extract_locks: dict[str, asyncio.Lock] = {}


def _target_key(target_url, request) -> Optional[str]:
    """Stable hash of scheme://host/path (query stripped, since it's the injection point)."""
    raw = target_url if isinstance(target_url, str) and target_url else None
    if not raw and isinstance(request, dict):
        candidate = request.get("url")
        if isinstance(candidate, str) and candidate:
            raw = candidate
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            return None
        base = urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path, "", "")
        )
        return hashlib.sha256(base.encode("utf-8")).hexdigest()
    except ValueError:
        return None


def _load_dump_state() -> dict[str, dict]:
    try:
        state_text = DUMP_STATE_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as error:
        logger.exception("Could not read sqli_map dump state")
        raise RuntimeError("Could not read sqli_map dump state") from error

    try:
        data = json.loads(state_text)
    except json.JSONDecodeError as error:
        logger.error("The sqli_map dump state is not valid JSON")
        raise RuntimeError("The sqli_map dump state is invalid") from error

    if isinstance(data, list):
        return {
            key: {"tables": [], "needs_refresh": True}
            for key in data
            if isinstance(key, str)
        }
    if (
        isinstance(data, dict)
        and data.get("version") == 1
        and isinstance(data.get("targets"), dict)
    ):
        return {
            key: entry
            for key, entry in data["targets"].items()
            if isinstance(key, str) and isinstance(entry, dict)
        }

    logger.error("The sqli_map dump state has an unsupported format")
    raise RuntimeError("The sqli_map dump state has an unsupported format")


def _save_dump_state(state: dict[str, dict]) -> None:
    try:
        DUMP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DUMP_STATE_FILE.with_suffix(".tmp")
        payload = {"version": 1, "targets": state}
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(DUMP_STATE_FILE)
    except OSError as error:
        logger.exception("Could not persist sqli_map dump state")
        raise RuntimeError("Could not persist sqli_map dump state") from error


def _sanitize_table_evidence(tables: object) -> list[dict]:
    if not isinstance(tables, list):
        return []

    sanitized = []
    for table in tables:
        if not isinstance(table, dict) or not isinstance(table.get("table"), str):
            continue
        columns = table.get("columns")
        columns = sorted({
            column for column in columns
            if isinstance(column, str)
        }) if isinstance(columns, list) else []
        preview = table.get("preview")
        sanitized_preview = []
        if isinstance(preview, list):
            for row in preview[:3]:
                if not isinstance(row, list):
                    continue
                sanitized_preview.append([
                    _stringify_dump_value(value) for value in row[:100]
                ])
        row_count = table.get("row_count")
        sanitized.append({
            "database": table.get("database") if isinstance(table.get("database"), str) else None,
            "table": table["table"],
            "row_count": row_count if isinstance(row_count, int) and not isinstance(row_count, bool) and row_count >= 0 else 0,
            "truncated": table.get("truncated") is True,
            "columns": columns,
            "preview": sanitized_preview,
            "status": table.get("status") if table.get("status") in {"error", "retrieved", "empty"} else "retrieved",
            "values_redacted": table.get("values_redacted") is True,
        })
    return sanitized


def _stringify_dump_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))[:250]
    return str(value)[:250]


def _dump_state_entry(key: Optional[str]) -> Optional[dict]:
    entry = _load_dump_state().get(key) if key else None
    if entry is None:
        return None
    if entry.get("needs_refresh") is True:
        return None
    tables = _sanitize_table_evidence(entry.get("tables"))
    if not tables:
        return None
    if any(
        table.get("row_count", 0) > 0 and table.get("values_redacted") is True
        for table in tables
    ):
        return None
    return {"tables": tables}


def _mark_dumped(key: Optional[str], tables: list[dict]) -> None:
    if not key:
        return
    state = _load_dump_state()
    state[key] = {"tables": _sanitize_table_evidence(tables)}
    _save_dump_state(state)


def _extract_lock_for(key: str) -> asyncio.Lock:
    lock = _extract_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _extract_locks[key] = lock
    return lock


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
                for row in rows[:3]
                if isinstance(row, dict)
            ],
            "status": "error" if dump.get("error") else ("retrieved" if row_count else "empty"),
            "values_redacted": False,
        }
        evidence.append(item)
    return evidence


def _completed_dump(report: Optional[dict]) -> bool:
    if not isinstance(report, dict) or report.get("status") not in {"completed", "empty_dumps"}:
        return False
    dumps = report.get("dumps")
    return (
        isinstance(dumps, list)
        and bool(dumps)
        and all(isinstance(dump, dict) and not dump.get("error") for dump in dumps)
    )


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

    # ---- Dedup logic -------------------------------------------------------
    dedup_key = _target_key(target_url, request if isinstance(request, dict) else None)
    force_dump = bool(arguments.get("force_dump", False))
    skip_dump = bool(arguments.get("skip_dump", False))
    cached_evidence = []
    cached_dump = False
    timeout = (
        SQLMAP_EXTRACT_TIMEOUT_SECONDS if action == "extract"
        else SQLMAP_CONTAINER_TIMEOUT_SECONDS
    )

    if action == "extract" and not force_dump and not skip_dump:
        state_entry = _dump_state_entry(dedup_key)
        if state_entry is not None:
            logger.info("sqli_map extract: skipping dump (already dumped for target)")
            skip_dump = True
            cached_dump = True
            cached_evidence = state_entry.get("tables", [])

    if action == "extract" and skip_dump:
        command_args.append("--skip-dump")

    if action == "extract" and not force_dump and dedup_key and not skip_dump:
        # Serialize concurrent extract calls for the same target. Inside the
        # lock we re-check the state so a coroutine that finished dumping
        # while we waited forces us into detection-only mode.
        async with _extract_lock_for(dedup_key):
            state_entry = _dump_state_entry(dedup_key)
            if state_entry is not None:
                logger.info("sqli_map extract: skipping dump (concurrent mark)")
                skip_dump = True
                cached_dump = True
                cached_evidence = state_entry.get("tables", [])
                command_args.append("--skip-dump")
            result = await docker_runner.execute_tool(
                image=IMAGE,
                command=shlex.join(command_args),
                timeout=timeout,
                input_files=input_files,
            )
            if not skip_dump and result.get("status") == "SUCCESS":
                parsed = _extract_report(result)
                if _completed_dump(parsed):
                    _mark_dumped(dedup_key, _table_evidence(parsed))
    else:
        result = await docker_runner.execute_tool(
            image=IMAGE,
            command=shlex.join(command_args),
            timeout=timeout,
            input_files=input_files,
        )
    # -----------------------------------------------------------------------

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
        tables = cached_evidence if cached_dump else _table_evidence(parsed_report)
        _set_dump_evidence(
            parsed_report,
            tables,
            "cached" if cached_dump else "current",
        )

    _strip_urls(parsed_report)
    return _persist_report(parsed_report, arguments)