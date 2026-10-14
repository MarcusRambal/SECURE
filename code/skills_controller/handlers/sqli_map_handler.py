import json
import logging
import shlex
from pathlib import Path

from docker_runner import docker_runner
from handlers.sqlmap_handler import build_raw_request
from handlers.report_writer import save_skill_report


IMAGE = "local-sqli-map:latest"
REQUEST_FILE = "/tmp/sqli-map-request.txt"
REPORT_MARKER = "SQLI_MAP_REPORT="
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "tools" / "sqli_map" / "outputs"
logger = logging.getLogger(__name__)


def _persist_report(report: dict, arguments: dict) -> str:
    try:
        output_path = save_skill_report(
            OUTPUT_DIR,
            "sqli_map",
            report,
            arguments.get("target_url"),
            arguments.get("param"),
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

    target_url = arguments.get("target_url")
    request = arguments.get("request")
    input_files = {}
    command_args = ["--action", "detect", "--param", parameter]

    if isinstance(request, dict):
        request = dict(request)
        if isinstance(target_url, str) and target_url:
            request["url"] = target_url
        if not isinstance(request.get("url"), str) or not request["url"]:
            raise ValueError("A request URL or target_url is required")
        input_files[REQUEST_FILE] = build_raw_request(request)
        command_args.extend(["--request-file", REQUEST_FILE])
    elif isinstance(target_url, str) and target_url:
        command_args.extend(["--url", target_url])
    else:
        raise ValueError("A captured request or target_url is required")

    result = await docker_runner.execute_tool(
        image=IMAGE,
        command=shlex.join(command_args),
        timeout=3600,
        input_files=input_files,
    )
    if result.get("status") != "SUCCESS":
        return _persist_report(
            {
                "error": "SQLMap detection container failed",
                "status": result.get("status", "UNKNOWN"),
            },
            arguments,
        )

    for line in result.get("output", "").splitlines():
        if not line.startswith(REPORT_MARKER):
            continue
        try:
            report = json.loads(line[len(REPORT_MARKER):])
        except json.JSONDecodeError:
            break
        if not isinstance(report, dict):
            break
        report.pop("url", None)
        result_report = report.get("result")
        if isinstance(result_report, dict):
            result_report.pop("url", None)
        return _persist_report(report, arguments)

    return _persist_report(
        {"error": "SQLMap report was missing or invalid"},
        arguments,
    )
