
import asyncio
import json
import logging
import requests
from pathlib import Path

from tools.sqli_skill.sqli_manual import run_detection_assessment
from handlers.report_writer import save_skill_report

logger = logging.getLogger(__name__)
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "tools" / "sqli_skill" / "outputs"


def _persist_report(report: dict, arguments: dict) -> None:
    try:
        output_path = save_skill_report(
            OUTPUT_DIR,
            "sqli_skill",
            report,
            arguments.get("target_url"),
            arguments.get("param"),
        )
    except OSError as error:
        logger.exception("Could not save the sqli_skill JSON report")
        report["persistence_error"] = f"Report save failed ({type(error).__name__})"
    else:
        logger.info("Saved sqli_skill report to %s", output_path)
        report["saved_report"] = str(output_path)


async def execute_sqli_manual(arguments: dict) -> str:
    try:
        report = await asyncio.to_thread(
            run_detection_assessment,
            arguments["target_url"],
            arguments["param"],
            arguments.get("method", "GET"),
            arguments.get("headers"),
            arguments.get("body"),
            arguments.get("location", "query"),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid SQLi assessment arguments: {type(error).__name__}") from error
    except requests.RequestException as error:
        logger.error(
            "SQLi assessment request failed for parameter %s (%s)",
            arguments.get("param", "[unknown]"),
            type(error).__name__,
        )
        report = {
            "parameter": arguments.get("param"),
            "location": arguments.get("location", "query"),
            "error": f"HTTP request failed ({type(error).__name__})",
        }
        _persist_report(report, arguments)
        return json.dumps(report, ensure_ascii=False)
    _persist_report(report, arguments)
    return json.dumps(report, ensure_ascii=False)