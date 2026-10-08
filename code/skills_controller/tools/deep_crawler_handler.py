import json


def handle_deep_crawler_args(arguments: dict) -> tuple[dict, dict[str, str]]:
    """Entrega el informe previo solo dentro del contenedor efimero."""
    crawler_report = arguments.pop("crawler_report", None)
    if not isinstance(crawler_report, dict):
        raise ValueError("deep_crawler requiere el resultado JSON de crawler.")
    arguments["crawler_report_path"] = "/tmp/crawler_report.json"
    return arguments, {"/tmp/crawler_report.json": json.dumps(crawler_report)}