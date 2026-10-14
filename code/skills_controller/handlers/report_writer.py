import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _sanitize_target(target_url: object) -> str | None:
    if not isinstance(target_url, str) or not target_url:
        return None
    try:
        parts = urlsplit(target_url)
        query = urlencode(
            [(name, "[REDACTED]") for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
        )
    except ValueError:
        return "[invalid-url]"

    return urlunsplit(
        (parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, query, "")
    )


def save_skill_report(output_dir: Path,skill_name: str,report: dict,target_url: object,parameter: object,) -> Path:
    safe_target = _sanitize_target(target_url)
    safe_report = dict(report)
    if "target" in safe_report:
        safe_report["target"] = safe_target

    created_at = datetime.now(timezone.utc)
    timestamp = created_at.strftime("%Y%m%dT%H%M%S%fZ")
    payload = {
        "created_at": created_at.isoformat(),
        "skill": skill_name,
        "target_url": safe_target,
        "parameter": parameter if isinstance(parameter, str) else None,
        "report": safe_report,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{timestamp}_{uuid.uuid4().hex}.json"
    with output_path.open("x", encoding="utf-8") as output_file:
        json.dump(payload, output_file, ensure_ascii=False, indent=2)
        output_file.write("\n")
    return output_path
