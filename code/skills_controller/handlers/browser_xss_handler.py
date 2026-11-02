import json
import shlex
from urllib.parse import urlsplit


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            return None
        return (
            parts.scheme,
            parts.hostname.casefold(),
            parts.port or (443 if parts.scheme == "https" else 80),
        )
    except ValueError:
        return None


def _valid_plan(target_url: str, plan: object) -> bool:
    if not isinstance(plan, dict) or _origin(target_url) is None:
        return False
    mode = plan.get("mode")
    if mode not in {"reflected_dom", "stored_dom"}:
        return False
    if not isinstance(plan.get("source_url"), str):
        return False
    if _origin(plan["source_url"]) != _origin(target_url):
        return False
    request = plan.get("request")
    if not isinstance(request, dict):
        return False
    request_path = request.get("path")
    if (
        not isinstance(request_path, str)
        or not request_path.startswith("/")
        or request_path.startswith("//")
        or "\\" in request_path
    ):
        return False
    expected_method = "GET" if mode == "reflected_dom" else "POST"
    if str(request.get("method") or "").upper() != expected_method:
        return False
    if mode == "reflected_dom":
        return (
            bool(plan.get("parameter"))
            and isinstance(plan.get("input_selector"), str)
        )

    cleanup = plan.get("cleanup")
    return (
        bool(plan.get("parameter"))
        and bool(plan.get("form_selector"))
        and isinstance(plan.get("form_fields"), list)
        and "{id}" in str(plan.get("verification_url_template") or "")
        and "{marker}" in str(plan.get("verification_url_template") or "")
        and isinstance(cleanup, dict)
        and str(cleanup.get("method") or "").upper() == "DELETE"
        and "{id}" in str(cleanup.get("path_template") or "")
        and str(cleanup.get("path_template") or "").startswith("/")
    )


def handle_browser_xss_args(arguments: dict) -> tuple[dict, dict[str, str]]:
    args = dict(arguments)
    target_url = str(args.get("target_url") or "")
    plan = args.get("plan")
    if not _valid_plan(target_url, plan):
        args["skip_execution"] = True
        args["reason"] = (
            "El plan XSS debe ser observado, pertenecer al mismo origen y definir "
            "limpieza para las pruebas almacenadas."
        )
        return args, {}

    args["target_arg"] = shlex.join(
        [
            "--target-url",
            target_url,
            "--plan-json",
            json.dumps(plan, ensure_ascii=False, separators=(",", ":")),
        ]
    )
    return args, {}
