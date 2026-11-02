import logging
import shlex
from typing import Any, Dict, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger("access_control_handler")


def _as_relative_endpoint(endpoint: str) -> str:
    """El prober concatena base_url + endpoint; evita URLs absolutas duplicadas."""
    value = str(endpoint or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    return value


def prepare_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    logger.info("[ACCESS CONTROL HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        base_url = str(args.get("base_url", "") or "").strip().rstrip("/")
        endpoint = _as_relative_endpoint(args.get("endpoint", ""))
        victim_id = str(args.get("victim_id", "") or "").strip()
        token_victim = str(args.get("token_victim", "") or "").strip()
        token_attacker = str(args.get("token_attacker", "") or "").strip()
        email_target = str(args.get("email_target", "") or "").strip()

        if not all([base_url, endpoint, victim_id, token_attacker]):
            args["skip_execution"] = True
            args["reason"] = (
                "Faltan parámetros requeridos (base_url, endpoint, victim_id o token_attacker)."
            )
            return args, input_files

        cli_flags = [
            "--base-url", shlex.quote(base_url),
            "--endpoint", shlex.quote(endpoint),
            "--victim-id", shlex.quote(victim_id),
            "--token-attacker", shlex.quote(token_attacker),
        ]

        if token_victim:
            cli_flags.extend(["--token-victim", shlex.quote(token_victim)])

        if email_target:
            cli_flags.extend(["--email-target", shlex.quote(email_target)])

        args["args"] = " ".join(cli_flags)
        logger.info("[ACCESS CONTROL HANDLER] Comando generado: %s", args["args"])
        return args, input_files
    except Exception as e:
        logger.exception("[ACCESS CONTROL HANDLER] Error: %s", e)
        args["skip_execution"] = True
        args["reason"] = str(e)
        return args, input_files