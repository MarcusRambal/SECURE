import logging
import shlex
import json
from typing import Any, Dict, Tuple
from handlers._common import is_static_asset

logger = logging.getLogger("crypto_inspector_handler")


def prepare_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    logger.info("[CRYPTO INSPECTOR HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        target_url = args.get("target_url", "")
        jwt_token = args.get("jwt_token", "")
        auth_header = args.get("auth_header", "")
        targets = args.get("targets", [])

        if not target_url and not jwt_token:
            args["skip_execution"] = True
            args["reason"] = "Se requiere al menos 'target_url' o 'jwt_token'."
            return args, input_files

        cli_flags = []

        if target_url:
            if is_static_asset(target_url):
                args["skip_execution"] = True
                args["reason"] = f"Recurso estático descartado: {target_url}"
                return args, input_files
            cli_flags.extend(["--url", shlex.quote(target_url)])

        if jwt_token:
            cli_flags.extend(["--jwt", shlex.quote(jwt_token)])

        if auth_header:
            cli_flags.extend(["--auth-header", shlex.quote(auth_header)])

        # SOLUCIÓN: Guardar los targets en un archivo temporal
        if targets:
            targets_json = json.dumps(targets)
            input_files["/tmp/targets.json"] = targets_json
            cli_flags.extend(["--targets-file", "/tmp/targets.json"])

        args["args"] = " ".join(cli_flags)
        logger.info("[CRYPTO INSPECTOR HANDLER] Comando generado: %s", args["args"])
        return args, input_files

    except Exception as e:
        logger.exception("[CRYPTO INSPECTOR HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno: {e}"
        return args, input_files