import logging
import shlex
from typing import Any, Dict, Tuple
from ._common import is_static_asset

logger = logging.getLogger("crypto_inspector_handler")


def handle_crypto_inspector_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Adaptador (handler) para Crypto Inspector.
    Devuelve (args_actualizados, input_files).
    """
    logger.info("[CRYPTO INSPECTOR HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        target_url = args.get("target_url", "")
        jwt_token = args.get("jwt_token", "")

        if not target_url and not jwt_token:
            args["skip_execution"] = True
            args["reason"] = "Se requiere al menos 'target_url' o 'jwt_token' para Crypto Inspector."
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

        args["args"] = " ".join(cli_flags)
        logger.info("[CRYPTO INSPECTOR HANDLER] Comando generado: %s", args["args"])
        return args, input_files

    except Exception as e:
        logger.exception("[CRYPTO INSPECTOR HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en crypto_inspector_handler: {e}"
        return args, input_files