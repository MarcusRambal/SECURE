import logging
import shlex
from typing import Any, Dict, Tuple
from tools._common import is_static_asset

logger = logging.getLogger("ffuf_handler")

def handle_ffuf_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Adaptador para FFuF.
    Soporta fuzzing de rutas GET y fuzzing de datos/JSON en peticiones POST.
    """
    logger.info("[FFUF HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        target_url = args.get("target_url", "")
        method = (args.get("method") or "GET").upper()
        post_data = args.get("data") or ""
        wordlist = args.get("wordlist", "/wordlists/common.txt")
        headers = args.get("headers") or {}

        if not target_url:
            args["skip_execution"] = True
            args["reason"] = "Sin URL objetivo para FFuF."
            return args, input_files

        if is_static_asset(target_url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {target_url}"
            return args, input_files

        # Banderas base
        cli_flags = [
            "-u", shlex.quote(target_url),
            "-w", shlex.quote(wordlist),
            "-s"  # Modo silencioso
        ]

        # Método HTTP
        if method != "GET":
            cli_flags.extend(["-X", method])

        # Manejo de Headers (ej: Content-Type: application/json)
        for h_name, h_val in headers.items():
            cli_flags.extend(["-H", shlex.quote(f"{h_name}: {h_val}")])

        # Manejo de payload POST/JSON
        if post_data:
            cli_flags.extend(["-d", shlex.quote(post_data)])

        args["args"] = " ".join(cli_flags)
        logger.info("[FFUF HANDLER] Comando generado para %s", target_url)
        return args, input_files

    except Exception as e:
        logger.exception("[FFUF HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en ffuf_handler: {e}"
        return args, input_files