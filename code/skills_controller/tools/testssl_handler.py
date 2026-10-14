import logging
import shlex
from typing import Any, Dict, Tuple
from tools._common import is_static_asset

logger = logging.getLogger("testssl_handler")

def handle_testssl_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Adaptador para testssl.sh.
    Devuelve (args_actualizados, input_files).
    
    Genera banderas en modo no interactivo (--quiet, --color 0) y emite 
    el reporte en JSON plano para fácil análisis por parte del agente.
    """
    logger.info("[TESTSSL HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        target_url = args.get("target_url", "")
        fast_mode = args.get("fast_mode", True)

        if not target_url:
            args["skip_execution"] = True
            args["reason"] = "Sin URL o host objetivo."
            return args, input_files

        if is_static_asset(target_url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {target_url}"
            return args, input_files

        # Construcción de las banderas CLI
        cli_flags = ["--quiet", "--color", "0", "--jsonfile-inline"]
        
        if fast_mode:
            cli_flags.append("--fast")

        cli_flags.append(shlex.quote(target_url))
        
        args["args"] = " ".join(cli_flags)
        logger.info("[TESTSSL HANDLER] Comando generado para: %s", target_url)
        return args, input_files

    except Exception as e:
        logger.exception("[TESTSSL HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en testssl_handler: {e}"
        return args, input_files