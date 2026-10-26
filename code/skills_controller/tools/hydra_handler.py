import logging
import shlex
from typing import Any, Dict, Tuple
from handlers._common import is_static_asset

logger = logging.getLogger("hydra_handler")

def prepare_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Adaptador para THC-Hydra.
    Devuelve (args_actualizados, input_files).
    
    Configura de forma segura las pruebas sobre endpoints de autenticación.
    """
    logger.info("[HYDRA HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        target = args.get("target", "")
        form_path = args.get("form_path", "")
        method = args.get("method", "http-post-form").lower()
        user_list = args.get("user_list", "/wordlists/users_small.txt")
        pass_list = args.get("pass_list", "/wordlists/pass_small.txt")

        if not target or not form_path:
            args["skip_execution"] = True
            args["reason"] = "Se requiere tanto el 'target' como el 'form_path' para ejecutar Hydra."
            return args, input_files

        if is_static_asset(target):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {target}"
            return args, input_files

        # Construcción de argumentos seguros para la CLI de Hydra
        cli_flags = [
            "-L", shlex.quote(user_list),
            "-P", shlex.quote(pass_list),
            "-t", "4",               # Limitar hilos para prevenir sobrecarga
            "-V",                    # Salida detallada
            shlex.quote(target),
            shlex.quote(method),
            f'"{form_path}"'
        ]

        args["args"] = " ".join(cli_flags)
        logger.info("[HYDRA HANDLER] Comando generado para target %s en %s", target, form_path)
        return args, input_files

    except Exception as e:
        logger.exception("[HYDRA HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en hydra_handler: {e}"
        return args, input_files