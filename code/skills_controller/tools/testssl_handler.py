import logging
import shlex
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

# Importación correcta de utilidades comunes desde el mismo paquete
from ._common import is_static_asset

logger = logging.getLogger("testssl_handler")


def handle_testssl_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Adaptador para testssl.sh.
    Devuelve (args_actualizados, input_files).

    Puntos clave:
    1. Limpia el protocolo (http:// o https://) del target_url.
    2. Usa '--warnings batch' para evitar bloqueos interactivos.
    3. Retorna la salida en JSON mediante '--jsonfile-inline' para persistencia en PostgreSQL.
    """
    logger.info("[TESTSSL HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["args"] = ""

    try:
        raw_target = args.get("target_url") or args.get("target") or ""

        if not raw_target:
            args["skip_execution"] = True
            args["reason"] = "Sin URL o host objetivo."
            return args, input_files

        if is_static_asset(raw_target):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {raw_target}"
            return args, input_files

        # --- 1. LIMPIEZA DE PROTOCOLO ---
        clean_target = raw_target
        if "://" in raw_target:
            parsed = urlparse(raw_target)
            clean_target = parsed.netloc or parsed.path

        # --- 2. BANDERAS DE EJECUCIÓN NO INTERACTIVA Y FORMATO ---
        cli_flags = [
            "--quiet",              # Omite el banner inicial
            "--color", "0",         # Desactiva colores ANSI para un JSON limpio
            "--warnings", "batch",  # Evita bloqueos en prompts interactivos ("yes/no")
            "--jsonfile-inline"     # Emite el reporte JSON directo en stdout
        ]

        # Modo rápido opcional si el agente lo solicita
        if args.get("fast_mode", False):
            cli_flags.append("--fast")

        cli_flags.append(shlex.quote(clean_target))

        args["args"] = " ".join(cli_flags)
        logger.info("[TESTSSL HANDLER] Comando generado para host limpio: %s", clean_target)
        return args, input_files

    except Exception as e:
        logger.exception("[TESTSSL HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en testssl_handler: {e}"
        return args, input_files


# Alias opcional por compatibilidad con el estándar prepare_args
prepare_args = handle_testssl_args