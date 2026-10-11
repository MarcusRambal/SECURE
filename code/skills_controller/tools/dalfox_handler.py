"""
Adaptador (handler) para Dalfox.

Soporta dos modos:
1. Modo URL (`scan`) — para GET con query params. Dalfox prueba payloads en cada
   parámetro sin marcadores manuales.
2. Modo archivo (`file`) — para POST o peticiones con body. Preserva el método,
   headers, body y cookies completos.

En ambos casos se descartan recursos estáticos y URLs sin parámetros inyectables.
"""

import logging
import shlex
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from tools._common import is_static_asset
from tools.sqlmap_handler import build_raw_request

logger = logging.getLogger("dalfox_handler")


def _extract_cookie(headers: dict) -> Optional[str]:
    """Extrae el header Cookie si existe."""
    for name, value in headers.items():
        if name.lower() == "cookie":
            return value
    return None


def _should_use_file_mode(request: dict) -> bool:
    """Usa modo archivo cuando el método no es GET o hay body."""
    method = (request.get("method") or "GET").upper()
    body = request.get("body") or ""
    if method != "GET":
        return True
    if body:
        return True
    return False


def _has_query_params(url: str) -> bool:
    """Dalfox requiere al menos un parámetro con `=` en la query string."""
    parsed = urlsplit(url)
    return bool(parsed.query and "=" in parsed.query)


def handle_dalfox_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Punto de entrada del adaptador. Devuelve (args_actualizados, archivos_a_inyectar).
    Los argumentos esperados por el template son: `{target_arg}` y `{extra_flags}`.
    """
    logger.info("[DALFOX HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["target_arg"] = ""
    args["extra_flags"] = ""

    try:
        request = args.get("request") or {}
        target_url = args.get("target_url", "")

        url = request.get("url") or target_url
        method = (request.get("method") or "GET").upper()
        headers = request.get("headers") or {}

        if not url:
            args["skip_execution"] = True
            args["reason"] = "Sin URL objetivo."
            return args, input_files

        if is_static_asset(url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {url}"
            logger.info("[DALFOX HANDLER] Skip por recurso estático: %s", url)
            return args, input_files

        # --- Modo archivo: POST, body, o métodos no-GET ---
        if request and _should_use_file_mode(request):
            file_path = "/tmp/dalfox-req.txt"
            input_files[file_path] = build_raw_request(request)
            args["target_arg"] = f'file "{file_path}"'
            logger.info("[DALFOX HANDLER] Modo archivo (.req): %s", url)
            return args, input_files

        # --- Modo URL: GET con query params ---
        if not _has_query_params(url):
            args["skip_execution"] = True
            args["reason"] = (
                "Dalfox requiere una URL con parámetros en la query string "
                "(ej: ?q=test). La URL no cumple ese requisito."
            )
            logger.info("[DALFOX HANDLER] Skip por falta de parámetros: %s", url)
            return args, input_files

        extra_flags = []
        cookie_value = _extract_cookie(headers)
        if cookie_value:
            extra_flags.append(f'--cookies "{cookie_value}"')

        args["target_arg"] = f'scan "{url}"'
        args["extra_flags"] = " ".join(extra_flags)
        logger.info("[DALFOX HANDLER] Modo URL: %s", url)
        return args, input_files

    except Exception as e:
        logger.exception("[DALFOX HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en dalfox_handler: {e}"
        return args, input_files