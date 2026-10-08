"""
Adaptador (handler) para Dalfox.

Transforma la salida del SPA Crawler (una petición HTTP estructurada)
en los argumentos que Dalfox necesita.

Reglas:
- Dalfox SOLO funciona con URLs que tengan parámetros en la query string.
  Si la URL no tiene query o no tiene "=", se marca skip_execution.
- Si la app requiere autenticación, se pasa la cookie con --cookies.
- Se descartan recursos estáticos (.js, .css, imágenes, etc.).
- A diferencia de Commix, Dalfox NO necesita insertar un marcador '*'.
  Trabaja con la URL tal cual, probando payloads en cada parámetro.
"""

import logging
import shlex
from typing import Any, Dict, Tuple
from urllib.parse import urlsplit

from tools._common import is_static_asset

logger = logging.getLogger("dalfox_handler")


def handle_dalfox_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Punto de entrada del adaptador. Recibe el diccionario de argumentos
    que el SkillsMCPServer le pasa desde el agente Validate.
    """
    logger.info("[DALFOX HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
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
            logger.info("[DALFOX HANDLER] Skip: sin URL.")
            return args, input_files

        if is_static_asset(url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {url}"
            logger.info("[DALFOX HANDLER] Skip por recurso estático: %s", url)
            return args, input_files

        # Dalfox solo escanea URLs con query params
        parsed = urlsplit(url)
        if not parsed.query or "=" not in parsed.query:
            args["skip_execution"] = True
            args["reason"] = (
                "Dalfox requiere una URL con parámetros en la query string "
                "(ej: ?q=test). La URL no cumple ese requisito."
            )
            logger.info("[DALFOX HANDLER] Skip por falta de parámetros: %s", url)
            return args, input_files

        # Dalfox solo maneja GET. Si es POST, se salta.
        if method != "GET":
            args["skip_execution"] = True
            args["reason"] = (
                f"Dalfox no soporta peticiones {method}. Solo escanea parámetros GET."
            )
            logger.info("[DALFOX HANDLER] Skip por método no soportado: %s", method)
            return args, input_files

        # Construir flags extra: cookie + headers custom si aplica
        extra_flags = []

        cookie_value = None
        for name, value in headers.items():
            if name.lower() == "cookie":
                cookie_value = value
                break

        if cookie_value:
            extra_flags.append(f"--cookies={shlex.quote(cookie_value)}")

        args["target_url"] = url
        args["extra_flags"] = " ".join(extra_flags)
        logger.info("[DALFOX HANDLER] Output: %s", args)
        return args, input_files

    except Exception as e:
        logger.exception("[DALFOX HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en dalfox_handler: {e}"
        return args, input_files