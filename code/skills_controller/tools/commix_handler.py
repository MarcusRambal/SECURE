"""
Adaptador (handler) para Commix.

Soporta dos modos:
1. Modo archivo (`.req`) — para peticiones POST, JSON, multipart o con cookies.
   Preserva el body exacto y todos los headers. Commix inyecta en cada parámetro.
2. Modo URL con `*` — para GET con query params simples.
   Inserta el marcador `*` en el parámetro más sospechoso.
"""

import json
import logging
import shlex
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from tools._common import is_static_asset
from tools.sqlmap_handler import build_raw_request  # reutilizamos serializador HTTP

logger = logging.getLogger("commix_handler")


# Palabras clave que sugieren un parámetro candidato a Command Injection.
OS_CMD_HINTS = {
    "ip", "host", "hostname", "domain", "url", "target", "addr",
    "cmd", "exec", "command", "run", "shell", "ping", "lookup",
    "file", "filename", "path", "dir", "directory", "daemon", "process",
}


def _pick_target_param(param_names: list[str]) -> Optional[str]:
    """Devuelve el parámetro más probable a ser vulnerable."""
    if not param_names:
        return None
    for name in param_names:
        if name.lower() in OS_CMD_HINTS:
            return name
    return param_names[0]


def _inject_in_query(url: str) -> Optional[str]:
    """Inserta `*` en el parámetro sospechoso de la query string."""
    parsed = urlsplit(url)
    if not parsed.query:
        return None

    params = parse_qs(parsed.query, keep_blank_values=True)
    target = _pick_target_param(list(params.keys()))
    if not target:
        return None

    pairs = []
    for name, values in params.items():
        value = values[0] if values else ""
        if name == target:
            pairs.append((name, f"{value}*"))
        else:
            pairs.append((name, value))

    new_query = urlencode(pairs, safe="*")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def _should_use_file_mode(request: dict, url: str) -> bool:
    """
    Usa modo archivo cuando:
    - El método no es GET, o
    - El body es no vacío, o
    - Hay cookies (para preservarlas sin flag extra).
    """
    method = (request.get("method") or "GET").upper()
    body = request.get("body") or ""
    headers = request.get("headers") or {}
    has_cookie = any(name.lower() == "cookie" for name in headers.keys())

    if method != "GET":
        return True
    if body:
        return True
    if has_cookie:
        return True
    return False


def handle_commix_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Punto de entrada del adaptador. Devuelve (args_actualizados, archivos_a_inyectar).
    Los argumentos esperados por el template son: `{target_arg}` y `{extra_flags}`.
    """
    logger.info("[COMMIX HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["target_arg"] = ""
    args["extra_flags"] = ""

    try:
        request = args.get("request") or {}
        target_url = args.get("target_url", "")

        url = request.get("url") or target_url
        method = (request.get("method") or "GET").upper()

        if not url:
            args["skip_execution"] = True
            args["reason"] = "Sin URL objetivo."
            return args, input_files

        if is_static_asset(url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {url}"
            logger.info("[COMMIX HANDLER] Skip por recurso estático: %s", url)
            return args, input_files

        # --- Modo archivo: POST, body, cookies, o cualquier request estructurada ---
        if request and _should_use_file_mode(request, url):
            file_path = "/tmp/commix-req.txt"
            raw_request = build_raw_request(request)
            input_files[file_path] = raw_request
            args["target_arg"] = f'-r "{file_path}"'
            # Commix inyecta automáticamente en todos los parámetros del .req.
            # Si hay múltiples, podríamos especificar -p, pero por defecto los prueba todos.
            logger.info("[COMMIX HANDLER] Modo archivo (.req): %s", url)
            return args, input_files

        # --- Modo URL: GET simple con query params ---
        if method == "GET":
            new_url = _inject_in_query(url)
            if not new_url:
                args["skip_execution"] = True
                args["reason"] = "La URL no tiene parámetros en la query string inyectables."
                logger.info("[COMMIX HANDLER] Skip por query sin parámetros: %s", url)
                return args, input_files
            args["target_arg"] = f'--url={shlex.quote(new_url)}'
            logger.info("[COMMIX HANDLER] Modo URL con *: %s", new_url)
            return args, input_files

        # Si llegamos aquí, no hay caso aplicable.
        args["skip_execution"] = True
        args["reason"] = f"Caso no soportado: method={method}, body={'sí' if request.get('body') else 'no'}."
        return args, input_files

    except Exception as e:
        logger.exception("[COMMIX HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en commix_handler: {e}"
        return args, input_files