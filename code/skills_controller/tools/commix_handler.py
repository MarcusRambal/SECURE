"""
Adaptador (handler) para Commix.

Transforma la salida del SPA Crawler (una petición HTTP estructurada)
en los argumentos que Commix necesita para ejecutarse.

Reglas:
- GET con query params: inserta un `*` en el parámetro sospechoso.
- POST con body (JSON o form-urlencoded): inserta un `*` en el valor
  del parámetro sospechoso dentro del body.
- Preserva cookies y headers relevantes de la petición original.
- Si la petición no tiene parámetros inyectables, devuelve skip_execution.
"""

import json
import logging
import shlex
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from tools._common import is_static_asset

logger = logging.getLogger("commix_handler")


# Palabras clave que sugieren un parámetro candidato a Command Injection.
OS_CMD_HINTS = {
    "ip", "host", "hostname", "domain", "url", "target", "addr",
    "cmd", "exec", "command", "run", "shell", "ping", "lookup",
    "file", "filename", "path", "dir", "directory", "daemon", "process",
}

# Headers que NO se deben reenviar a Commix (los gestiona Docker/HTTP).
HEADERS_TO_SKIP = {"host", "content-length", "connection", "accept-encoding", "content-type"}


def _pick_target_param(param_names: list[str]) -> Optional[str]:
    """
    Devuelve el parámetro con mayor probabilidad de ser vulnerable.
    Prioriza nombres que coinciden con OS_CMD_HINTS.
    Si no hay coincidencia, devuelve el primero. Si la lista está vacía, None.
    """
    if not param_names:
        return None
    for name in param_names:
        if name.lower() in OS_CMD_HINTS:
            return name
    return param_names[0]


def _build_extra_flags(headers: dict) -> tuple[list[str], Optional[str]]:
    """
    Construye flags adicionales a partir de los headers originales.
    Devuelve (lista_de_flags, cookie_valor).
    """
    flags: list[str] = []
    cookie: Optional[str] = None
    forward_headers: list[str] = []

    for name, value in headers.items():
        lower = name.lower()
        if lower == "cookie":
            cookie = value
        elif lower not in HEADERS_TO_SKIP:
            forward_headers.append(f"{name}: {value}")

    if forward_headers:
        # Commix acepta múltiples headers separados por \\n reales.
        joined = "\n".join(forward_headers)
        flags.append(f"--headers={shlex.quote(joined)}")

    return flags, cookie


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


def _inject_in_body(body: str, content_type: str) -> Optional[str]:
    """Inserta `*` en el parámetro sospechoso del body. Devuelve el nuevo body o None."""
    if "application/json" in content_type:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict) or not data:
            return None
        target = _pick_target_param(list(data.keys()))
        if not target:
            return None
        data[target] = f"{data[target]}*"
        return json.dumps(data)

    if "application/x-www-form-urlencoded" in content_type or not content_type:
        params = parse_qs(body, keep_blank_values=True)
        if not params:
            return None
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
        return urlencode(pairs, safe="*")

    return None


def handle_commix_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Punto de entrada del adaptador. Recibe el diccionario de argumentos
    que el SkillsMCPServer le pasa desde el agente Validate.
    """
    logger.info("[COMMIX HANDLER] Input recibido: %s", arguments)
    args = dict(arguments)
    input_files: Dict[str, str] = {}
    args["extra_flags"] = ""

    try:
        request = args.get("request") or {}
        target_url = args.get("target_url", "")

        url = request.get("url") or target_url
        method = (request.get("method") or "GET").upper()
        headers = request.get("headers") or {}
        body = request.get("body") or ""
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""

        if not url:
            args["skip_execution"] = True
            args["reason"] = "Sin URL objetivo."
            return args, input_files

        if is_static_asset(url):
            args["skip_execution"] = True
            args["reason"] = f"Recurso estático descartado: {url}"
            logger.info("[COMMIX HANDLER] Skip por recurso estático: %s", url)
            return args, input_files

        # Construir flags auxiliares (headers extra + cookie) desde el inicio
        extra_flags, cookie = _build_extra_flags(headers)

        # Caso 1: GET (o POST sin body) -> inyectar en query string
        if method == "GET" or not body:
            new_url = _inject_in_query(url)
            if not new_url:
                args["skip_execution"] = True
                args["reason"] = "La URL no tiene parámetros en la query string inyectables."
                logger.info("[COMMIX HANDLER] Skip por query sin parámetros: %s", url)
                return args, input_files
            args["target_url"] = new_url

        # Caso 2: POST con body
        else:
            new_body = _inject_in_body(body, content_type)
            if not new_body:
                args["skip_execution"] = True
                args["reason"] = (
                    f"No se pudo identificar un parámetro inyectable en el body "
                    f"(Content-Type: {content_type or 'desconocido'})."
                )
                logger.info("[COMMIX HANDLER] Skip por body no soportado: %s", content_type)
                return args, input_files
            args["target_url"] = url
            extra_flags.append(f"--data={shlex.quote(new_body)}")

        if cookie:
            extra_flags.append(f"--cookie={shlex.quote(cookie)}")

        args["extra_flags"] = " ".join(extra_flags)
        logger.info("[COMMIX HANDLER] Output: %s", args)
        return args, input_files

    except Exception as e:
        logger.exception("[COMMIX HANDLER] Error inesperado: %s", e)
        args["skip_execution"] = True
        args["reason"] = f"Error interno en commix_handler: {e}"
        return args, input_files