"""
Adaptador (handler) para jwt_tool_handler.py.

El ejecutable del contenedor (jwt_tool_handler.py) acepta tres flags:
    --target URL               (obligatorio)
    --token JWT                (obligatorio)
    --test-endpoint PATH       (opcional, override de autodescubrimiento)

Este adapter construye el comando con shlex.quote() para que ningún
carácter especial del token o la URL rompa el /bin/sh -c del contenedor.
"""

import logging
import shlex
from typing import Any, Dict, Tuple

logger = logging.getLogger("jwt_tool_adapter")


def handle_jwt_tool_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Prepara los fragmentos del comando para el template:
        {target_arg} {token_arg} {test_endpoint_arg}

    Devuelve (args_actualizados, archivos_a_inyectar).
    No hay archivos a inyectar porque el token viaja como string.
    """
    args = dict(arguments)
    input_files: Dict[str, str] = {}

    target_url = args.get("target_url")
    token = args.get("token")

    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("jwt_tool requiere 'target_url'.")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("jwt_tool requiere 'token'.")

    # Sanitizar por si llegan con prefijos que el usuario copió del navegador
    # (algunos DevTools muestran "Bearer eyJ...", o el usuario pega comillas).
    token_clean = token.strip().strip('"').strip("'")
    if token_clean.lower().startswith("bearer "):
        token_clean = token_clean[7:].strip()

    args["target_arg"] = f"--target {shlex.quote(target_url.strip())}"
    args["token_arg"] = f"--token {shlex.quote(token_clean)}"

    test_endpoint = args.get("test_endpoint")
    if isinstance(test_endpoint, str) and test_endpoint.strip():
        args["test_endpoint_arg"] = (
            f"--test-endpoint {shlex.quote(test_endpoint.strip())}"
        )
    else:
        args["test_endpoint_arg"] = ""

    logger.info(
        "[JWT ADAPTER] target=%s token_length=%d test_endpoint=%s",
        target_url, len(token_clean), args["test_endpoint_arg"] or "<auto>",
    )
    return args, input_files