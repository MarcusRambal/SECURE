import logging
import shlex
from typing import Any, Dict, List, Tuple
from handlers._common import is_static_asset

logger = logging.getLogger("ffuf_handler")


def prepare_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Adaptador para ffuf.
    Prepara los argumentos para la ejecución en contenedores efímeros.
    """
    args = dict(arguments)
    input_files: List[str] = []

    target_url = args.get("target_url") or args.get("url") or ""

    if not target_url or is_static_asset(target_url):
        args["skip_execution"] = True
        args["reason"] = "URL objetivo no válida o es un recurso estático."
        return args, input_files

    # Usar wordlist existente por defecto dentro de la imagen
    wordlist = args.get("wordlist", "/wordlists/users_small.txt")
    method = args.get("method", "POST")
    content_type = args.get("content_type", "application/json")
    data_payload = args.get("data", '{"email":"FUZZ","password":"password123"}')
    match_codes = args.get("match_codes", "200,401")

    # Construcción de la bandera CLI con sanitización mediante shlex.quote
    cli_flags = [
        "-u",
        shlex.quote(target_url),
        "-w",
        shlex.quote(wordlist),
        "-X",
        shlex.quote(method),
        "-H",
        shlex.quote(f"Content-Type: {content_type}"),
        "-d",
        shlex.quote(data_payload),
        "-mc",
        shlex.quote(match_codes),
        "-s",  # Modo silencioso para facilitar el parsing de resultados JSON
    ]

    args["args"] = " ".join(cli_flags)
    logger.info("[FFUF HANDLER] Comando generado correctamente para %s", target_url)

    return args, input_files
