import logging
import shlex
from typing import Any, Dict, List, Tuple
from handlers._common import is_static_asset

logger = logging.getLogger("ffuf_handler")

def prepare_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Adaptador para ffuf con perfiles de escaneo y optimizaciones.
    """
    args = dict(arguments)
    input_files: List[str] = []

    target_url = args.get("target_url") or args.get("url") or ""

    if not target_url or is_static_asset(target_url):
        args["skip_execution"] = True
        args["reason"] = "URL objetivo no válida o es un recurso estático."
        return args, input_files

    # Mapeo de wordlists (asumiendo que están en /wordlists/ dentro del contenedor)
    WORDLIST_MAP = {
        "common": "/wordlists/common.txt",
        "api": "/wordlists/api-endpoints.txt",
        "backups": "/wordlists/backup-files.txt",
        "users": "/wordlists/users_small.txt",
        "medium": "/wordlists/directory-list-2.3-medium.txt" # <--- AÑADIR ESTA LÍNEA
    }
    wordlist_type = args.get("wordlist_type", "api") # Por defecto usamos API
    wordlist_path = WORDLIST_MAP.get(wordlist_type, WORDLIST_MAP["api"])

    method = args.get("method", "GET")
    content_type = args.get("content_type", "application/json")
    data_payload = args.get("data", '')
    match_codes = args.get("match_codes", "200,204,301,302,403")
    
    # Perfil de escaneo: default, deep, stealth
    scan_profile = args.get("scan_profile", "deep")

    cli_flags = [
        "-u", shlex.quote(target_url),
        "-w", shlex.quote(wordlist_path),
        "-X", shlex.quote(method),
        "-H", shlex.quote(f"Content-Type: {content_type}"),
        "-mc", shlex.quote(match_codes),
        "-s",  # Modo silencioso (solo imprime las rutas encontradas)
    ]

    # --- CONFIGURACIÓN AVANZADA SEGÚN EL PERFIL ---
    if scan_profile == "deep":
        # Escaneo profundo: recursión, más hilos y auto-calibración
        cli_flags.extend([
            "-recursion", "-recursion-depth", "2",
            "-t", "100",
            "-ac" # Auto-calibración (evita falsos positivos)
        ])
    elif scan_profile == "stealth":
        # Evasión de WAF: rate limiting y cabeceras de bypass
        cli_flags.extend([
            "-rate", "10",
            "-p", "0.1-0.3",
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-ac"
        ])
    else:
        # Default: escaneo rápido y equilibrado
        cli_flags.extend(["-t", "40", "-ac"])

    # Solo añadimos el body (-d) si hay datos
    if data_payload:
        cli_flags.extend(["-d", shlex.quote(data_payload)])

    args["args"] = " ".join(cli_flags)
    logger.info("[FFUF HANDLER] Comando generado para %s con perfil %s", target_url, scan_profile)

    return args, input_files