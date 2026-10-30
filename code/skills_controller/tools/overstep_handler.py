import logging
import shlex
from typing import Any, Dict, List, Tuple
from handlers._common import is_static_asset

logger = logging.getLogger("overstep_handler")

def handle_overstep_args(arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Adaptador para overstep.
    Prepara los argumentos para ejecutar pruebas de autorización declarativa.
    """
    args = dict(arguments)
    input_files: List[str] = []

    target_url = args.get("target_url") or args.get("url") or ""
    if not target_url or is_static_asset(target_url):
        args["skip_execution"] = True
        args["reason"] = "URL objetivo no válida o es un recurso estático."
        return args, input_files

    # overstep requiere una matriz YAML que declare sujetos, recursos y política.
    # El handler debe recibir la ruta al archivo de matriz.
    matrix_file = args.get("matrix_file", "")
    if not matrix_file:
        args["skip_execution"] = True
        args["reason"] = "overstep requiere una matriz YAML (matrix_file) con la definición de sujetos y recursos."
        return args, input_files

    # Tokens para los sujetos (se inyectan como variables de entorno o en la matriz)
    token_a = args.get("token_a", "")
    token_b = args.get("token_b", "")
    output_dir = args.get("output", "./overstep_findings")

    # Construir el comando base: overstep run <matrix.yaml> --out <dir>
    cli_flags = [
        "run",
        shlex.quote(matrix_file),
        "--out",
        shlex.quote(output_dir),
    ]

    # Si se proporcionan tokens, se pueden pasar como variables de entorno
    # (asumiendo que la matriz usa ${ALICE_TOKEN} y ${BOB_TOKEN})
    # Esto se manejaría en el entorno de ejecución del contenedor, no aquí.

    # Banderas opcionales para CI/reportes
    if args.get("read_only", False):
        cli_flags.append("--read-only")
    if args.get("fail_on"):
        cli_flags.extend(["--fail-on", shlex.quote(args["fail_on"])])

    args["args"] = " ".join(cli_flags)
    args["env"] = {
        "ALICE_TOKEN": token_a,
        "BOB_TOKEN": token_b,
    } if token_a and token_b else {}

    logger.info("[OVERSTEP HANDLER] Comando generado para %s con matriz %s", target_url, matrix_file)
    return args, input_files

prepare_args = handle_overstep_args