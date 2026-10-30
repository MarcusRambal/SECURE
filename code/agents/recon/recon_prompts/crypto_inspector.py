from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        "Para fallos criptográficos (crypto_inspector), analiza minuciosamente todas las fuentes disponibles:\n"
        "- peticiones capturadas (captured_entry_points)\n"
        "- endpoints interesantes (interesting_urls)\n"
        "- rutas y endpoints del crawler (crawler_endpoints)\n\n"
        "Prioriza e incluye objetivos observables que correspondan a:\n"
        "1. Endpoints de configuración, administración, diagnóstico o metadatos de la aplicación (ej: /rest/admin/..., config, version, status, /api/...).\n"
        "2. Endpoints de autenticación, usuarios, sesiones o contraseñas (ej: login, register, auth, token, Users, whoami, reset).\n"
        "3. Cualquier endpoint o solicitud HTTP observada con posible exposición de hashes (MD5, SHA1, SHA256), tokens JWT o cabeceras de autorización.\n\n"
        "REGLA OBLIGATORIA: Si se descubrieron endpoints API, administrativos, de configuración o de autenticación, selecciónalos como objetivos "
        "prioritarios con recommended_tool='crypto_inspector' para que la herramienta especializada valide y analice su contenido y entropía.",
    )
