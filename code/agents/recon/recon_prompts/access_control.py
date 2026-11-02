from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        "Para Broken Access Control (access_control_prober), analiza todas las fuentes disponibles:\n"
        "- peticiones capturadas (captured_entry_points)\n"
        "- endpoints del crawler (crawler_endpoints)\n"
        "- URLs relevantes (interesting_urls, deduplicated_urls)\n"
        "- endpoints con identificadores (potential_idor_endpoints)\n\n"
        "Prioriza e incluye objetivos observables que correspondan a:\n"
        "1. Recursos que pertenezcan a un usuario concreto: perfiles, cestas, pedidos, facturas, documentos o archivos con ID numérico o UUID.\n"
        "2. Endpoints REST/API de usuario, cuenta, administración o configuración que permitan comparar el acceso entre dos identidades.\n"
        "3. Rutas de descarga o directorios sensibles expuestos.\n\n"
        "REGLA OBLIGATORIA: selecciona como objetivos prioritarios los recursos con identificador observable y usa "
        "recommended_tool='access_control_prober'. No inventes IDs, tokens ni endpoints: la fase de validación "
        "obtiene las credenciales y ejecuta la explotación activa.",
    )
