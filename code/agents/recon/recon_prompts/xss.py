from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        "Prioriza parámetros GET y campos de formularios o solicitudes POST "
        "controlados por el usuario que puedan reflejarse o persistirse y "
        "mostrarse después. Devuelve solo endpoints y requests observados, "
        "recomendando dalfox cuando esté disponible. La superficie observada "
        "no confirma XSS.",
    )
