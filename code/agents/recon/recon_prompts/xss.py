from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        "Prioriza parámetros GET y campos de formularios o solicitudes POST "
        "controlados por el usuario que puedan reflejarse o persistirse y "
        "mostrarse después. Devuelve solo requests observadas con parámetros "
        "GET o body; recomienda exclusivamente dalfox y nunca sqlmap para este "
        "filtro. La superficie observada no confirma XSS.",
    )
