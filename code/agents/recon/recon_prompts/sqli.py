from .common import build_prompt as build_common_prompt


def build_prompt(target_url: str, attack_type_filter: str) -> str:
    return build_common_prompt(
        target_url,
        attack_type_filter,
        "Para SQLi, analiza exclusivamente sqli_input_entry_points. Solo se incluyen "
        "requests observadas con body no nulo. Identifica evidencia que pueda "
        "relacionarse con entradas controladas por el cliente y consultas SQL; "
        "esto no confirma una vulnerabilidad.",
    )
