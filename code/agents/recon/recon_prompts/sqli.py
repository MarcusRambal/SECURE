from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        "Para SQLi, analiza exclusivamente sqli_input_entry_points. Evalúa todos los "
        "entry points de la lista y devuelve un target independiente para cada request "
        "relevante; no selecciones solo el más evidente. Se incluyen requests "
        "observadas con body o parámetros de query; en métodos GET, el body debe "
        "permanecer nulo y los parámetros deben leerse de la URL/query_parameters. "
        "Identifica los campos controlados por el cliente que podrían llegar a "
        "consultas SQL y prioriza los candidatos con mayor evidencia, sin omitir los "
        "demás. Esto no confirma una vulnerabilidad.",
    )
