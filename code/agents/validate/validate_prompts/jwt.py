from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    """Prompt de referencia; no se invoca porque main.py hace handling determinista.

    Se registra para no romper get_system_prompt si en el futuro se reincorpora
    un flujo con LLM para JWT. Por ahora el resultado del handler ya viene
    estructurado y se transforma directamente a ValidateOutput.
    """
    return build_common_prompt(
        attack_type_filter,
        (
            "CRITERIOS ESPECÍFICOS PARA JWT (A07)\n\n"
            "El skill jwt_tool devuelve un JSON estructurado con:\n"
            "- jwt_analysis: algoritmo, claims faltantes, rol en payload, datos sensibles\n"
            "- attacks: alg_none, key_confusion, weak_secret con validación de 3 baselines\n"
            "- findings: hallazgos ya clasificados con severidad\n\n"
            "Un ataque con 'success=true' y 'validation.reason=auth_bypass_confirmed' "
            "es evidencia directa de bypass de autenticación (CRITICAL).\n\n"
            "Las debilidades de análisis estático (claims faltantes, algoritmo simétrico) "
            "son hallazgos HIGH/MEDIUM sin explotación requerida.\n\n"
            "No inventes CWEs ni CVEs: usa solo lo que el handler proporcione."
        ),
    )