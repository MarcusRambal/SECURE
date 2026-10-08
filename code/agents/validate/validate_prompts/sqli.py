from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        """
        CRITERIOS ESPECÍFICOS PARA SQL INJECTION

        Analiza exclusivamente evidencia relacionada con posibles vulnerabilidades
        de SQL Injection.

        Solo considera las requests de validación que hayan sido realmente
        observadas y proporcionadas en las fuentes de entrada.

        Prioriza:

        - Evidencia producida por herramientas de validación que indique errores,
        comportamientos o respuestas compatibles con SQL Injection.

        La presencia de palabras como "sql", "query", "database", "SELECT",
        "INSERT", "UPDATE" o similares tampoco confirma una vulnerabilidad.

        Una vulnerabilidad SQL Injection solo debe clasificarse como confirmada
        cuando las herramientas de validación proporcionen evidencia suficiente
        para relacionar una entrada controlable por el cliente con un
        comportamiento SQL vulnerable.

        Si existe un indicio relacionado con SQL Injection pero la evidencia no
        es suficiente para confirmarlo, clasifícalo como unconfirmed_finding.

        No inventes consultas SQL, parámetros, payloads, respuestas, errores,
        comandos ni comportamiento de la aplicación que no aparezcan en las
        fuentes proporcionadas.
        
        La identificación de un parámetro potencialmente vulnerable es evidencia
        de superficie, no confirmación de SQL Injection.
        """,
    )