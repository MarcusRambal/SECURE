from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        """
        CRITERIOS ESPECÍFICOS PARA SQL INJECTION

        Analiza exclusivamente evidencia relacionada con posibles vulnerabilidades
        de SQL Injection.

        El agente SQLi puede haber ejecutado pruebas limitadas de error, booleanas
        y de tiempo sobre parámetros observados en requests capturadas. Basa cualquier
        conclusión exclusivamente en los resultados concretos incluidos en el
        contexto de validación.

        Después de esas pruebas también puede haber resultados de SQLMap en modo
        detección. Una detección positiva explícita de SQLMap es evidencia; un
        resultado sin confirmar o un error de ejecución no demuestra que el endpoint
        sea vulnerable.

        Prioriza:

        - Errores SQL explícitos vinculados al parámetro probado.
        - Diferencias repetibles entre las respuestas de las condiciones verdadera
        y falsa.
        - En endpoints de login, una respuesta exitosa a la tautología SQL
        únicamente cuando la condición contradictoria sea rechazada.
        - Retrasos compatibles con la prueba temporal ejecutada, distinguiéndolos
        de latencia de red o errores de transporte.

        La presencia de palabras como "sql", "query", "database", "SELECT",
        "INSERT", "UPDATE" o similares tampoco confirma una vulnerabilidad.

        Una vulnerabilidad SQL Injection solo debe clasificarse como confirmada
        cuando las herramientas de validación proporcionen evidencia suficiente
        para relacionar una entrada controlable por el cliente con un
        comportamiento SQL vulnerable.

        Si existe un indicio relacionado con SQL Injection pero la evidencia no
        es suficiente para confirmarlo, clasifícalo como unconfirmed_finding.

        No inventes consultas SQL, parámetros, resultados de pruebas, respuestas,
        errores, comandos ni comportamiento de la aplicación que no aparezcan en
        las fuentes proporcionadas. Una prueba con error de transporte no es una
        prueba negativa ni confirma una vulnerabilidad.
        
        La identificación de un parámetro potencialmente vulnerable es evidencia
        de superficie, no confirmación de SQL Injection.
        """,
    )