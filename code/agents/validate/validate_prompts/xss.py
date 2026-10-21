from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        """
        CRITERIOS ESPECÍFICOS PARA XSS

        Analiza exclusivamente las ejecuciones de Dalfox que aparecen en el
        contexto normalizado. Dalfox puede marcar una POC como `verified` (V)
        o como reflejada (R); una reflexión por sí sola no confirma ejecución
        de JavaScript. Confirma XSS solo ante una POC verificada. Usa el contexto,
        parámetro y payload únicamente si aparecen en el resultado normalizado.
        `NO_FINDINGS`, `SKIPPED` y `ERROR` no confirman ni descartan XSS.

        No afirmes XSS almacenado solo porque se haya escaneado una request POST:
        la salida debe acreditar la ejecución de una POC; esta integración no
        realiza un flujo de escritura y posterior lectura de segundo orden.
        No inventes comandos reproducibles, payloads ni comportamiento del navegador.
        """,
    )
