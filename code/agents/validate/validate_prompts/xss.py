from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    return build_common_prompt(
        attack_type_filter,
        """
        CRITERIOS ESPECÍFICOS PARA XSS

        Analiza las ejecuciones normalizadas de Dalfox y browserXssValidator.
        Dalfox confirma solo una POC `verified` (V); una reflexión (R) por sí
        sola no acredita ejecución. browserXssValidator confirma únicamente si
        reporta `VERIFIED` tras observar ejecución del marcador sintético en el
        navegador. En flujos `stored_dom`, exige además `cleanup=success`.

        Conserva `INCONCLUSIVE`, `SKIPPED` y `ERROR` como no confirmados; no los
        conviertas en resultados limpios ni en evidencia de mitigación. No afirmes
        XSS almacenado solo porque se escaneó un POST: requiere evidencia de
        escritura, lectura, ejecución y limpieza. No inventes pruebas ni resultados.
        """,
    )
