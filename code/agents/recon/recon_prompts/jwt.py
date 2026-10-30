from .common import build_prompt as build_common_prompt


def build_prompt(attack_type_filter: str) -> str:
    """Prompt de referencia; no se invoca porque main.py hace fast-path para JWT.

    Se mantiene registrado para no romper get_system_prompt si en el futuro
    se reincorpora el flujo de crawling para JWT.
    """
    return build_common_prompt(
        attack_type_filter,
        (
            "Para JWT la fase de reconocimiento es un fast-path: no se realiza crawling. "
            "El skill jwt_tool autodescubre el endpoint protegido (401 sin auth, 200 con token "
            "válido) y ejecuta los ataques de autenticación. Devuelve un único target apuntando "
            "a la URL raíz con recommended_tool='jwt_tool'."
        ),
    )