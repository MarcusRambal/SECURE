ATTACKS_REGISTRY = {
    "sqli": {
        "name": "SQL Injection (SQLi)",
        "description": (
            "Vulnerabilidad que ocurre cuando entradas no consolidadas ni sanitizadas "
            "se concatenan directamente en consultas SQL enviadas a la base de datos."
        ),
        "recon_focus": (
            "Busca y prioriza endpoints que procesen datos de entrada: formularios de autenticación (login/register), "
            "campos de búsqueda, parámetros ID en URLs (ej: /user?id=1), o endpoints JSON con filtros en peticiones POST."
        ),
        "key_indicators": [
            "Peticiones POST con payloads de autenticación (JSON o Form Data)",
            "Parámetros numéricos o de texto en URLs query (?id=, ?category=, ?search=)",
            "Cabeceras HTTP que puedan interactuar con la base de datos (User-Agent, Referer)"
        ],
        "primary_skill": "sqlmap"
    },
}