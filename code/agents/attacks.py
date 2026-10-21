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
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": (
            "Vulnerabilidad que permite ejecutar contenido controlado por el cliente "
            "en el contexto del navegador de otra persona."
        ),
        "recon_focus": (
            "Prioriza parámetros de URL, formularios, campos de búsqueda, comentarios "
            "y solicitudes POST donde una entrada del usuario pueda reflejarse o "
            "persistirse y mostrarse posteriormente."
        ),
        "key_indicators": [
            "Parámetros de query y fragmento procesados por la aplicación",
            "Campos de formularios y solicitudes POST con entrada de usuario",
            "Respuestas o vistas que vuelven a mostrar esos valores",
        ],
        "primary_skill": "dalfox",
    },
}