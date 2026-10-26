ATTACKS_REGISTRY = {
    "sqli": {
        "name": "SQL Injection (SQLi)",
        "description": (
            "Vulnerabilidad que ocurre cuando entradas no consolidadas ni sanitizadas "
            "se concatenan directamente en consultas SQL enviadas a la base de datos."
        ),
        "recon_focus": (
            "Busca y prioriza endpoints que procesen datos de entrada: formularios de "
            "autenticación (login/register), campos de búsqueda, parámetros ID en URLs "
            "(ej: /user?id=1), o endpoints JSON con filtros en peticiones POST."
        ),
        "key_indicators": [
            "Peticiones POST con payloads de autenticación (JSON o Form Data)",
            "Parámetros numéricos o de texto en URLs query (?id=, ?category=, ?search=)",
            "Cabeceras HTTP que puedan interactuar con la base de datos (User-Agent, Referer)",
        ],
        "primary_skill": "sqlmap",
    },
    "jwt": {
        "name": "JWT Authentication Analysis (A07)",
        "description": (
            "Debilidades en la validación de JSON Web Tokens: alg:none, confusión de "
            "claves (RS256→HS256), secretos HMAC débiles, claims sin caducidad, "
            "información sensible en el payload y escalado de rol."
        ),
        "recon_focus": (
            "Requiere un JWT válido de un usuario de prueba. El handler autodescubre "
            "un endpoint protegido (401 sin token, 200 con token) y valida cada ataque "
            "con 3 baselines (sin_auth / customer / forged) para evitar falsos positivos."
        ),
        "key_indicators": [
            "Token JWT en cabecera Authorization: Bearer",
            "Claims sin exp/nbf/iss/aud",
            "Algoritmo simétrico (HS256) con secreto débil",
            "Algoritmo asimétrico con clave pública accesible",
        ],
        "primary_skill": "jwt_tool",
    },
}