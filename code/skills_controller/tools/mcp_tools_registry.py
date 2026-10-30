
from handlers.commix_handler import handle_commix_args
from handlers.dalfox_handler import handle_dalfox_args
from handlers.sqlmap_handler import handle_sqlmap_args
from handlers.sqliManual_handler import execute_sqli_manual
from handlers.sqli_map_handler import execute_sqli_map
from handlers.deep_crawler_handler import handle_deep_crawler_args

from handlers.crypto_inspector_handler import prepare_args as handle_crypto_inspector_args
from tools.testssl_handler import prepare_args as handle_testssl_args
from tools.hydra_handler import prepare_args as handle_hydra_args
from tools.ffuf_handler import prepare_args as handle_ffuf_args

from handlers.crawler_reports import (
    persist_crawler_report,
    persist_deep_crawler_report,
)
from handlers.commix_handler import handle_commix_args
from handlers.dalfox_handler import handle_dalfox_args
from tools.jwt_tool_adapter import handle_jwt_tool_args

MCP_SKILLS_REGISTRY = {
    "sqli_agent": {
        "mcp_schema": {
            "name": "sqli_manual",
            "description": (
                "Realiza pruebas SQLi acotadas de error, booleanas y de tiempo "
                "sobre un parámetro observado. No extrae datos ni ejecuta escrituras."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Endpoint capturado"},
                    "param": {"type": "string", "description": "Campo observado a validar"},
                    "method": {"type": "string", "description": "Método HTTP observado"},
                    "location": {
                        "type": "string",
                        "description": "Ubicación observada: query, form_body o json_body",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Headers capturados para reproducir la request",
                    },
                    "body": {
                        "type": "object",
                        "description": "Body estructurado capturado, cuando esté disponible",
                    },
                },
                "required": ["target_url", "param"],
            },
        },
        "handler": execute_sqli_manual,
    },
    "sqli_map": {
        "mcp_schema": {
            "name": "sqli_map",
            "description": (
                "Ejecuta SQLMap en un contenedor conectado a sec-net sobre un único "
                "parámetro observado. validate detecta y, solo con confirmación "
                "positiva, lista nombres de bases de datos y tablas. No consulta "
                "columnas ni extrae filas. detect ejecuta solo la detección."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["detect", "validate"],
                        "description": (
                            "detecta únicamente o valida y lista bases/tablas tras "
                            "una detección positiva (por defecto: detect)"
                        ),
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Endpoint capturado dentro del origen autorizado",
                    },
                    "request": {
                        "type": "object",
                        "description": "Petición HTTP estructurada capturada",
                    },
                    "param": {
                        "type": "string",
                        "description": "Único parámetro observado que se debe probar",
                    },
                },
                "required": ["param"],
            },
        },
        "handler": execute_sqli_map,
    },
    "katana_full": {
        "mcp_schema": {
            "name": "katana_full",
            "description": "Escaneo profundo de la Web, ideal para ataques",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo a rastrear",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "projectdiscovery/katana:latest",
        "command_template": "-u {target_url} -silent -d 5 -jc -jsl -xhr -fx -aff -kf all -td -kb-endpoints",
        "timeout": 3600,
        "success_exit_codes": [0],
    },
    "spa_crawler": {
        "mcp_schema": {
            "name": "spa_crawler",
            "description": (
                "Crawler basado en navegador para aplicaciones SPA. Abre la aplicación con Chromium, "
                "detecta enlaces, rutas hash como /#/login, directivas routerLink y peticiones API "
                "XHR/fetch. USAR para complementar Katana cuando la aplicación dependa de JavaScript."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL raíz de la SPA a explorar",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "local-spa-crawler:latest",
        "command_template": "--target-url {target_url}",
        "timeout": 1800,
        "success_exit_codes": [0],
    },
    "crawler": {
        "mcp_schema": {
            "name": "crawler",
            "description": "Descubre enlaces, rutas y metadatos del objetivo con un navegador.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "URL raiz a rastrear"},
                },
                "required": ["target_url"],
            },
        },
        "image": "local-crawler:latest",
        "command_template": "--target-url {target_url}",
        "timeout": 1800,
        "success_exit_codes": [0],
        "postprocess_result": persist_crawler_report,
    },
    "deep_crawler": {
        "mcp_schema": {
            "name": "deep_crawler",
            "description": "Descubre endpoints y realiza interacciones seguras con formularios para capturar peticiones HTTP.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "crawler_report": {
                        "type": "object",
                        "description": "Resultado JSON devuelto por la herramienta crawler en esta ejecucion",
                    },
                },
                "required": ["crawler_report"],
            },
        },
        "image": "local-deep-crawler:latest",
        "command_template": "--crawler-report {crawler_report_path}",
        "timeout": 3600,
        "prepare_args": handle_deep_crawler_args,
        "success_exit_codes": [0],
        "postprocess_result": persist_deep_crawler_report,
    },
    "sqlmap": {
        "mcp_schema": {
            "name": "sqlmap",
            "description": (
                "Evaluación y explotación automática de inyecciones SQL (SQLi). USAR EN FASE DE VALIDACIÓN "
                "CUANDO existan endpoints con parámetros o campos vulnerables a base de datos. "
                "Input esperado: 'request' estructurada o 'target_url'."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Endpoint o URL a evaluar cuando no hay request estructurada",
                    },
                    "request": {
                        "type": "object",
                        "description": "Petición estructurada con method, url, headers y body",
                    },
                },
                "required": [],
            },
        },
        "image": "parrotsec/sqlmap:latest",
        "command_template": '-r "{file_path}" --batch --level=3 --risk=2 -o --threads=10 --ignore-stdin --ignore-code=401 --no-escape',
        "timeout": 3600,
        "prepare_args": handle_sqlmap_args,
        "success_exit_codes": [0],
    },

    "dalfox": {
        "mcp_schema": {
            "name": "dalfox",
            "description": (
                "Análisis especializado en Cross-Site Scripting (XSS reflejado y DOM). "
                "Para GET: requiere URL con parámetros en la query string (?q=test). "
                "Para POST: acepta 'request' estructurada con body y headers."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL con parámetros GET (ej: http://target/search?q=test)",
                    },
                    "request": {
                        "type": "object",
                        "description": "Petición estructurada con method, url, headers y body",
                    },
                },
                "required": [],
            },
        },
        "image": "hahwul/dalfox:latest",
        "command_template": '/app/dalfox {target_arg} {extra_flags}',
        "timeout": 1800,
        "prepare_args": handle_dalfox_args,
        "success_exit_codes": [0, 1],
    },
    "commix": {
        "mcp_schema": {
            "name": "commix",
            "description": (
                "Detección y explotación de inyección de comandos en el sistema operativo "
                "(OS Command Injection). Soporta POST JSON, form-urlencoded y GET con query params."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u endpoint a analizar cuando no hay request estructurada",
                    },
                    "request": {
                        "type": "object",
                        "description": "Petición estructurada con method, url, headers y body",
                    },
                },
                "required": [],
            },
        },
        "image": "local-commix:latest",
        "command_template": "{target_arg} {extra_flags} --technique=CT --batch --level=3",
        "timeout": 3600,
        "prepare_args": handle_commix_args,
        "success_exit_codes": [0],
    },
    "nuclei": {
        "mcp_schema": {
            "name": "nuclei",
            "description": (
                "Escáner multivectorial rápido basado en plantillas predefinidas. USAR PARA VALIDACIÓN GENERAL "
                "de múltiples vulnerabilidades (XSS, Auth Bypass, SQLi, Misconfigurations)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL o endpoint objetivo a evaluar",
                    },
                    "tags": {
                        "type": "string",
                        "description": "Etiquetas de vulnerabilidades a probar",
                        "default": "xss,rce,sqli",
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "local-nuclei:latest",
        "command_template": '-u "{target_url}" -tags {tags} -silent -nc',
        "timeout": 3600,
        "success_exit_codes": [0],
    },
     "ffuf": {
        "mcp_schema": {
            "name": "ffuf",
            "description": (
                "Fuzzer web de URLs, parámetros y payloads JSON. Permite enviar peticiones GET/POST "
                "con cabeceras personalizadas. REQUIERE que la URL o el payload contenga la palabra clave 'FUZZ'."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL que contiene 'FUZZ' (ej: http://juice-shop-target:3000/rest/user/FUZZ)",
                    },
                    "method": {
                        "type": "string",
                        "description": "Método HTTP (GET, POST)",
                        "default": "GET"
                    },
                    "data": {
                        "type": "string",
                        "description": "Cuerpo de la petición JSON o form con el marcador 'FUZZ' (ej: '{\"email\":\"FUZZ\",\"password\":\"test\"}')",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Diccionario de cabeceras (ej: {\"Content-Type\": \"application/json\"})",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "local-ffuf:latest",
        "command_template": "{args}",
        "timeout": 1800,
        "prepare_args": handle_ffuf_args,
        "success_exit_codes": [0],
    },
    # =========================================================================
    # 10. JWT Tool — Análisis y ataques de autenticación JWT (A07:2025)
    # =========================================================================
    "jwt_tool": {
        "mcp_schema": {
            "name": "jwt_tool",
            "description": (
                "Analiza un JSON Web Token y ejecuta tres ataques de autenticación con validación "
                "de 3 baselines (no_auth / customer / forged) para evitar falsos positivos: "
                "(1) alg:none bypass, (2) key confusion RS256→HS256, (3) weak HMAC secret. "
                "Además realiza análisis estático: algoritmo, claims faltantes (exp/nbf/iss/aud), "
                "rol en payload y datos sensibles. USAR EN FASE DE VALIDACIÓN sobre ataques de "
                "autenticación (A07). REQUIERE un JWT válido de un usuario de prueba del objetivo."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL raíz del objetivo (ej: http://juice-shop-target:3000)",
                    },
                    "token": {
                        "type": "string",
                        "description": "JWT válido de un usuario de prueba (header.payload.signature)",
                    },
                    "test_endpoint": {
                        "type": "string",
                        "description": "Path del endpoint protegido (opcional; autodescubre si se omite)",
                    },
                },
                "required": ["target_url", "token"],
            },
        },
        "image": "local-jwt-tool:latest",
        "command_template": "{target_arg} {token_arg} {test_endpoint_arg}",
        "timeout": 600,
        "prepare_args": handle_jwt_tool_args,
        "success_exit_codes": [0, 2],
    },
  
  # =========================================================================
    # testssl - Evaluación de fallos criptográficos (TLS/SSL)
    # =========================================================================
    "testssl": {
        "mcp_schema": {
            "name": "testssl",
            "description": (
                "Análisis pasivo y activo de configuraciones TLS/SSL, certificados, cifer de cifrado "
                "obsoletos y vulnerabilidades del protocolo (OWASP Cryptographic Failures). "
                "Input esperado: target_url (ej: http://juice-shop-target:3000 o hostname:puerto)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u host:puerto objetivo a auditar a nivel SSL/TLS",
                    },
                    "fast_mode": {
                        "type": "boolean",
                        "description": "Ejecutar en modo rápido omitiendo pruebas exhaustivas",
                        "default": True,
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "drwetter/testssl.sh:latest",
        "command_template": "{args}",
        "timeout": 600,
        "prepare_args": handle_testssl_args,
        "success_exit_codes": [0, 1],
    },
  
  # =========================================================================
    # hydra - Pruebas de credenciales por defecto / Fuerza Bruta
    # =========================================================================
    "hydra": {
        "mcp_schema": {
            "name": "hydra",
            "description": (
                "Evaluación de mecanismos de autenticación contra credenciales por defecto y ataques "
                "de diccionario pequeños (OWASP Identification and Authentication Failures)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host u IP objetivo (ej: juice-shop-target)",
                    },
                    "form_path": {
                        "type": "string",
                        "description": "Ruta del formulario y parámetros (ej: /rest/user/login:email=^USER^&password=^PASS^:Invalid)",
                    },
                    "method": {
                        "type": "string",
                        "description": "Protocolo/método a evaluar (ej: http-post-form)",
                        "default": "http-post-form",
                    },
                },
                "required": ["target", "form_path"],
            },
        },
        "image": "local-hydra:latest",
        "command_template": "{args}",
        "timeout": 900,
        "prepare_args": handle_hydra_args,
        "success_exit_codes": [0],
    },
  
  # =========================================================================
    # crypto_inspector - Análisis de seguridad de JWT y algoritmos de hashing
    "crypto_inspector": {
        "mcp_schema": {
            "name": "crypto_inspector",
            "description": (
                "Análisis pasivo de respuestas JSON de API REST y tokens JWT. "
                "Detecta algoritmos de hashing obsoletos (MD5, SHA1), claves expuestas y JWTs inseguros."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "jwt_token": {
                        "type": "string",
                        "description": "Token JWT a analizar",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "URL u endpoint a evaluar",
                    },
                },
                "required": [],
            },
        },
        "image": "local-crypto-inspector:latest",
        "command_template": "{args}",
        "timeout": 300,
        "prepare_args": handle_crypto_inspector_args,
        "success_exit_codes": [0],
    },
  
  
}
