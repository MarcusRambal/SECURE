from handlers.sqlmap_handler import handle_sqlmap_args
from handlers.sqliManual_handler import execute_sqli_manual
from handlers.sqli_map_handler import execute_sqli_map
from handlers.deep_crawler_handler import handle_deep_crawler_args
from handlers.commix_handler import handle_commix_args
from handlers.dalfox_handler import handle_dalfox_args

MCP_SKILLS_REGISTRY = {
    "sqli_agent": {
        "mcp_schema": {
            "name": "sqli_agent",
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
            "description": ("Escaneo profundo de la Web, ideal para ataques"),
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
    # =========================================================================
    # 4. SPA Crawler - Descubrimiento de rutas de aplicaciones JavaScript
    # =========================================================================
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
    },
    # =========================================================================
    # 5. SQLMap - Validación de Inyección SQL
    # =========================================================================
    "sqlmap": {
        "mcp_schema": {
            "name": "sqlmap",
            "description": (
                "Evaluación y explotación automática de inyecciones SQL (SQLi). USAR EN FASE DE VALIDACIÓN "
                "CUANDO existan endpoints con parámetros o campos vulnerables a base de datos (ej: formulación "
                "de login, búsquedas, IDs). NO usar como escáner general sobre la raíz del sitio. "
                "Input esperado: preferiblemente 'request' con la petición HTTP estructurada "
                "generada por el crawler. El servidor crea un archivo temporal interno para SQLMap. "
                "Alternativa: 'target_url' para una URL simple. "
                "Devuelve: Confirmación del vector SQLi, tipo de BD y payloads funcionales."
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
    # =========================================================================
    # 6. DalFox - Escáner de Cross-Site Scripting (XSS)
    # =========================================================================
"dalfox": {
    "mcp_schema": {
        "name": "dalfox",
        "description": (
            "Análisis especializado en Cross-Site Scripting (XSS reflejado y DOM). "
            "Para GET: requiere URL con parámetros en la query string (?q=test). "
            "Para POST: acepta 'request' estructurada con body y headers. "
            "El modo POST analiza la request capturada, pero no implementa por sí solo "
            "la secuencia almacenado escritura-lectura de XSS almacenado. "
            "USAR EN FASE DE VALIDACIÓN sobre endpoints de búsqueda, filtros o formularios. "
            "Devuelve: confirmación de XSS y PoC con payload ejecutable."
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
    # =========================================================================
    # 7. Commix - Inyección de Comandos del SO (Command Injection)
    # =========================================================================
    "commix": {
        "mcp_schema": {
            "name": "commix",
            "description": (
                "Detección y explotación de inyección de comandos en el sistema operativo (OS Command Injection). "
                "USAR EN FASE DE VALIDACIÓN sobre endpoints con parámetros sospechosos de interactuar con el sistema "
                "(ej: campos de IP, ping, subida de archivos, utilidades del sistema). "
                "Soporta POST JSON, form-urlencoded y GET con query params. "
                "Input esperado: 'request' con la petición HTTP estructurada (method, url, headers, body) "
                "o 'target_url' para una URL simple. Devuelve: confirmación de RCE con payload y técnica detectada."
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
    # =========================================================================
    # 8. Nuclei - Escaneo Multivectorial por Plantillas
    # =========================================================================
    "nuclei": {
        "mcp_schema": {
            "name": "nuclei",
            "description": (
                "Escáner multivectorial rápido basado en plantillas predefinidas. USAR PARA VALIDACIÓN GENERAL "
                "de múltiples vulnerabilidades (XSS, Auth Bypass, SQLi, Misconfigurations) en un solo paso. "
                "Ideal como escaneo de cobertura amplia tras el reconocimiento. Input esperado: URL objetivo "
                "y tags opcionales (ej: 'xss,rce,sqli,auth'). Devuelve: Vulnerabilidades detectadas categorizadas por severidad."
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
    # =========================================================================
    # 9. FFuF - Fuzzing Web y Descubrimiento Oculto
    # =========================================================================
    "ffuf": {
        "mcp_schema": {
            "name": "ffuf",
            "description": (
                "Fuzzer de URLs y parámetros mediante diccionarios. LA URL DEBE INCLUIR OBLIGATORIAMENTE LA "
                "PALABRA CLAVE 'FUZZ' (ej: http://target/FUZZ o http://target/api?user=FUZZ). NO USAR si la "
                "URL no contiene la palabra FUZZ. USAR PARA descubrir archivos ocultos, rutas no enlazadas o "
                "fuerza bruta de parámetros. Input esperado: URL formateada con 'FUZZ'. Devuelve: Códigos de respuesta "
                "HTTP relevantes (200, 301, 401, 403)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL que DEBE incluir la palabra 'FUZZ' (ej: http://juice-shop-target:3000/FUZZ)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "local-ffuf:latest",
        "command_template": '-u "{target_url}" -w /wordlists/common.txt -s',
        "timeout": 1800,
        "success_exit_codes": [0],
    },
}
