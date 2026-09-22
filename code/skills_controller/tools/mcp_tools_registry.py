from tools.sqlmap_handler import handle_sqlmap_args

MCP_SKILLS_REGISTRY = {
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
        "command_template": '-r "{req_file_path}" --batch --level=5 --risk=3 --ignore-stdin --ignore-code=401 --no-escape',
        "timeout": 3600,
        "handler": handle_sqlmap_args,
        "success_exit_codes": [0],
    },
    # =========================================================================
    # 6. DalFox - Escáner de Cross-Site Scripting (XSS)
    # =========================================================================
    "dalfox": {
        "mcp_schema": {
            "name": "dalfox",
            "description": (
                "Análisis especializado en Cross-Site Scripting (XSS reflejado y DOM). REQUIERE OBLIGATORIAMENTE "
                "una URL que contenga parámetros en la query (ej: ?q=test o ?search=query). NO FUNCIONA en URLs "
                "raíz o sin parámetros. USAR EN FASE DE VALIDACIÓN sobre endpoints de búsqueda o filtros. "
                "Input esperado: URL con parámetros query. Devuelve: Confirmación de XSS y PoC con payload ejecutable."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL completa con parámetros (ej: http://juice-shop-target:3000/#/search?q=test)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "hahwul/dalfox:latest",
        "command_template": './dalfox url --url "{target_url}" --silence',
        "timeout": 1800,
        "success_exit_codes": [0, 2],
    },
    # =========================================================================
    # 7. Commix - Inyección de Comandos del SO (Command Injection)
    # =========================================================================
    "commix": {
        "mcp_schema": {
            "name": "commix",
            "description": (
                "Detección y explotación de inyección de comandos en el sistema operativo (OS Command Injection). "
                "USAR EN FASE DE VALIDACIÓN sobre parámetros sospechosos de interactuar con el sistema (ej: campos "
                "de IP, pings, subida de archivos, utilidades del sistema). Input esperado: URL con parámetro "
                "evaluable (ej: http://webgoat-target:8080/WebGoat/ping?ip=127.0.0.1). Devuelve: Confirmación de RCE "
                "y comandos ejecutados."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u endpoint a analizar (ej: http://webgoat-target:8080/WebGoat/cmd)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "local-commix:latest",
        "command_template": '--url="{target_url}" --batch',
        "timeout": 3600,
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
