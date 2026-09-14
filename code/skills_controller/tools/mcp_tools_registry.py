MCP_SKILLS_REGISTRY = {
    # =========================================================================
    # 1. OWASP ZAP - AJAX Spider
    # =========================================================================
    "zap_ajax_spider": {
        "mcp_schema": {
            "name": "zap_ajax_spider",
            "description": (
                "Rastreo dinámico profundo con navegador headless para aplicaciones SPA/JavaScript "
                "(React, Angular, Vue). USAR CUANDO el objetivo sea una SPA o requiera ejecutar "
                "código JS para revelar botones y rutas ocultas (ej: Juice Shop). NO usar para "
                "sitios estáticos simples o APIs puras. Input esperado: URL raíz completa "
                "(ej: http://juice-shop-target:3000). Devuelve: URLs dinámicas descubiertas y "
                "alertas de seguridad pasivas."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop-target:3000)",
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo",
                        "default": 3,
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -j -I",
        "timeout": 900,
        "success_exit_codes": [0, 1, 2, 3],
    },
    # =========================================================================
    # 2. OWASP ZAP - Baseline Spider
    # =========================================================================
    "zap_baseline_spider": {
        "mcp_schema": {
            "name": "zap_baseline_spider",
            "description": (
                "Rastreo estático rápido y análisis pasivo de cabeceras HTTP, cookies, robots.txt "
                "y sitemaps. USAR CUANDO necesites un escaneo superficial inicial de cabeceras o "
                "para sitios HTML tradicionales. NO usar para SPA complejas basadas en JS. "
                "Input esperado: URL raíz (ej: http://target:8080). Devuelve: Análisis pasivo de "
                "configuración de seguridad (CSP, HSTS, Flags de Cookie)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo completa a rastrear (ej: http://webgoat-target:8080)",
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo",
                        "default": 1,
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -I",
        "timeout": 300,
        "success_exit_codes": [0, 1, 2, 3],
    },
    # =========================================================================
    # 3. OWASP ZAP - API Scan
    # =========================================================================
    "zap_api_scan": {
        "mcp_schema": {
            "name": "zap_api_scan",
            "description": (
                "Escaneo de vulnerabilidades enfocado exclusivamente en endpoints de API REST/GraphQL. "
                "USAR UNICAMENTE CUANDO tengas la URL directa de la documentación OpenAPI/Swagger o "
                "esquema GraphQL (ej: /api-docs/openapi.json). NO usar sobre URLs de páginas HTML o "
                "sitios web navegables. Input esperado: URL del esquema JSON/YAML. Devuelve: Fallos de "
                "seguridad en contratos de API."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schema_url": {
                        "type": "string",
                        "description": "URL directa a la especificación OpenAPI (ej: http://target:3000/api-docs/openapi.json)",
                    },
                    "format": {
                        "type": "string",
                        "description": "Formato del esquema de la API",
                        "enum": ["openapi", "soap", "graphql"],
                        "default": "openapi",
                    },
                },
                "required": ["schema_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        "command_template": "zap-api-scan.py -t {schema_url} -f {format} -I",
        "timeout": 300,
        "success_exit_codes": [0, 1, 2, 3],
    },
    # =========================================================================
    # 4. Katana - Crawling ligero y veloz
    # =========================================================================
    "katana": {
        "mcp_schema": {
            "name": "katana",
            "description": (
                "Crawler/Rastreador ultrarrápido de endpoints. USAR COMO PRIMERA OPCIÓN en la fase de "
                "reconocimiento para mapear toda la superficie de ataque y listar rutas navegables. "
                "Es más ligero y rápido que ZAP. Input esperado: URL raíz del objetivo. Devuelve: "
                "Lista limpia de endpoints y URLs encontradas."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo a rastrear (ej: http://juice-shop-target:3000)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "projectdiscovery/katana:latest",
        "command_template": "-u {target_url} -silent -jc",
        "timeout": 300,
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
                "Input esperado: URL con parámetros o endpoint específico (ej: http://target/rest/user/login). "
                "Devuelve: Confirmación del vector SQLi, tipo de BD y payloads funcionales."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Endpoint o URL a evaluar (ej: http://juice-shop-target:3000/rest/user/login)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "parrotsec/sqlmap:latest",
        "command_template": '-u "{target_url}" --batch --risk=1 --level=1',
        "timeout": 900,
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
        "command_template": './dalfox url "{target_url}" --silence',
        "timeout": 300,
        "success_exit_codes": [0,2],
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
        "timeout": 900,
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
        "timeout": 600,
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
        "timeout": 300,
        "success_exit_codes": [0],
    },
}
