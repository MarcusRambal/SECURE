MCP_SKILLS_REGISTRY = {
    # =========================================================================
    # 1. OWASP ZAP - AJAX Spider (Para aplicaciones SPA / React / Angular)
    # =========================================================================
    "zap_ajax_spider": {
        "mcp_schema": {
            "name": "zap_ajax_spider",
            "description": "Ejecuta un rastreo profundo de aplicaciones SPA/JavaScript usando OWASP ZAP AJAX Spider con navegador headless.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop:3000)",
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo (Recomendado: 1)",
                        "default": 1,
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -j -I",
        "timeout": 600,
    },
    # =========================================================================
    # 2. OWASP ZAP - Baseline Spider (Para rastreo estático rápido y headers)
    # =========================================================================
    "zap_baseline_spider": {
        "mcp_schema": {
            "name": "zap_baseline_spider",
            "description": "Realiza un análisis pasivo y spidering estático rápido para identificar robots.txt, sitemaps, cookies y headers de seguridad.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop-target:3000)",
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo estático",
                        "default": 1,
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        # Sin el flag -j para enfocarse únicamente en el motor de spidering tradicional
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -I",
        "timeout": 300,
    },
    # =========================================================================
    # 3. OWASP ZAP - API Scan (Para OpenAPI / Swagger / GraphQL)
    # =========================================================================
    "zap_api_scan": {
        "mcp_schema": {
            "name": "zap_api_scan",
            "description": "Analiza y rastrea endpoints de API REST o GraphQL usando especificaciones OpenAPI/Swagger o definiciones de esquemas.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schema_url": {
                        "type": "string",
                        "description": "URL de la especificación OpenAPI/Swagger o GraphQL (ej: http://juice-shop-target:3000/api-docs/openapi.json)",
                    },
                    "format": {
                        "type": "string",
                        "description": "Formato de la especificación de API",
                        "enum": ["openapi", "soap", "graphql"],
                        "default": "openapi",
                    },
                },
                "required": ["schema_url"],
            },
        },
        "image": "zaproxy/zap-stable:latest",
        # zap-api-scan.py requiere especificar el formato (-f) y la URL del esquema (-t)
        "command_template": "zap-api-scan.py -t {schema_url} -f {format} -I",
        "timeout": 300,
    },
    # =========================================================================
    # 4. Katana - Crawling y descubrimiento de URLs
    # =========================================================================
    "katana": {
        "mcp_schema": {
            "name": "katana",
            "description": "Rastrea y descubre endpoints y URLs navegables de una aplicación objetivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop-target:3000)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "projectdiscovery/katana:latest",
        "command_template": "-u {target_url} -silent -jc",
        "timeout": 300,
    },
    # =========================================================================
    # 5. SQLMap - Detección y evaluación de Inyección SQL
    # =========================================================================
    "sqlmap": {
        "mcp_schema": {
            "name": "sqlmap",
            "description": "Realiza pruebas de evaluación de inyección SQL sobre un endpoint o URL específica.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u objeto a evaluar (ej: http://juice-shop-target:3000/rest/user/login)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "sqlmapproject/sqlmap:latest",
        "command_template": '-u "{target_url}" --batch --risk=1 --level=1',
        "timeout": 300,
    },
    # =========================================================================
    # 6. DalFox - Detección y verificación de XSS (Cross-Site Scripting)
    # =========================================================================
    "dalfox": {
        "mcp_schema": {
            "name": "dalfox",
            "description": "Escanea y analiza parámetros en busca de vulnerabilidades XSS reflejadas y almacenadas.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u objeto con parámetros a evaluar (ej: http://juice-shop-target:3000/#/search?q=test)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "hahwul/dalfox:latest",
        "command_template": 'url "{target_url}" --silence',
        "timeout": 300,
    },
    # =========================================================================
    # 7. Commix - Detección y explotación de Inyección de Comandos (Command Injection)
    # =========================================================================
    "commix": {
        "mcp_schema": {
            "name": "commix",
            "description": "Prueba y evalúa inyección de comandos del sistema operativo (OS Command Injection).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL u endpoint a analizar (ej: http://webgoat-target:8080/WebGoat/CommandInjection)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "commix/commix:latest",
        "command_template": '--url="{target_url}" --batch',
        "timeout": 300,
    },
    # =========================================================================
    # 8. Nuclei - Escaneo multivectorial (XSS, Auth, SQLi, Command Injection)
    # =========================================================================
    "nuclei": {
        "mcp_schema": {
            "name": "nuclei",
            "description": "Ejecuta plantillas de detección de vulnerabilidades para XSS, Broken Auth, Command Injection o misconfiguraciones.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL o endpoint objetivo a evaluar.",
                    },
                    "tags": {
                        "type": "string",
                        "description": "Etiquetas de vulnerabilidades a probar (ej: xss, rce, sqli, auth, exposure)",
                        "default": "xss,rce,sqli",
                    },
                },
                "required": ["target_url"],
            },
        },
        "image": "projectdiscovery/nuclei:latest",
        "command_template": '-u "{target_url}" -tags {tags} -silent -nc',
        "timeout": 300,
    },
    # =========================================================================
    # 9. FFuF - Fuzzing de endpoints, parámetros y credenciales (Broken Auth)
    # =========================================================================
    "ffuf": {
        "mcp_schema": {
            "name": "ffuf",
            "description": "Realiza fuzzing rápido de URLs, parámetros y formularios de autenticación.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL objetivo con la palabra clave FUZZ (ej: http://juice-shop-target:3000/rest/user/login?email=FUZZ)",
                    }
                },
                "required": ["target_url"],
            },
        },
        "image": "ffuf/ffuf:latest",
        "command_template": '-u "{target_url}" -s',
        "timeout": 300,
    },
}
