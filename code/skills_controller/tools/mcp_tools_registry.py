# skills_controller/mcp_tools_registry.py

# skills_controller/mcp_tools_registry.py

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
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop-target:3000)"
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo",
                        "default": 1
                    }
                },
                "required": ["target_url"]
            }
        },
        "image": "zaproxy/zap-stable:latest",
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -j -I",
        "timeout": 300
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
                        "description": "URL objetivo completa a rastrear (ej: http://juice-shop-target:3000)"
                    },
                    "minutes": {
                        "type": "integer",
                        "description": "Tiempo máximo en minutos para el escaneo estático",
                        "default": 1
                    }
                },
                "required": ["target_url"]
            }
        },
        "image": "zaproxy/zap-stable:latest",
        # Sin el flag -j para enfocarse únicamente en el motor de spidering tradicional
        "command_template": "zap-baseline.py -t {target_url} -m {minutes} -I",
        "timeout": 300
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
                        "description": "URL de la especificación OpenAPI/Swagger o GraphQL (ej: http://juice-shop-target:3000/api-docs/openapi.json)"
                    },
                    "format": {
                        "type": "string",
                        "description": "Formato de la especificación de API",
                        "enum": ["openapi", "soap", "graphql"],
                        "default": "openapi"
                    }
                },
                "required": ["schema_url"]
            }
        },
        "image": "zaproxy/zap-stable:latest",
        # zap-api-scan.py requiere especificar el formato (-f) y la URL del esquema (-t)
        "command_template": "zap-api-scan.py -t {schema_url} -f {format} -I",
        "timeout": 300
    }
}