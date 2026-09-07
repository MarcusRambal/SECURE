# skills_controller/mcp_server.py
import json
import logging
from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY
from docker_runner import docker_runner

logger = logging.getLogger(__name__)

class SkillsMCPServer:
    
    def list_tools(self) -> dict:
        """Responde a la solicitud MCP `tools/list` entregando el catálogo de herramientas."""
        tools_list = [skill["mcp_schema"] for skill in MCP_SKILLS_REGISTRY.values()]
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": tools_list
            }
        }

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Responde a la solicitud MCP `tools/call` ejecutando el contenedor efímero correspondiente."""
        if tool_name not in MCP_SKILLS_REGISTRY:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Herramienta MCP '{tool_name}' no encontrada."}
            }

        tool_config = MCP_SKILLS_REGISTRY[tool_name]
        
        # Clonar diccionario de argumentos para evitar modificar el original
        merged_args = dict(arguments) if arguments else {}

        # 1. Rellenar automáticamente con los valores predeterminados del schema si existen
        schema_props = tool_config.get("mcp_schema", {}).get("inputSchema", {}).get("properties", {})
        for prop_name, prop_spec in schema_props.items():
            if prop_name not in merged_args and "default" in prop_spec:
                merged_args[prop_name] = prop_spec["default"]

        # 2. Formatear la plantilla de comando
        try:
            formatted_args = tool_config["command_template"].format(**merged_args)
        except KeyError as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": f"Falta argumento requerido para el comando: {str(e)}"}
            }

        logger.info(f"🛠️ [MCP Call] Ejecutando: {tool_name} con comando: {formatted_args}")

        # 3. Invocación del contenedor efímero a través de la Engine API
        result = await docker_runner.execute_tool(
            image=tool_config["image"],
            command=formatted_args,
            timeout=tool_config["timeout"]
        )

        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": result["output"]
                    }
                ],
                "isError": result["status"] != "SUCCESS"
            }
        }

mcp_server = SkillsMCPServer()