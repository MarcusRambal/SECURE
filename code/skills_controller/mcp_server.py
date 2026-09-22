import json
import logging
from docker_runner import docker_runner
from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY

logger = logging.getLogger(__name__)

class SkillsMCPServer:

    def list_tools(self) -> dict:
        logger.info("📋 [MCP list_tools] Solicitando lista de herramientas...")
        tools_list = [skill["mcp_schema"] for skill in MCP_SKILLS_REGISTRY.values()]
        return {"jsonrpc": "2.0", "result": {"tools": tools_list}}

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        logger.info(f"📥 [MCP call_tool] Petición recibida para la herramienta: '{tool_name}'")

        if tool_name not in MCP_SKILLS_REGISTRY:
            logger.error(f"❌ [MCP call_tool] Herramienta '{tool_name}' no encontrada.")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Herramienta MCP '{tool_name}' no encontrada."},
            }

        tool_config = MCP_SKILLS_REGISTRY[tool_name]
        merged_args = dict(arguments) if arguments else {}
        input_files = {}

        # 1. Si la herramienta define un handler/preparador especial, lo invocamos
        prepare_fn = tool_config.get("prepare_args")
        if prepare_fn:
            merged_args, input_files = prepare_fn(merged_args)

        # 2. Aplicar valores por defecto declarados en el esquema MCP
        schema_props = tool_config.get("mcp_schema", {}).get("inputSchema", {}).get("properties", {})
        for prop_name, prop_spec in schema_props.items():
            if prop_name not in merged_args and "default" in prop_spec:
                merged_args[prop_name] = prop_spec["default"]

        # 3. Fallback de plantilla (-r vs -u)
        template = tool_config["command_template"]
        if "{req_file_path}" in template and not merged_args.get("req_file_path"):
            if not merged_args.get("target_url"):
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Se requiere 'req_file_path' o 'target_url'.",
                    },
                }
            template = template.replace('-r "{req_file_path}"', '-u "{target_url}"')

        # 4. Formatear comando y ejecutar
        try:
            formatted_args = template.format(**merged_args)
        except KeyError as e:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32602,
                    "message": f"Falta argumento requerido para el comando: {str(e)}",
                },
            }

        logger.info(f"🛠️ [MCP Call] Ejecutando: {tool_name} | Comando: {formatted_args}")

        timeout = merged_args.get("timeout", tool_config["timeout"])

        result = await docker_runner.execute_tool(
            image=tool_config["image"],
            command=formatted_args,
            timeout=timeout,
            success_exit_codes=tool_config.get("success_exit_codes", [0]),
            input_files=input_files,
        )

        is_error = result.get("status") != "SUCCESS"

        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": result.get("output", "")}],
                "isError": is_error,
            },
        }

mcp_server = SkillsMCPServer()