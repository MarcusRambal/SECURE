import asyncio
import json
import logging
import uuid
import aio_pika
from langchain_core.tools import StructuredTool
from pydantic import create_model, Field

logger = logging.getLogger("orchestrator-tools")
SKILLS_QUEUE = "skills_queue"

async def call_mcp_skill(channel: aio_pika.Channel, tool_name: str, arguments: dict) -> str:
    """
    Publica la solicitud `tools/call` en `skills_queue` y espera la respuesta RPC.
    """
    correlation_id = str(uuid.uuid4())
    
    # 1. Crear cola de respuesta exclusiva
    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                response_data = json.loads(message.body.decode("utf-8"))
                if not future.done():
                    future.set_result(response_data)

    consumer_tag = await reply_queue.consume(on_response)

    # 2. Payload MCP / JSON-RPC
    mcp_payload = {
        "jsonrpc": "2.0",
        "id": correlation_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }

    logger.info(f"📤 [AGENTE -> SKILLS_QUEUE] Invocando tool MCP '{tool_name}'...")

    # 3. Publicación
    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(mcp_payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json"
        ),
        routing_key=SKILLS_QUEUE
    )

    try:
        response = await asyncio.wait_for(future, timeout=360.0)
        content_list = response.get("result", {}).get("content", [])
        if content_list:
            return content_list[0].get("text", "Sin salida.")
        return json.dumps(response)
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


async def get_mcp_catalog(channel: aio_pika.Channel) -> list:
    """Consulta las herramientas disponibles en el Skills Controller (tools/list)."""
    correlation_id = str(uuid.uuid4())
    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                if not future.done():
                    future.set_result(json.loads(message.body.decode("utf-8")))

    consumer_tag = await reply_queue.consume(on_response)

    mcp_payload = {
        "jsonrpc": "2.0",
        "id": correlation_id,
        "method": "tools/list"
    }

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(mcp_payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json"
        ),
        routing_key=SKILLS_QUEUE
    )

    try:
        response = await asyncio.wait_for(future, timeout=60.0)
        return response.get("result", {}).get("tools", [])
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


def build_langchain_tools(mcp_catalog: list, channel: aio_pika.Channel) -> list:
    """
    Convierte el catálogo de herramientas MCP en herramientas nativas de LangChain,
    traduciendo el inputSchema JSON a un modelo de Pydantic dinámico.
    """
    langchain_tools = []

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        description = mcp_tool["description"]
        
        # 1. Extraer propiedades requeridas desde el catálogo MCP
        input_schema = mcp_tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        required_fields = input_schema.get("required", [])

        # 2. Construir los campos para el modelo Pydantic dinámico
        fields = {}
        for prop_name, prop_info in properties.items():
            # Asignar tipo Python según el tipo JSON
            prop_type = str
            if prop_info.get("type") == "integer":
                prop_type = int
            elif prop_info.get("type") == "boolean":
                prop_type = bool

            prop_desc = prop_info.get("description", "")
            
            if prop_name in required_fields:
                fields[prop_name] = (prop_type, Field(..., description=prop_desc))
            else:
                default_val = prop_info.get("default", None)
                fields[prop_name] = (prop_type, Field(default_val, description=prop_desc))

        # 3. Crear la clase Schema dinámicamente
        ArgsSchema = create_model(f"{tool_name}_schema", **fields)

        def make_executor(name):
            async def _executor(**kwargs):
                return await call_mcp_skill(channel, name, kwargs)
            return _executor

        # 4. Registrar la herramienta con su ArgsSchema
        tool_instance = StructuredTool.from_function(
            coroutine=make_executor(tool_name),
            name=tool_name,
            description=description,
            args_schema=ArgsSchema
        )
        langchain_tools.append(tool_instance)

    return langchain_tools