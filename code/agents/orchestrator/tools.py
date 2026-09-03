import asyncio
import json
import logging
import uuid
import aio_pika
from langchain_core.tools import StructuredTool

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
    Convierte el catálogo MCP en objetos StructuredTool de LangChain.
    """
    langchain_tools = []

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        description = mcp_tool["description"]

        def make_executor(name):
            async def _executor(**kwargs):
                return await call_mcp_skill(channel, name, kwargs)
            return _executor

        tool_instance = StructuredTool.from_function(
            coroutine=make_executor(tool_name),
            name=tool_name,
            description=description
        )
        langchain_tools.append(tool_instance)

    return langchain_tools