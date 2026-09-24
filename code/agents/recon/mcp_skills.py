import asyncio
import json
import logging
import uuid

import aio_pika

from helpers import log_preview

from config import SKILLS_QUEUE

logger = logging.getLogger("recon-agent-worker")


async def call_mcp_skill(channel: aio_pika.Channel, tool_name: str,arguments: dict,) -> str:
    """Invoca una herramienta MCP en skills_controller a través de RabbitMQ."""
    correlation_id = str(uuid.uuid4())
    logger.info("[MCP RECON] Publicando tool=%s correlation_id=%s arguments=%s",tool_name,correlation_id,log_preview(arguments),)

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
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(mcp_payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
        ),
        routing_key=SKILLS_QUEUE,
    )

    try:
        response = await asyncio.wait_for(future, timeout=1000.0)

        logger.info("[MCP RECON] Respuesta recibida tool=%s correlation_id=%s is_error=%s",tool_name,correlation_id,response.get("result", {}).get("isError", False),)

        is_error = response.get("result", {}).get("isError", False)
        content = response.get("result", {}).get("content", [])
        raw_output = content[0].get("text", "") if content else json.dumps(response)

        logger.info("[MCP RECON] RAW INFO: %s", raw_output)

        if is_error:
            raise RuntimeError(f"MCP tool '{tool_name}' failed: {raw_output}")
        await asyncio.sleep(2)


        return raw_output
    except Exception:
        logger.exception("[MCP RECON] Error esperando respuesta tool=%s correlation_id=%s", tool_name, correlation_id)
        raise
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


async def get_mcp_catalog(channel: aio_pika.Channel) -> list:
    """Consulta las herramientas MCP registradas en skills_controller."""
    correlation_id = str(uuid.uuid4())

    logger.info("[MCP RECON] Solicitando catálogo correlation_id=%s", correlation_id)

    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                if not future.done():
                    future.set_result(json.loads(message.body.decode("utf-8")))

    consumer_tag = await reply_queue.consume(on_response)

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(
                {"jsonrpc": "2.0", "id": correlation_id, "method": "tools/list"}
            ).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
        ),
        routing_key=SKILLS_QUEUE,
    )

    try:
        response = await asyncio.wait_for(future, timeout=30.0)
        tools = response.get("result", {}).get("tools", [])
        logger.info( "[MCP RECON] Catálogo recibido correlation_id=%s tools=%d names=%s",correlation_id,len(tools),[tool.get("name") for tool in tools],)

        return tools
    except Exception:
        logger.exception("[MCP RECON] Error obteniendo catálogo correlation_id=%s", correlation_id)
        raise
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)
        