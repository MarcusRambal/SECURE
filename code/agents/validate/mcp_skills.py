import asyncio
import json
import time
import uuid

import aio_pika

from config import SKILLS_QUEUE


async def call_mcp_skill(
    channel: aio_pika.Channel,
    tool_name: str,
    arguments: dict,
    timings: list[dict] | None = None,
) -> str:
    """Invoca una herramienta de validación MCP a través de RabbitMQ."""
    correlation_id = str(uuid.uuid4())
    started_at = time.perf_counter()
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

    publish_started = time.perf_counter()
    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(mcp_payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
            headers={"x-published-at": time.time()},
        ),
        routing_key=SKILLS_QUEUE,
    )
    publish_ms = round((time.perf_counter() - publish_started) * 1000, 2)

    try:
        response = await asyncio.wait_for(future, timeout=1000.0)
        if timings is not None:
            timings.append(
                {
                    "tool": tool_name,
                    **(response.get("timing") or {}),
                    "publishMs": publish_ms,
                    "roundTripMs": round((time.perf_counter() - started_at) * 1000, 2),
                }
            )
        content = response.get("result", {}).get("content", [])
        raw_output = content[0].get("text", "") if content else json.dumps(response)
        return raw_output
    except asyncio.TimeoutError:
        if timings is not None:
            timings.append(
                {
                    "tool": tool_name,
                    "publishMs": publish_ms,
                    "roundTripMs": round((time.perf_counter() - started_at) * 1000, 2),
                    "status": "TIMEOUT",
                }
            )
        raise
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)
