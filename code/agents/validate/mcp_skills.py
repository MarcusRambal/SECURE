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



# ============================================================================
# Catálogo MCP + builder de herramientas LangChain (heredado de David)
# ============================================================================

async def get_mcp_catalog(channel) -> list:
    """Obtiene el catálogo de herramientas activas en el servidor MCP."""
    import uuid
    import json
    import asyncio
    import aio_pika
    from config import SKILLS_QUEUE

    correlation_id = str(uuid.uuid4())
    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id and not future.done():
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
        return response.get("result", {}).get("tools", [])
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


def build_validation_tools(
    mcp_catalog: list,
    channel,
    attack_type: str,
    excluded_tools: set[str] | None = None,
) -> list:
    """Construye herramientas LangChain orientadas al attack_type + submit tool."""
    from langchain_core.tools import StructuredTool
    from pydantic import Field, create_model
    from config import TOOL_MAP
    from contract_schemas import ValidateSubmission

    langchain_tools = []
    allowed_tools = TOOL_MAP.get(attack_type, TOOL_MAP.get("full", []))
    excluded_tools = excluded_tools or set()

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        if tool_name not in allowed_tools or tool_name in excluded_tools:
            continue

        description = mcp_tool.get("description", "")
        input_schema = mcp_tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        required_fields = input_schema.get("required", [])

        fields = {}
        for prop_name, prop_info in properties.items():
            prop_type = {
                "integer": int,
                "object": dict,
                "array": list,
                "boolean": bool,
            }.get(prop_info.get("type"), str)
            prop_desc = prop_info.get("description", "")
            if prop_name in required_fields:
                fields[prop_name] = (prop_type, Field(..., description=prop_desc))
            else:
                fields[prop_name] = (
                    prop_type,
                    Field(prop_info.get("default", None), description=prop_desc),
                )

        ArgsSchema = create_model(f"{tool_name}_schema", **fields)

        def make_executor(name):
            async def _executor(**kwargs):
                return await call_mcp_skill(channel, name, kwargs)
            return _executor

        tool_instance = StructuredTool.from_function(
            coroutine=make_executor(tool_name),
            name=tool_name,
            description=description,
            args_schema=ArgsSchema,
        )
        langchain_tools.append(tool_instance)

    def submit_validate_output(**kwargs) -> str:
        submission = ValidateSubmission.model_validate(kwargs)
        return f"Hallazgos recibidos: {len(submission.vulnerabilities)}"

    langchain_tools.append(
        StructuredTool.from_function(
            func=submit_validate_output,
            name="submit_validate_output",
            description="Entrega los hallazgos de validación estructurados al sistema.",
            args_schema=ValidateSubmission,
        )
    )
    return langchain_tools