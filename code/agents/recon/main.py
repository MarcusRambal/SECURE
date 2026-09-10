import os
import re
import json
import uuid
import asyncio
import logging
import aio_pika

from pydantic import create_model, Field
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-agent-worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
SKILLS_QUEUE = "skills_queue"
RECON_QUEUE = "recon_queue"


def parse_and_filter_endpoints(raw_text: str) -> str:
    if not raw_text:
        return "No se encontraron resultados en la herramienta."
    urls_found = re.findall(r'https?://[^\s><")]+', raw_text)
    unique_urls = list(dict.fromkeys(urls_found))
    if unique_urls:
        formatted_list = "\n".join([f"- {url}" for url in unique_urls[:50]])
        return f"Endpoints y rutas descubiertas ({len(unique_urls)} en total):\n{formatted_list}"
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    return "\n".join(lines[:15])


async def call_mcp_skill(channel: aio_pika.Channel, tool_name: str, arguments: dict) -> str:
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
        response = await asyncio.wait_for(future, timeout=600.0)
        content = response.get("result", {}).get("content", [])
        raw_output = content[0].get("text", "") if content else json.dumps(response)
        await asyncio.sleep(20)
        return parse_and_filter_endpoints(raw_output)
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


async def get_mcp_catalog(channel: aio_pika.Channel) -> list:
    correlation_id = str(uuid.uuid4())
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
        return response.get("result", {}).get("tools", [])
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


def build_recon_tools(mcp_catalog: list, channel: aio_pika.Channel) -> list:
    langchain_tools = []
    recon_keywords = ["katana", "zap", "spider", "nikto"]

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        if not any(kw in tool_name.lower() for kw in recon_keywords):
            continue

        description = mcp_tool["description"]
        input_schema = mcp_tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        required_fields = input_schema.get("required", [])

        fields = {}
        for prop_name, prop_info in properties.items():
            prop_type = int if prop_info.get("type") == "integer" else str
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

    return langchain_tools


async def process_recon_task(channel: aio_pika.Channel, target_url: str) -> str:
    catalog = await get_mcp_catalog(channel)
    tools = build_recon_tools(catalog, channel)
    if not tools:
        return "No hay herramientas MCP de recon disponibles."

    groq_api_key = os.getenv("GROQ_API_KEY")
    llm = ChatGroq(
        model_name="qwen/qwen3.8-27b", groq_api_key=groq_api_key, temperature=0.1, max_tokens=800
    )

    system_prompt = SystemMessage(
        content=(
            "Eres un Especialista en Reconocimiento de Aplicaciones Web.\n"
            "Tu objetivo es descubrir los endpoints principales del objetivo usando las herramientas MCP disponibles.\n\n"
            "REGLAS DE OPERACIÓN:\n"
            "1. Puedes ejecutar **hasta dos herramientas como máximo**.\n"
            "2. Prioriza primero una herramienta de descubrimiento (por ejemplo, 'katana' o 'zap_ajax_spider').\n"
            "3. Si lo consideras necesario, puedes ejecutar una segunda herramienta complementaria (por ejemplo, 'zap_baseline_spider').\n"
            "4. Después de obtener los resultados de las herramientas, **NO ejecutes más herramientas**.\n"
            "5. Genera inmediatamente un resumen final en texto claro con las URLs/endpoints descubiertos y finaliza la tarea.\n\n"
            "IMPORTANTE: Evita ejecutar más de dos herramientas o repetir llamadas. El resumen final debe ser conciso y basado en los resultados obtenidos."
        )
    )

    agent_executor = create_react_agent(model=llm, tools=tools, prompt=system_prompt)
    initial_input = {
        "messages": [HumanMessage(content=f"Analiza la superficie del objetivo '{target_url}'.")]
    }

    recon_output = ""
    async for event in agent_executor.astream(initial_input, config={"recursion_limit": 12}):
        for value in event.values():
            last_msg = value["messages"][-1]
            if last_msg.type == "ai" and not getattr(last_msg, "tool_calls", None):
                recon_output = last_msg.content

    return recon_output


async def start_recon_worker():
    while True:
        try:
            logger.info(f"Conectando Recon-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(RECON_QUEUE, durable=True)
                logger.info(f"🎧 Recon-Agent escuchando en la cola '{RECON_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            payload = json.loads(message.body.decode("utf-8"))
                            target_url = payload.get("target_url")
                            logger.info(f"📥 [RECON-AGENT] Tarea recibida para {target_url}")

                            summary = await process_recon_task(channel, target_url)

                            if message.reply_to:
                                response_body = json.dumps(
                                    {"status": "SUCCESS", "summary": summary}
                                )
                                await channel.default_exchange.publish(
                                    aio_pika.Message(
                                        body=response_body.encode("utf-8"),
                                        correlation_id=message.correlation_id,
                                        content_type="application/json",
                                    ),
                                    routing_key=message.reply_to,
                                )
        except Exception as e:
            logger.warning(f"Error en Recon Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_recon_worker())
