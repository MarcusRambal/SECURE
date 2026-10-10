import asyncio
import aio_pika
import json
import logging
import os
from mcp_server import mcp_server

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s")
logger = logging.getLogger("skills-controller")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq-broker:5672/")
INPUT_QUEUE = "skills_queue"
MAX_CONCURRENT_REQUESTS = 3


async def main():
    connection = None

    # Bucle de reintentos hasta que RabbitMQ responda
    while not connection:
        try:
            logger.info(f"Conectando a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            logger.info("⚡ Skills Controller conectado exitosamente a RabbitMQ.")
        except Exception as e:
            logger.warning(f"RabbitMQ no está listo aún ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)

    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=MAX_CONCURRENT_REQUESTS)

        queue = await channel.declare_queue(INPUT_QUEUE, durable=True)
        logger.info(f"🚀 [SKILLS CONTROLLER - MCP SERVER] Escuchando en '{INPUT_QUEUE}'...")

        async def on_message(message: aio_pika.IncomingMessage) -> None:
            async with message.process():
                try:
                    payload = json.loads(message.body.decode("utf-8"))
                    method = payload.get("method")
                    correlation_id = message.correlation_id or payload.get("id")
                    reply_to = message.reply_to or "orchestrator_results_queue"

                    logger.info(
                        "📩 Petición MCP recibida: Método '%s' | ID: %s",
                        method,
                        correlation_id,
                    )

                    if method == "tools/list":
                        mcp_response = mcp_server.list_tools()

                    elif method == "tools/call":
                        params = payload.get("params", {})
                        tool_name = params.get("name")
                        arguments = params.get("arguments", {})

                        logger.info("⚡ Ejecutando MCP Tool '%s'...", tool_name)
                        mcp_response = await mcp_server.call_tool(tool_name, arguments)

                    else:
                        mcp_response = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32601,
                                "message": f"Método MCP '{method}' no soportado.",
                            },
                            "id": correlation_id,
                        }

                    mcp_response["id"] = correlation_id

                    await channel.default_exchange.publish(
                        aio_pika.Message(
                            body=json.dumps(mcp_response).encode("utf-8"),
                            correlation_id=correlation_id,
                            content_type="application/json",
                        ),
                        routing_key=reply_to,
                    )
                    logger.info(
                        "✅ Respuesta MCP enviada a '%s' para ID: %s",
                        reply_to,
                        correlation_id,
                    )

                except Exception:
                    logger.exception("Error procesando mensaje en Skills Controller")

        await queue.consume(on_message)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
