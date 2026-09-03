import asyncio
import aio_pika
import json
import logging
import os
from mcp_server import mcp_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
)
logger = logging.getLogger("skills-controller")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq-broker:5672/")
INPUT_QUEUE = "skills_queue"

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
        await channel.set_qos(prefetch_count=1)

        queue = await channel.declare_queue(INPUT_QUEUE, durable=True)
        logger.info(f"🚀 [SKILLS CONTROLLER - MCP SERVER] Escuchando en '{INPUT_QUEUE}'...")

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process():
                    try:
                        payload = json.loads(message.body.decode("utf-8"))
                        method = payload.get("method")
                        correlation_id = message.correlation_id or payload.get("id")
                        reply_to = message.reply_to or "orchestrator_results_queue"

                        logger.info(f"📩 Petición MCP recibida: Método '{method}' | ID: {correlation_id}")

                        if method == "tools/list":
                            mcp_response = mcp_server.list_tools()

                        elif method == "tools/call":
                            params = payload.get("params", {})
                            tool_name = params.get("name")
                            arguments = params.get("arguments", {})

                            logger.info(f"⚡ Ejecutando MCP Tool '{tool_name}'...")
                            mcp_response = await mcp_server.call_tool(tool_name, arguments)

                        else:
                            mcp_response = {
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32601,
                                    "message": f"Método MCP '{method}' no soportado."
                                },
                                "id": correlation_id
                            }

                        mcp_response["id"] = correlation_id

                        await channel.default_exchange.publish(
                            aio_pika.Message(
                                body=json.dumps(mcp_response).encode("utf-8"),
                                correlation_id=correlation_id,
                                content_type="application/json"
                            ),
                            routing_key=reply_to
                        )
                        logger.info(f"✅ Respuesta MCP enviada a '{reply_to}' para ID: {correlation_id}")

                    except Exception as e:
                        logger.error(f"Error procesando el mensaje en Skills Controller: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())