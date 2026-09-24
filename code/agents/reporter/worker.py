import asyncio
import json
import logging

import aio_pika

from config import LOG_RPC_PAYLOADS, RABBITMQ_URL, REPORTER_QUEUE
from main import process_report_task

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reporter-agent-worker")


async def start_reporter_worker():
    """Worker asíncrono que procesa solicitudes en reporter_queue."""
    while True:
        try:
            logger.info("Conectando Reporter-Agent a RabbitMQ en %s...", RABBITMQ_URL)
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(REPORTER_QUEUE, durable=True)
                logger.info("Reporter-Agent escuchando activamente en '%s'...", REPORTER_QUEUE)

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to

                            try:
                                payload = json.loads(message.body.decode("utf-8"))
                                logger.info(
                                    "[REPORTER-AGENT] Generando informe para tarea %s",
                                    payload.get("task_id"),
                                )
                                if LOG_RPC_PAYLOADS:
                                    logger.info(
                                        "[REPORTER] Payload RPC completo recibido: %s",
                                        json.dumps(
                                            payload,
                                            ensure_ascii=False,
                                            indent=2,
                                            default=str,
                                        ),
                                    )

                                report_markdown, used_fallback = await process_report_task(payload)
                                response_payload = {
                                    "status": "PARTIAL" if used_fallback else "SUCCESS",
                                    "used_fallback": used_fallback,
                                    "report_markdown": report_markdown,
                                }
                            except Exception as message_error:
                                logger.error(
                                    "Error procesando mensaje Reporter: %s",
                                    message_error,
                                    exc_info=True,
                                )
                                response_payload = {
                                    "status": "ERROR",
                                    "error": str(message_error),
                                }

                            if LOG_RPC_PAYLOADS:
                                logger.info(
                                    "[REPORTER -> ORQUESTADOR] Respuesta RPC completa: %s",
                                    json.dumps(
                                        response_payload,
                                        ensure_ascii=False,
                                        indent=2,
                                        default=str,
                                    ),
                                )

                            if reply_to:
                                try:
                                    await channel.default_exchange.publish(
                                        aio_pika.Message(
                                            body=json.dumps(response_payload).encode("utf-8"),
                                            correlation_id=correlation_id,
                                            content_type="application/json",
                                        ),
                                        routing_key=reply_to,
                                    )
                                    logger.info(
                                        "[REPORTER-AGENT] Respuesta enviada a '%s'", reply_to
                                    )
                                except Exception as publish_error:
                                    logger.error(
                                        "No se pudo publicar respuesta RPC: %s", publish_error
                                    )
        except Exception as error:
            logger.warning("Error en Reporter Worker (%s). Reintentando en 3s...", error)
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_reporter_worker())
