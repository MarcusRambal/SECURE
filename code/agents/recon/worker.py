
import asyncio
import json
import logging
import os

import aio_pika

from main import process_recon_task

logger = logging.getLogger("recon-agent-worker")
RABBITMQ_URL = os.getenv("RABBITMQ_URL")
RECON_QUEUE = "recon_queue"


# ============================================================================
# WORKER
# ============================================================================

async def start_recon_worker():
    """Worker asíncrono que escucha solicitudes en recon_queue y responde con ReconOutput JSON."""
    while True:
        try:
            logger.info(f"Conectando Recon-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(RECON_QUEUE, durable=True)
                logger.info(f"🎧 Recon-Agent escuchando activamente en '{RECON_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to

                            try:
                                payload = json.loads(message.body.decode("utf-8"))
                                target_url = payload.get("target_url")
                                attack_type_filter = payload.get("attack_type", "full")
                                logger.info(f"📥 [RECON-AGENT] Tarea recibida para {target_url}")

                                recon_data, recovery_mode = await process_recon_task(
                                    channel,
                                    target_url,
                                    attack_type_filter,
                                )

                                status = "SUCCESS"
                                used_fallback = False

                                response_body = json.dumps(
                                    {
                                        "status": status,
                                        "used_fallback": used_fallback,
                                        "recovery_mode": recovery_mode,
                                        "recon_data": recon_data.model_dump(),
                                    }
                                )
                            except Exception as msg_error:
                                logger.error(
                                    f"❌ Error procesando mensaje Recon: {msg_error}",
                                    exc_info=True,
                                )
                                response_body = json.dumps(
                                    {
                                        "status": "ERROR",
                                        "error": str(msg_error),
                                    }
                                )

                            if reply_to:
                                try:
                                    await channel.default_exchange.publish(
                                        aio_pika.Message(
                                            body=response_body.encode("utf-8"),
                                            correlation_id=correlation_id,
                                            content_type="application/json",
                                        ),
                                        routing_key=reply_to,
                                    )
                                    logger.info(
                                        f"📤 [RECON-AGENT] Respuesta enviada a '{reply_to}'"
                                    )
                                except Exception as pub_error:
                                    logger.error(
                                        f"❌ No se pudo publicar respuesta RPC: {pub_error}"
                                    )
        except Exception as e:
            logger.warning(f"Error en Recon Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_recon_worker())