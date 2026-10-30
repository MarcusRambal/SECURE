import asyncio
import json
import logging
import time

import aio_pika

from config import LOG_RPC_PAYLOADS, RABBITMQ_URL, VALIDATE_QUEUE
from contract_schemas import ValidateOutput
from main import process_validate_task
from output_guard import guard_validate_output

logger = logging.getLogger("validate-agent-worker")


async def start_validate_worker():
    """Worker asíncrono que procesa solicitudes en validate_queue."""
    while True:
        try:
            logger.info(f"Conectando Validate-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(VALIDATE_QUEUE, durable=True)
                logger.info(f"🎧 Validate-Agent escuchando activamente en '{VALIDATE_QUEUE}'...")
                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to
                            processing_started = time.perf_counter()
                            published_at = (message.headers or {}).get("x-published-at")

                            try:
                                payload = json.loads(message.body.decode("utf-8"))

                                target_url = payload.get("target_url")
                                attack_type = payload.get("attack_type")
                                token = payload.get("token")  # None para ataques sin token
                                task_id = payload.get("task_id") or correlation_id

                                recon_data = payload.get("recon_data", {})
                                
                                raw_targets = recon_data.get("high_priority_targets", [])

                                simplified_targets = []
                                for item in raw_targets:
                                    simplified_targets.append({
                                        "target_id": item.get("target_id"),
                                        "request_id": item.get("request_id"),
                                        "endpoint": item.get("endpoint"),
                                        "method": item.get("method"),
                                        "recommended_tool": item.get("recommended_tool"),
                                        "request": item.get("request", {})  # Petición estructurada para SQLMap/Skills
                                    })

                                logger.info(
                                    f"📥 [VALIDATE-AGENT] Tarea de validación recibida para {target_url} "
                                    f"con {len(simplified_targets)} objetivo(s) prioritario(s)."
                                )


                                if LOG_RPC_PAYLOADS:
                                    logger.info(
                                        "[VALIDATE] Payload RPC completo recibido: %s",
                                        json.dumps(
                                            payload,
                                            ensure_ascii=False,
                                            indent=2,
                                            default=str,
                                        ),
                                    )

                                logger.info(
                                    "[VALIDATE-AGENT] task_id=%s target_url=%s",
                                    task_id,
                                    target_url,
                                )

                                validate_data, recovery_mode, tool_timings = await process_validate_task(
                                    channel,
                                    target_url,
                                    attack_type,
                                    simplified_targets,
                                    token=token,
                                    task_id=task_id,
                                )
                                guarded_output, duplicates_removed = guard_validate_output(
                                    validate_data.model_dump()
                                )
                                validate_data = ValidateOutput.model_validate(
                                    guarded_output
                                )
                                if duplicates_removed:
                                    logger.info(
                                        "[VALIDATE] task_id=%s output_guard "
                                        "duplicate_findings_removed=%d",
                                        task_id,
                                        duplicates_removed,
                                    )

                                if recovery_mode == "fallback":
                                    status = "PARTIAL"
                                    used_fallback = True
                                else:
                                    status = "SUCCESS"
                                    used_fallback = False

                                response_payload = {
                                    "status": status,
                                    "used_fallback": used_fallback,
                                    "recovery_mode": recovery_mode,
                                    "validation_data": validate_data.model_dump(),
                                    "tool_timings": tool_timings,
                                }
                            except Exception as msg_error:
                                logger.error(
                                    f"❌ Error procesando mensaje Validate: {msg_error}",
                                    exc_info=True,
                                )
                                response_payload = {
                                    "status": "ERROR",
                                    "error": str(msg_error),
                                }

                            response_payload["timing"] = {
                                "queueWaitMs": round(
                                    max(0, time.time() - published_at) * 1000, 2
                                )
                                if isinstance(published_at, (int, float))
                                else None,
                                "processingMs": round(
                                    (time.perf_counter() - processing_started) * 1000, 2
                                ),
                            }
                            response_body = json.dumps(response_payload)
                            if LOG_RPC_PAYLOADS:
                                logger.info(
                                    "[VALIDATE -> ORQUESTADOR] Respuesta RPC completa: %s",
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
                                            body=response_body.encode("utf-8"),
                                            correlation_id=correlation_id,
                                            content_type="application/json",
                                        ),
                                        routing_key=reply_to,
                                    )
                                    logger.info(
                                        f"📤 [VALIDATE-AGENT] Respuesta enviada a '{reply_to}'"
                                    )
                                except Exception as pub_error:
                                    logger.error(
                                        f"❌ No se pudo publicar respuesta RPC: {pub_error}"
                                    )
        except Exception as e:
            logger.warning(f"Error en Validate Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_validate_worker())