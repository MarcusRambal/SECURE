# app/core/rabbitmq.py (o app/rabbitmq/client.py)
import aio_pika
import json
import logging
import asyncio
from collections.abc import Awaitable, Callable

from aio_pika.abc import AbstractIncomingMessage
from .config import settings

logger = logging.getLogger(__name__)
SCAN_EVENTS_QUEUE = "scan_events_queue"

class RabbitClient:
    def __init__(self):
        self.connection = None
        self.channel = None

    async def connect(self, retries: int = 5, delay: int = 3):
        """Intenta conectar a RabbitMQ con reintentos."""
        for attempt in range(1, retries + 1):
            try:
                logger.info(f"Intentando conectar a RabbitMQ en {settings.RABBITMQ_HOST}:{settings.RABBITMQ_PORT} (Intento {attempt}/{retries})...")
                self.connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
                self.channel = await self.connection.channel()
                
                # Declarar cola de entrada para el Orquestador
                await self.channel.declare_queue("orchestrator_queue", durable=True)
                logger.info("Conectado exitosamente a RabbitMQ. Cola 'orchestrator_queue' lista.")

                await self.channel.declare_queue("skills_queue", durable=True)
                logger.info("Cola 'skills_queue' lista para recibir tareas.")

                await self.channel.declare_queue(SCAN_EVENTS_QUEUE, durable=True)
                logger.info("Cola '%s' lista para recibir eventos.", SCAN_EVENTS_QUEUE)

                return
            except Exception as e:
                logger.warning(f"Fallo al conectar con RabbitMQ ({e}). Reintentando en {delay}s...")
                if attempt == retries:
                    logger.error("No se pudo establecer conexión con RabbitMQ después de varios intentos.")
                    raise e
                await asyncio.sleep(delay)

    async def publish_task_request(self, task_payload: dict):
        if not self.channel or self.channel.is_closed:
            raise RuntimeError("La conexión con RabbitMQ no está activa.")
            
        message_body = json.dumps(task_payload).encode("utf-8")
        
        await self.channel.default_exchange.publish(
            aio_pika.Message(
                body=message_body,
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json"
            ),
            routing_key="orchestrator_queue"
        )
        logger.info(f"[RABBITMQ] Tarea publicada en orchestrator_queue para task_id: {task_payload.get('task_id')}")

    async def consume_scan_events(
        self, handler: Callable[[str, dict], Awaitable[None]]
    ) -> None:
        if not self.channel or self.channel.is_closed:
            raise RuntimeError("La conexión con RabbitMQ no está activa.")

        queue = await self.channel.declare_queue(SCAN_EVENTS_QUEUE, durable=True)

        async def on_message(message: AbstractIncomingMessage) -> None:
            async with message.process(requeue=False):
                try:
                    event = json.loads(message.body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    logger.exception("Evento inválido recibido en '%s'.", SCAN_EVENTS_QUEUE)
                    return

                task_id = event.get("taskId") if isinstance(event, dict) else None
                if not isinstance(task_id, str) or not task_id:
                    logger.error("Evento sin taskId recibido en '%s'.", SCAN_EVENTS_QUEUE)
                    return

                await handler(task_id, event)

        await queue.consume(on_message)
        logger.info("Consumiendo eventos de agentes desde '%s'.", SCAN_EVENTS_QUEUE)

    async def close(self):
        if self.connection and not self.connection.is_closed:
            await self.connection.close()

rabbitmq_client = RabbitClient()