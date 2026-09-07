# app/core/rabbitmq.py (o app/rabbitmq/client.py)
import aio_pika
import json
import logging
import asyncio
from .config import settings

logger = logging.getLogger(__name__)

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

    async def close(self):
        if self.connection and not self.connection.is_closed:
            await self.connection.close()

rabbitmq_client = RabbitClient()