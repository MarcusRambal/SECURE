import aio_pika
import json
import logging
import asyncio
from app.core.config import settings

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
                return
            except Exception as e:
                logger.warning(f"Fallo al conectar con RabbitMQ ({e}). Reintentando en {delay}s...")
                if attempt == retries:
                    logger.error("No se pudo establecer conexión con RabbitMQ después de varios intentos.")
                    raise e
                await asyncio.sleep(delay)

    async def publish_scan_request(self, scan_data: dict):
        if not self.channel:
            raise RuntimeError("La conexión con RabbitMQ no está activa.")
            
        message_body = json.dumps(scan_data).encode("utf-8")
        
        await self.channel.default_exchange.publish(
            aio_pika.Message(
                body=message_body,
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
            ),
            routing_key="orchestrator_queue"
        )
        logger.info(f"Mensaje publicado en orchestrator_queue para scan_id: {scan_data.get('scan_id')}")

    async def close(self):
        if self.connection:
            await self.connection.close()

rabbitmq_client = RabbitClient()