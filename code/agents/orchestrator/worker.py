import asyncio
import json
import logging
import os
import sys
import aio_pika

# Importamos la función de ejecución desde main.py
from main import execute_orchestration_flow

# Configuración de logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
)
logger = logging.getLogger("orchestrator-worker")

# Variables de entorno
RABBITMQ_URL = os.getenv(
    "RABBITMQ_URL", 
    "amqp://guest:guest@rabbitmq-broker:5672/"
)
QUEUE_NAME = "orchestrator_queue"


async def start_worker():
    """Conecta a RabbitMQ y escucha activamente la cola orchestrator_queue."""
    connection = None

    while not connection:
        try:
            logger.info(f"Conectando Orquestador a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            logger.info("⚡ Orquestador conectado exitosamente a RabbitMQ.")
        except Exception as e:
            logger.warning(f"RabbitMQ no disponible aún ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)

    async with connection:
        channel = await connection.channel()

        # Prefetch = 1 para procesar una tarea a la vez
        await channel.set_qos(prefetch_count=1)

        # Declaración idempotente de la cola principal
        queue = await channel.declare_queue(QUEUE_NAME, durable=True)

        logger.info(f"🎧 Escuchando activamente eventos en la cola '{QUEUE_NAME}'...")

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process():
                    try:
                        # Decodificar el mensaje JSON recibido
                        payload = json.loads(message.body.decode("utf-8"))
                        # Delegar el flujo de ejecución a main.py
                        await execute_orchestration_flow(payload, channel)
                    except Exception as e:
                        logger.error(f"Error procesando el mensaje: {str(e)}", exc_info=True)


if __name__ == "__main__":
    try:
        asyncio.run(start_worker())
    except KeyboardInterrupt:
        logger.info("Worker del Orquestador detenido por el usuario.")
        sys.exit(0)