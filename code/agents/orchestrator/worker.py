import asyncio
import json
import logging
import os
import sys
import aio_pika

# Configuración de logs para ver la actividad en Docker
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
)
logger = logging.getLogger("orchestrator-worker")

# Variables de entorno inyectadas por Docker
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq-broker")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")

RABBITMQ_URL = f"amqp://{RABBITMQ_USER}:{RABBITMQ_PASS}@{RABBITMQ_HOST}:{RABBITMQ_PORT}/"
QUEUE_NAME = "orchestrator_queue"


async def process_task(payload: dict):
    """
    Aquí es donde el Orquestador toma el mando:
    1. Lee task_id, target_url, attack_type.
    2. Define la estrategia (ej. invocar agentes con LangChain/LangGraph/MCP).
    """
    task_id = payload.get("task_id")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type")

    logger.info(f"📥 [NUEVA TAREA] ID: {task_id} | Objetivo: {target_url} | Tipo: {attack_type}")

    # --- SIMULACIÓN DEL TRABAJO DEL AGENTE ORQUESTADOR ---
    await asyncio.sleep(3) 

    logger.info(f"✅ [TAREA COMPLETADA] Orquestación inicial finalizada para {task_id}")


async def start_worker():
    """Conecta a RabbitMQ y consume mensajes continuamente."""
    connection = None
    
    # Reintentos de conexión por si el broker tarda en estar ready
    while not connection:
        try:
            logger.info(f"Conectando Worker a RabbitMQ en {RABBITMQ_HOST}:{RABBITMQ_PORT}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            logger.info("⚡ Worker conectado exitosamente a RabbitMQ.")
        except Exception as e:
            logger.warning(f"RabbitMQ no disponible aún ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)

    async with connection:
        channel = await connection.channel()

        # 1. Definir Prefetch: Máximo 1 mensaje simultáneo por worker
        await channel.set_qos(prefetch_count=1)

        # 2. Asegurar que la cola existe (durable=True)
        queue = await channel.declare_queue(QUEUE_NAME, durable=True)

        logger.info(f"🎧 Escuchando eventos en la cola '{QUEUE_NAME}'...")

        # 3. Consumir mensajes con confirmación automática al finalizar el bloque context
        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                # message.process() maneja automáticamente el ACK (si fue exitoso) o NACK (si hubo error)
                async with message.process():
                    try:
                        payload = json.loads(message.body.decode("utf-8"))
                        await process_task(payload)
                    except Exception as e:
                        logger.error(f"Error procesando la tarea: {str(e)}")


if __name__ == "__main__":
    try:
        asyncio.run(start_worker())
    except KeyboardInterrupt:
        logger.info("Worker detenido por el usuario.")
        sys.exit(0)