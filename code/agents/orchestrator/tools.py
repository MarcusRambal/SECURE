import os
import json
import uuid
import asyncio
import logging
import aio_pika
from pydantic import BaseModel, Field
from langchain_core.tools import StructuredTool

logger = logging.getLogger("orchestrator-tools")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
RECON_QUEUE = "recon_queue"


class ReconAgentInput(BaseModel):
    target_url: str = Field(description="URL objetivo para la fase de reconocimiento.")


async def call_recon_agent(target_url: str) -> str:
    """Llama al microservicio del Agente de Reconocimiento vía RabbitMQ (RPC)."""
    logger.info(
        f"📤 [ORQUESTADOR -> RECON-AGENT VIA RABBITMQ] Delegando escaneo de {target_url}..."
    )

    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        reply_queue = await channel.declare_queue(exclusive=True)
        correlation_id = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()

        async def on_response(message: aio_pika.IncomingMessage):
            async with message.process():
                if message.correlation_id == correlation_id:
                    if not future.done():
                        future.set_result(json.loads(message.body.decode("utf-8")))

        consumer_tag = await reply_queue.consume(on_response)

        payload = {"target_url": target_url}

        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps(payload).encode("utf-8"),
                correlation_id=correlation_id,
                reply_to=reply_queue.name,
                content_type="application/json",
            ),
            routing_key=RECON_QUEUE,
        )

        try:
            response = await asyncio.wait_for(future, timeout=600.0)
            return response.get("summary", "No se obtuvo respuesta del recon-agent.")
        except asyncio.TimeoutError:
            return "Error: El Recon-Agent excedió el tiempo límite de ejecución en RabbitMQ."
        finally:
            await reply_queue.cancel(consumer_tag)
            await reply_queue.delete(if_unused=False, if_empty=False)


recon_agent_tool = StructuredTool.from_function(
    coroutine=call_recon_agent,
    name="recon_agent",
    description="Delega la fase de reconocimiento al Agente de Reconocimiento vía RabbitMQ.",
    args_schema=ReconAgentInput,
)
