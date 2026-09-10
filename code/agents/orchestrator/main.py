import os
import json
import logging
import asyncio
import aio_pika
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

from tools import recon_agent_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator-main")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
ORCHESTRATOR_QUEUE = "orchestrator_queue"


async def execute_orchestration_flow(payload: dict, channel: aio_pika.Channel):
    task_id = payload.get("task_id")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type", "scan")

    logger.info("============================================================")
    logger.info(f"   [NUEVA TAREA RECIBIDA] ID: {task_id}")
    logger.info(f"   Objetivo: {target_url} | Tipo: {attack_type}")
    logger.info("============================================================")

    tools = [recon_agent_tool]
    logger.info(f"Agentes especializados cargados en LangChain: {[t.name for t in tools]}")

    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        logger.error("GROQ_API_KEY no encontrada en las variables de entorno.")
        return

    llm = ChatGroq(
        model_name="qwen/qwen3.8-27b",
        groq_api_key=groq_api_key,
        temperature=0.1,
        max_tokens=800,
    )

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Orquestador Principal de Ciberseguridad.\n"
            "Tu única responsabilidad es planificar y delegar tareas a tus agentes especializados.\n"
            "Para auditorías de escaneo o reconocimiento, DEBES invocar al 'recon_agent'.\n"
            "Una vez que el agente te devuelva los resultados, consolida la respuesta final para el usuario."
        )
    )

    agent_executor = create_react_agent(model=llm, tools=tools, prompt=system_prompt)

    initial_input = {
        "messages": [
            HumanMessage(
                content=f"Inicia una auditoría de reconocimiento sobre la URL objetivo '{target_url}' delegando en el agente correspondiente."
            )
        ]
    }

    logger.info("[PASO 2] Iniciando razonamiento del agente orquestador...")

    try:
        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 6}):
            for value in event.values():
                last_msg = value["messages"][-1]
                logger.info(f"\n[{last_msg.type.upper()}]:\n{last_msg.content}")

        logger.info(f"Tarea {task_id} procesada exitosamente.\n")

    except Exception as e:
        logger.error(f"Error durante la ejecución del orquestador: {str(e)}", exc_info=True)


async def start_orchestrator_worker():
    while True:
        try:
            logger.info(f"Conectando Orquestador a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                # Declaramos la cola donde la API enviará los trabajos
                queue = await channel.declare_queue(ORCHESTRATOR_QUEUE, durable=True)
                logger.info(f"🎧 Orquestador escuchando activamente en '{ORCHESTRATOR_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            payload = json.loads(message.body.decode("utf-8"))
                            await execute_orchestration_flow(payload, channel)
        except Exception as e:
            logger.warning(f"Error en el Worker del Orquestador ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_orchestrator_worker())
