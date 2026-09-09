import os
import json
import logging
import asyncio
import aio_pika
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

from tools import recon_agent_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator-main")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://marcus:CampanaPlateada1902@rabbitmq-broker:5672/")
ORCHESTRATOR_QUEUE = "orchestrator_queue"

TASKS_RESULTS_DB = {}

# Worker de RabbitMQ integrado
async def start_rabbitmq_consumer():
    while True:
        try:
            logger.info(f"Conectando Orquestador a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(ORCHESTRATOR_QUEUE, durable=True)
                logger.info(f"🎧 Orquestador escuchando en '{ORCHESTRATOR_QUEUE}'...")
                
                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            payload = json.loads(message.body.decode("utf-8"))
                            await execute_orchestration_flow(payload)
        except Exception as e:
            logger.warning(f"RabbitMQ no disponible aún ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Arranca la escucha de eventos en segundo plano junto con la API
    consumer_task = asyncio.create_task(start_rabbitmq_consumer())
    yield
    consumer_task.cancel()

app = FastAPI(title="SECURE - Orchestrator Main", lifespan=lifespan)

@app.get("/api/task/{task_id}")
async def get_task_result(task_id: str):
    if task_id not in TASKS_RESULTS_DB:
        return {
            "task_id": task_id,
            "status": "PROCESSING",
            "message": "La tarea sigue en ejecución..."
        }
    return TASKS_RESULTS_DB[task_id]

async def execute_orchestration_flow(payload: dict):
    task_id = payload.get("task_id")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type", "scan")

    logger.info("============================================================")
    logger.info(f"   [NUEVA TAREA RECIBIDA] ID: {task_id}")
    logger.info(f"   Objetivo: {target_url} | Tipo: {attack_type}")
    logger.info("============================================================")

    TASKS_RESULTS_DB[task_id] = {
        "task_id": task_id,
        "status": "PROCESSING",
        "target_url": target_url
    }

    tools = [recon_agent_tool]
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        logger.error("GROQ_API_KEY no encontrada.")
        TASKS_RESULTS_DB[task_id] = {
            "task_id": task_id,
            "status": "FAILED",
            "error": "GROQ_API_KEY faltante"
        }
        return

    llm = ChatGroq(
        model_name="qwen/qwen3.8-27b",
        groq_api_key=groq_api_key,
        temperature=0.1,
        max_tokens=800
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

    try:
        final_summary = ""
        global_traceability = []

        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 6}):
            for value in event.values():
                last_msg = value["messages"][-1]
                logger.info(f"\n[{last_msg.type.upper()}]:\n{last_msg.content}")

                if getattr(last_msg, "tool_calls", None):
                    for tool in last_msg.tool_calls:
                        global_traceability.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "agent": "orchestrator",
                            "action": f"Delegando tarea a '{tool['name']}'",
                            "arguments": tool["args"]
                        })

                elif last_msg.type == "tool":
                    try:
                        tool_data = json.loads(last_msg.content)
                        if isinstance(tool_data, dict) and "traceability" in tool_data:
                            global_traceability.extend(tool_data["traceability"])
                        else:
                            global_traceability.append({
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "agent": last_msg.name or "sub_agent",
                                "action": "Resultado recibido",
                                "output": str(last_msg.content)[:300]
                            })
                    except Exception:
                        global_traceability.append({
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "agent": last_msg.name or "sub_agent",
                            "action": "Resultado recibido",
                            "output": str(last_msg.content)[:300]
                        })

                elif last_msg.type == "ai" and not getattr(last_msg, "tool_calls", None):
                    final_summary = last_msg.content

        TASKS_RESULTS_DB[task_id] = {
            "task_id": task_id,
            "status": "COMPLETED",
            "target_url": target_url,
            "attack_type": attack_type,
            "global_traceability": global_traceability,
            "final_report": final_summary
        }
        logger.info(f"Tarea {task_id} procesada exitosamente.\n")

    except Exception as e:
        logger.error(f"Error durante la ejecución del orquestador: {str(e)}", exc_info=True)
        TASKS_RESULTS_DB[task_id] = {
            "task_id": task_id,
            "status": "FAILED",
            "error": str(e)
        }