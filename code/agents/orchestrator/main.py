import os
import json
import logging
import asyncio
import aio_pika
import uvicorn
from fastapi import FastAPI, HTTPException, Response
from llm_factory import get_llm

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

from tools import TASK_STATE, create_orchestrator_tools

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("orchestrator-main")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
ORCHESTRATOR_QUEUE = "orchestrator_queue"

# Resultados finales por task_id (en memoria, no persistente).
TASKS_RESULTS_DB: dict[str, dict] = {}

app = FastAPI(title="SECURE - Orchestrator Gateway API", version="1.0.0")


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "orchestrator"}


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/api/task/{task_id}")
async def get_task_result(task_id: str):
    """Permite consultar el estado y el reporte final en Markdown de una tarea."""
    if task_id in TASKS_RESULTS_DB:
        return TASKS_RESULTS_DB[task_id]
    if task_id in TASK_STATE:
        return {
            "task_id": task_id,
            "status": TASK_STATE[task_id].get("status", "PROCESSING"),
            "target_url": TASK_STATE[task_id].get("target_url"),
            "attack_type": TASK_STATE[task_id].get("attack_type"),
        }
    raise HTTPException(status_code=404, detail=f"Tarea '{task_id}' no encontrada.")


async def execute_orchestration_flow(payload: dict, channel: aio_pika.Channel):
    """Ejecuta el pipeline secuencial y persiste el resultado en TASKS_RESULTS_DB."""
    task_id = payload.get("task_id", "N/A")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type", "full")

    logger.info("============================================================")
    logger.info(f"🚀 [AUDITORÍA INICIADA] Task ID: {task_id}")
    logger.info(f"   Objetivo: {target_url} | Tipo: {attack_type}")
    logger.info("============================================================")

    TASK_STATE[task_id] = {
        "task_id": task_id,
        "target_url": target_url,
        "attack_type": attack_type,
        "status": "PROCESSING",
        "recon_data": None,
        "validation_data": None,
        "report_markdown": None,
        "recon_used_fallback": False,
        "validate_used_fallback": False,
        "reporter_used_fallback": False,
        # Cómo se recuperó cada fase: "clean" | "recovered" | "fallback" | "error".
        "recon_recovery_mode": None,
        "validate_recovery_mode": None,
    }

    try:
        llm = get_llm("orchestrator")

        tools = create_orchestrator_tools(channel)
        logger.info(f"Agentes cargados en LangChain: {[t.name for t in tools]}")

        system_prompt = SystemMessage(
            content=(
                "Eres el Agente Orquestador Principal de Ciberseguridad.\n"
                "Tu función única es coordinar la ejecución en secuencia estricta de los 3 agentes especializados invocando sus herramientas pasando únicamente el 'task_id':\n\n"
                "SECUENCIA OBLIGATORIA DE HERRAMIENTAS:\n"
                "1. Llama a 'recon_agent' con 'task_id'.\n"
                "2. Llama a 'validate_agent' con 'task_id'.\n"
                "3. Llama a 'reporter_agent' con 'task_id'.\n"
                "4. Una vez que 'reporter_agent' confirme la generación del informe, emite como tu MENSAJE FINAL ÚNICAMENTE la frase: 'Pipeline completado'.\n\n"
                "REGLAS STRICTAS:\n"
                "- NO intentes copiar ni reproducir el texto Markdown del reporte en tu mensaje final.\n"
                "- NO redactes conclusiones ni resúmenes.\n"
                "- Pasa ÚNICAMENTE 'task_id' en cada llamada a herramienta."
            )
        )

        agent_executor = create_react_agent(model=llm, tools=tools, prompt=system_prompt)

        initial_input = {
            "messages": [
                HumanMessage(
                    content=f"Inicia el pipeline de auditoría pasando task_id='{task_id}'."
                )
            ]
        }

        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 10}):
            for value in event.values():
                last_msg = value["messages"][-1]
                if last_msg.type == "tool":
                    logger.info(f"[TOOL]: {str(last_msg.content)[:180]}...")
                elif last_msg.type == "ai" and not getattr(last_msg, "tool_calls", None):
                    logger.info(f"[AI FINAL]: {str(last_msg.content)[:180]}")

        completed_state = TASK_STATE.get(task_id, {})
        final_status = completed_state.get("status", "COMPLETED")

        TASKS_RESULTS_DB[task_id] = {
            "task_id": task_id,
            "target_url": target_url,
            "attack_type": attack_type,
            "status": final_status,
            "report_markdown": completed_state.get("report_markdown"),
            "recon_used_fallback": completed_state.get("recon_used_fallback", False),
            "validate_used_fallback": completed_state.get("validate_used_fallback", False),
            "reporter_used_fallback": completed_state.get("reporter_used_fallback", False),
            "recon_recovery_mode": completed_state.get("recon_recovery_mode"),
            "validate_recovery_mode": completed_state.get("validate_recovery_mode"),
        }

        logger.info(
            f"✅ Auditoría {task_id} finalizada ({final_status}) y persistida en TASKS_RESULTS_DB."
        )

    except Exception as e:
        logger.error(f"❌ Error durante la ejecución del orquestador: {e}", exc_info=True)
        TASKS_RESULTS_DB[task_id] = {
            "task_id": task_id,
            "target_url": target_url,
            "attack_type": attack_type,
            "status": "FAILED",
            "error": str(e),
        }
    finally:
        # Liberación limpia de memoria del estado intermedio de la tarea
        TASK_STATE.pop(task_id, None)


async def start_orchestrator_worker():
    """Worker asíncrono que escucha solicitudes en RabbitMQ."""
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
                            await execute_orchestration_flow(payload, channel)
        except Exception as e:
            logger.warning(f"Error en Worker del Orquestador ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


async def start_http_server():
    """Servidor FastAPI HTTP para exponer los endpoints de consulta."""
    config = uvicorn.Config(app, host="0.0.0.0", port=8001, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    await asyncio.gather(
        start_orchestrator_worker(),
        start_http_server(),
    )


if __name__ == "__main__":
    asyncio.run(main())
