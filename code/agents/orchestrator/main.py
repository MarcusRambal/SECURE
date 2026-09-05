import os
import logging
import aio_pika
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

from tools import get_mcp_catalog, build_langchain_tools

logger = logging.getLogger("orchestrator-main")

async def execute_orchestration_flow(payload: dict, channel: aio_pika.Channel):
    task_id = payload.get("task_id")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type", "scan")

    logger.info("============================================================")
    logger.info(f"   [NUEVA TAREA RECIBIDA] ID: {task_id}")
    logger.info(f"   Objetivo: {target_url} | Tipo: {attack_type}")
    logger.info("============================================================")

    # 1. Consultar catálogo dinámico MCP desde el Skills Controller
    logger.info("[PASO 1] Consultando catálogo de herramientas MCP...")
    mcp_catalog = await get_mcp_catalog(channel)

    if not mcp_catalog:
        logger.error("No se recibieron herramientas desde el Skills Controller.")
        return

    # 2. Convertir catálogo MCP a herramientas de LangChain
    tools = build_langchain_tools(mcp_catalog, channel)
    logger.info(f"Tools MCP cargadas en LangChain: {[t.name for t in tools]}")

    # 3. Configurar Modelo LLM usando Gemini 1.5 Flash
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        logger.error("GEMINI_API_KEY no encontrada en las variables de entorno.")
        return

    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=api_key,
        version="v1",
        temperature=0.1
    )

    system_prompt = SystemMessage(
        content=(
            "Eres un Agente Orquestador Especialista en Reconocimiento y Escaneo Web.\n"
            "Tu objetivo es realizar una fase de escaneo inicial invocando la herramienta MCP "
            "más adecuada disponible (como 'katana', 'zap_baseline_spider' o 'nikto').\n"
            "Una vez que la herramienta responda con la salida del escaneo, analiza los datos "
            "y entrega un resumen conciso de los endpoints descubiertos y las posibles vulnerabilidades preliminares."
        )
    )

    # 4. Crear el Grafo del Agente en LangGraph
    agent_executor = create_react_agent(
        model=llm,
        tools=tools,
        prompt=system_prompt
    )

    initial_input = {
        "messages": [
            HumanMessage(
                content=f"Realiza un escaneo de reconocimiento sobre el objetivo '{target_url}'. "
                        f"Ejecuta una herramienta de escaneo MCP y entrega un resumen de los hallazgos."
            )
        ]
    }

    logger.info("[PASO 2] Iniciando razonamiento del agente en LangGraph con Gemini...")

    try:
        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 6}):
            for value in event.values():
                last_msg = value["messages"][-1]
                logger.info(f"\n[{last_msg.type.upper()}]:\n{last_msg.content}")

        logger.info(f"Tarea {task_id} procesada exitosamente.\n")

    except Exception as e:
        logger.error(f"Error durante la ejecución del grafo de agentes: {str(e)}", exc_info=True)