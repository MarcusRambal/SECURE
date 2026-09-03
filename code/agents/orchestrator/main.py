import os
import logging
import aio_pika
from tools import get_mcp_catalog, call_mcp_skill

logger = logging.getLogger("orchestrator-main")

async def execute_orchestration_flow(payload: dict, channel: aio_pika.Channel):
    """
    Flujo de orquestación determinista para pruebas end-to-end.
    Involucra el protocolo MCP sobre RabbitMQ sin entrar en bucles de LLM.
    """
    task_id = payload.get("task_id")
    target_url = payload.get("target_url")
    attack_type = payload.get("attack_type", "SCAN")

    logger.info("============================================================")
    logger.info(f"📥 [NUEVA TAREA RECIBIDA] ID: {task_id}")
    logger.info(f"👉 Objetivo: {target_url} | Tipo: {attack_type}")
    logger.info("============================================================")

    # 1. Obtener el catálogo dinámico desde el Skills Controller vía MCP (tools/list)
    logger.info("🔍 [PASO 1] Consultando catálogo de herramientas MCP...")
    mcp_catalog = await get_mcp_catalog(channel)

    if not mcp_catalog:
        logger.error("❌ No se recibieron herramientas desde el Skills Controller.")
        return

    available_tools = [t["name"] for t in mcp_catalog]
    logger.info(f"📋 Herramientas MCP detectadas en el sistema: {available_tools}")

    # 2. Selección explícita de la herramienta de prueba
    selected_tool = "zap_ajax_spider"

    if selected_tool not in available_tools:
        logger.error(f"❌ La herramienta '{selected_tool}' no está en el catálogo del Skills Controller.")
        return

    # 3. Preparación de los argumentos según el esquema MCP de la herramienta
    tool_arguments = {
        "target_url": target_url
    }

    # 4. Invocación efímera vía MCP (tools/call) -> Publica a 'skills_queue'
    logger.info(f"🎯 [PASO 2] Invocando manualmente la herramienta MCP '{selected_tool}'...")
    logger.info(f"⏳ Esperando la ejecución efímera del contenedor en Docker...")

    try:
        execution_output = await call_mcp_skill(
            channel=channel,
            tool_name=selected_tool,
            arguments=tool_arguments
        )

        logger.info("✅ [PASO 3] Ejecución efímera completada.")
        logger.info("📄 --- [RESULTADOS DEL ESCANEO] ---")
        logger.info(f"\n{execution_output}")
        logger.info("----------------------------------")

    except Exception as e:
        logger.error(f"❌ Error durante la ejecución de la skill: {str(e)}", exc_info=True)

    logger.info(f"🎉 Tarea {task_id} procesada exitosamente.\n")