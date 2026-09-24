import json
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_llm

from langchain_core.messages import HumanMessage, SystemMessage
from langchain.agents import create_agent

from contract_schemas import ReconPlannerOutput
from helpers import (
    build_planner_output_from_dict,
    clean_json_response,
    deduplicate_urls,
    extract_urls_from_crawler,
    extract_urls_from_katana,
    log_preview,
)
from mcp_skills import call_mcp_skill, get_mcp_catalog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-agent-worker")




# ============================================================================
# FLUJO PRINCIPAL DE RECONOCIMIENTO
# ============================================================================


async def process_recon_task(channel: aio_pika.Channel,target_url: str,attack_type_filter: str = "full",) -> tuple[ReconPlannerOutput, str]:
    """
    Ejecuta el pipeline de reconocimiento con 3 capas de resiliencia.

        Retorna el plan validado y el modo de recuperación usado.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    logger.info("[RECON] Inicio target=%s attack_type=%s started_at=%s",target_url,attack_type_filter,started_at)

    catalog = await get_mcp_catalog(channel)
    catalog_names = {tool.get("name") for tool in catalog}
    mandatory_tools = {"spa_crawler", "katana_full"}
    missing_tools = mandatory_tools - catalog_names
    if missing_tools:
        raise RuntimeError(
            f"Faltan herramientas obligatorias de Recon en MCP: {sorted(missing_tools)}"
        )

    logger.info("[RECON] Fase obligatoria 1/2: ejecutando spa_crawler target=%s", target_url)

     #Llamamos a las skills de Crawler y Katana
    crawler_output = await call_mcp_skill(channel,"spa_crawler", {"target_url": target_url},)

    try:
        crawler_data = json.loads(crawler_output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"spa_crawler no devolvió JSON válido: {error}") from error

    logger.info( "[RECON] spa_crawler completado captured=%s routes=%d",crawler_data.get("total_requests_captured", 0), len(crawler_data.get("discovered_forms_structure", [])),)

    logger.info("[RECON] Fase obligatoria 2/2: ejecutando katana_full target=%s", target_url)

   
    katana_output = await call_mcp_skill(channel,"katana_full",{"target_url": target_url},)

    #Fase de limpieza del contexto para que el agente pueda consumirlo
    katana_urls = extract_urls_from_katana(katana_output)
    crawler_urls = extract_urls_from_crawler(crawler_data)
    discovered_urls = deduplicate_urls(crawler_urls, katana_urls)
    available_tools = [
        {
            "name": tool.get("name"),
            "description": tool.get("description", ""),
        }
        for tool in catalog
        if tool.get("name") not in {"spa_crawler", "katana_full"}
    ]
    recon_sources = {
        "spa_crawler": crawler_data,
        "katana_full_raw_output": katana_output,
        "katana_full_urls": katana_urls,
        "deduplicated_urls": discovered_urls,
        "available_validation_tools": available_tools,
    }
    logger.info(
        "[RECON] Fuentes consolidadas crawler=%d katana=%d deduplicadas=%d",
        len(crawler_urls),
        len(katana_urls),
        len(discovered_urls),
    )

    # Recon solo analiza; Validate ejecutará las herramientas de seguridad después.

    logger.info("[RECON] Cargando LLM de reconocimiento")
    llm = get_llm("recon")

     # Prompt del Sistema enfocado en Planificación de Ataque
    system_prompt = SystemMessage(
        content=(
            "Eres un Agente Especialista en Reconocimiento y Planificación de Vectores de Ataque Web.\n"
            f"Tu objetivo principal es analizar el objetivo '{target_url}' y planificar un flujo de ataque enfocado en: {attack_type_filter}, .\n\n"
            "INSTRUCCIONES DE EJECUCIÓN:\n"
            "1. Las fases obligatorias spa_crawler y katana_full ya fueron ejecutadas. Analiza ambas salidas y las peticiones estructuradas .\n"
            "2. Usa el contenido real para identificar método, ruta, query, headers y body. No inventes rutas de archivos ni archivos HAR.\n"
            f"3. Limpia los duplicados usando la lista consolidada y filtra las rutas y parámetros sospechosos de ser vulnerables a '{attack_type_filter}'.\n"
            "4. Decide después el plan de acción: objetivos prioritarios, método, petición estructurada y herramienta recomendada.\n"
            "5. Este agente es exclusivamente analítico. No ejecutes sqlmap, nuclei, dalfox, commix, ffuf ni ninguna otra herramienta.\n\n"
            "6. Para recommended_tool usa únicamente un nombre presente en available_validation_tools.\n\n"
            "REGLA CRÍTICA DE FINALIZACIÓN:\n"
            "Analiza primero toda la salida de spa_crawler. Al final responde con una breve explicación y, como último contenido, un único bloque Markdown ```json ... ``` válido.\n"
            "El JSON debe tener esta estructura:\n"
            "{\n"
            '  "recon_summary": {\n'
            f'    "target_url": "{target_url}",\n'
            f'    "attack_type_filter": "{attack_type_filter}",\n'
            '    "total_targets_identified": <numero_int>,\n'
            '    "total_requests_captured": 12\n'
            "  },\n"
            '  "high_priority_targets": [\n'
            "    {\n"
            '      "target_id": "target_001",\n'
            f'      "vulnerability_target": "{attack_type_filter} (POST-based Auth Bypass)",\n'
            '      "endpoint": "http://...",\n'
            '      "method": "POST",\n'
            '      "request": {"request_id": "req_008", "method": "POST", "url": "http://...", "headers": {}, "body": ""},\n'
            '      "recommended_tool": "sqlmap"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "No pongas texto después del bloque JSON."
        )
    )

    agent_executor = create_agent(model=llm, tools=[], system_prompt=system_prompt)
    logger.info("[RECON] Agente analítico creado sin tools de ataque; iniciando stream")
    initial_input = {
        "messages": [
            HumanMessage(
                content=(
                    f"Analiza la superficie del objetivo '{target_url}' y planifica el siguiente paso.\n\n"
                    "Fuentes obligatorias de reconocimiento ya ejecutadas:\n"
                    f"{json.dumps(recon_sources, ensure_ascii=False, indent=2)}\n\n"
                    "Usa únicamente los datos JSON proporcionados; no dependas de archivos compartidos."
                )
            )
        ]
    }

    raw_final_output = ""
    llm_outputs: list[str] = []

    event_number = 0
    async for event in agent_executor.astream(initial_input, config={"recursion_limit": 10}):
        event_number += 1
        logger.info("[RECON] Evento #%d recibido keys=%s", event_number, list(event.keys()))
        for value in event.values():
            last_msg = value["messages"][-1]
            logger.info(
                "[RECON] Mensaje #%d type=%s content=%s",
                event_number,
                last_msg.type,
                log_preview(last_msg.content),
            )

            if last_msg.type == "ai" and isinstance(last_msg.content, str):
                llm_outputs.append(last_msg.content)

            if last_msg.type == "tool":
                logger.info(
                    "[RECON] Tool finalizada name=%s output_chars=%d",
                    getattr(last_msg, "name", "unknown"),
                    len(last_msg.content) if isinstance(last_msg.content, str) else 0,
                )

            elif last_msg.type == "ai" and not getattr(last_msg, "tool_calls", None):
                if isinstance(last_msg.content, str):
                    raw_final_output = last_msg.content
                    logger.info("[RECON] Respuesta textual final capturada")

    full_llm_output = "\n\n--- LLM event ---\n\n".join(llm_outputs)
    logger.info("[RECON] Parseando bloque JSON final chars=%d", len(raw_final_output))
    parsed_dict = json.loads(clean_json_response(raw_final_output))
    recon_output = build_planner_output_from_dict(
        parsed_dict,
        target_url,
        attack_type_filter,
    )
    logger.info(
        "[RECON] Plan JSON validado targets=%d ", len(recon_output.high_priority_targets),)
    return recon_output, "clean"


