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
    build_recon_context,
    build_sqli_fallback_output,
    clean_json_response,
    deduplicate_urls,
    extract_urls_from_crawler,
    extract_urls_from_deep_crawler,
    hydrate_selected_requests,
    log_preview,
    write_recon_context_snapshot,
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
    mandatory_tools = {"crawler"}
    if attack_type_filter.lower() == "sqli":
        mandatory_tools.add("deep_crawler")
    missing_tools = mandatory_tools - catalog_names
    if missing_tools:
        raise RuntimeError(
            f"Faltan herramientas obligatorias de Recon en MCP: {sorted(missing_tools)}"
        )

    logger.info("[RECON] Fase obligatoria: ejecutando crawler target=%s", target_url)

    crawler_output = await call_mcp_skill(channel,"crawler", {"target_url": target_url},)

    try:
        crawler_data = json.loads(crawler_output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"crawler no devolvió JSON válido: {error}") from error

    crawler_urls = extract_urls_from_crawler(crawler_data)
    logger.info("[RECON] crawler completado urls=%d", len(crawler_urls))

    deep_crawler_data = None
    deep_crawler_urls: list[str] = []
    if attack_type_filter.lower() == "sqli":
        logger.info("[RECON] SQLi: ejecutando deep_crawler con la salida efimera de crawler")
        deep_crawler_output = await call_mcp_skill(
            channel, "deep_crawler", {"crawler_report": crawler_data}
        )
        try:
            deep_crawler_data = json.loads(deep_crawler_output)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"deep_crawler no devolvió JSON válido: {error}") from error
        deep_crawler_urls = extract_urls_from_deep_crawler(deep_crawler_data)
        logger.info(
            "[RECON] deep_crawler completado entry_points=%d urls=%d",
            len(deep_crawler_data.get("entry_points", [])), len(deep_crawler_urls),
        )

    #Fase de limpieza del contexto para que el agente pueda consumirlo
    discovered_urls = deduplicate_urls(crawler_urls, deep_crawler_urls)
    available_tools = [
        {
            "name": tool.get("name"),
            "description": tool.get("description", ""),
        }
        for tool in catalog
        if tool.get("name") not in {"crawler", "deep_crawler"}
    ]
    recon_sources = build_recon_context(
        crawler_data,
        deep_crawler_data,
        discovered_urls,
        available_tools,
        attack_type_filter,
    )
    try:
        context_path = write_recon_context_snapshot(
            target_url, attack_type_filter, recon_sources
        )
        logger.info("[RECON] Contexto LLM guardado en %s", context_path)
    except OSError:
        logger.exception("[RECON] No se pudo guardar el contexto LLM")
    logger.info(
        "[RECON] Fuentes consolidadas crawler=%d deep_crawler=%d deduplicadas=%d",
        len(crawler_urls),
        len(deep_crawler_urls),
        len(discovered_urls),
    )

    # Recon solo analiza; Validate ejecutará las herramientas de seguridad después.

    logger.info("[RECON] Cargando LLM de reconocimiento")
    llm = get_llm("recon")

    system_prompt = SystemMessage(
                content=f"""Eres un Agente Especialista en Reconocimiento y Planificación de Vectores de Ataque Web.

OBJETIVO
Analiza exclusivamente la información de reconocimiento previamente obtenida.

TARGET: {target_url}
TIPO DE ATAQUE SOLICITADO: {attack_type_filter}

La fase de crawling/reconocimiento YA fue ejecutada. Determina qué endpoints o solicitudes son relevantes para el tipo de ataque solicitado. No ejecutes ataques ni herramientas de explotación; tu función termina en la fase de análisis y planificación.

REGLAS DE ANÁLISIS
1. Analiza todas las fuentes proporcionadas antes de decidir.
2. Busca todos los endpoints, requests o entry points relevantes para {attack_type_filter}.
3. No te limites al primer endpoint. Devuelve todos los objetivos con evidencia suficiente.
4. Cada objetivo representa un endpoint o request concreto. No combines endpoints distintos en un mismo target.
5. Prioriza por evidencia observable: coincidencia con el ataque, método HTTP, query, body, headers, formularios, autenticación/autorización, APIs y datos controlables por cliente.
6. La prioridad expresa relevancia para el análisis; nunca confirma una vulnerabilidad.
7. Diferencia entre endpoint interesante, evidencia observada y vulnerabilidad confirmada. El crawler solo aporta evidencia de reconocimiento.
8. Usa únicamente información presente en las fuentes. No inventes URLs, endpoints, rutas, parámetros, headers, bodies, request IDs, métodos ni valores.
9. Cuando exista una request capturada, selecciona su request_id real. El sistema reconstruirá method, url, headers y body desde la captura original. No presentes requests hipotéticas como capturadas.
10. Requests del mismo endpoint con método, parámetros o body significativamente diferentes son targets independientes; duplicados exactos son un solo target.
11. Si un dato no existe, usa null o una estructura vacía.
12. Para SQLi usa exclusivamente sqli_input_entry_points: contienen requests observadas con body no nulo.

SELECCIÓN Y PRIORIZACIÓN
Identifica entre 0 y N targets, según la evidencia real. No fuerces targets. Ordena high_priority_targets de mayor a menor relevancia sin usar el orden del crawler como criterio.

RECOMMENDED TOOL
recommended_tool debe ser únicamente una herramienta presente en available_validation_tools. Selecciona la más apropiada para una futura validación, sin ejecutarla ni proporcionar comandos.

RESTRICCIONES
Eres exclusivamente analítico. No ejecutes sqlmap, nuclei, dalfox, commix, ffuf, nikto, nmap ni ninguna herramienta de explotación, fuzzing o scanning.

FORMATO DE SALIDA
Responde exclusivamente con un único bloque Markdown ```json válido, sin texto antes ni después, con esta estructura:
```json
{{
    "recon_summary": {{
        "target_url": "{target_url}",
        "attack_type_filter": "{attack_type_filter}",
        "total_targets_identified": 1,
        "total_requests_captured": 3
    }},
    "high_priority_targets": [
        {{
            "target_id": "target_001",
            "request_id": "entry_0008",
            "vulnerability_target": "SQLi candidate",
            "endpoint": "http://juice-shop-target:3000/rest/user/login",
            "method": "POST",
            "recommended_tool": "sqlmap"
        }}
    ]
}}
```
"""
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
    logger.info(
        "[RECON] Contexto compacto para LLM chars=%d",
        len(json.dumps(recon_sources, ensure_ascii=False)),
    )

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
    logger.info("[RECON] Parseando bloque JSON final chars=%d", len(full_llm_output))
    try:
        parsed_dict = json.loads(clean_json_response(raw_final_output))
    except (ValueError, json.JSONDecodeError) as error:
        if attack_type_filter.lower() != "sqli":
            raise
        logger.warning(
            "[RECON] El LLM no devolvio JSON valido (%s); usando peticiones observadas de deep_crawler.",
            error,
        )
        parsed_dict = build_sqli_fallback_output(target_url, deep_crawler_data)
    parsed_dict = hydrate_selected_requests(parsed_dict, deep_crawler_data)
    recon_output = build_planner_output_from_dict(parsed_dict,target_url,attack_type_filter,)
    logger.info(
        "[RECON] Plan JSON validado targets=%d ", len(recon_output.high_priority_targets),)
    return recon_output, "clean"


