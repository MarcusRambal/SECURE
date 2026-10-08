import json
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_llm
from pydantic import ValidationError

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.exceptions import OutputParserException

from attack_types import is_sqli_attack
from contract_schemas import ReconPlannerOutput
from helpers import (
    build_recon_output_from_dict,
    build_sqli_recon_context,
    build_sqli_fallback_output,
    deduplicate_urls,
    extract_urls_from_crawler,
    extract_urls_from_deep_crawler,
    write_recon_context_snapshot,
)
from mcp_skills import call_mcp_skill, get_mcp_catalog
from recon_prompts import get_system_prompt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-agent-worker")


llm = get_llm("recon")
structured_llm = llm.with_structured_output(ReconPlannerOutput, method="json_schema",)
# Recon solo analiza; Validate ejecutará las herramientas de seguridad después.
logger.info("🟢 [RECON] Cargando LLM de reconocimiento")

# ============================================================================
# FLUJO PRINCIPAL DE RECONOCIMIENTO
# ============================================================================

async def process_recon_task(channel: aio_pika.Channel,target_url: str,attack_type_filter: str = "full",) -> tuple[ReconPlannerOutput, str]:


    started_at = datetime.now(timezone.utc).isoformat()
    is_sqli = is_sqli_attack(attack_type_filter)

    logger.info("🟡 [RECON] Inicio target=%s attack_type=%s started_at=%s",target_url,attack_type_filter,started_at)

    #Obtenemos el catálogo de herramientas disponibles en MCP
    catalog = await get_mcp_catalog(channel)

    #Herramienta mandatoria de ejecucion
    crawler_output = await call_mcp_skill(channel,"crawler", {"target_url": target_url},)

    try:
        crawler_data = json.loads(crawler_output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"crawler no devolvió JSON válido: {error}") from error

    crawler_urls = extract_urls_from_crawler(crawler_data)

    logger.info("[RECON] crawler completado urls=%d", len(crawler_urls))

    if is_sqli:
        logger.info("[RECON] SQLi: ejecutando deep_crawler con la salida efimera de crawler")

        deep_crawler_output = await call_mcp_skill(channel, "deep_crawler", {"crawler_report": crawler_data})

        try:
            deep_crawler_data = json.loads(deep_crawler_output)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"deep_crawler no devolvió JSON válido: {error}") from error
        
        deep_crawler_urls = extract_urls_from_deep_crawler(deep_crawler_data)
         
        logger.info("[RECON] deep_crawler completado entry_points=%d urls=%d", len(deep_crawler_data.get("entry_points", [])), len(deep_crawler_urls),)
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
        recon_sources = build_sqli_recon_context(crawler_data,deep_crawler_data,discovered_urls,available_tools )

    try:
        context_path = write_recon_context_snapshot(target_url, attack_type_filter, recon_sources)

        logger.info("[RECON] Contexto LLM guardado en %s", context_path)
    except OSError:
        logger.exception("[RECON] No se pudo guardar el contexto LLM")
    logger.info("[RECON] Fuentes consolidadas crawler=%d deep_crawler=%d deduplicadas=%d",len(crawler_urls),len(deep_crawler_urls),len(discovered_urls),)

    system_prompt = SystemMessage(content=get_system_prompt(attack_type_filter))

    user_message = HumanMessage(
        content=(
            f"Analiza la superficie del objetivo '{target_url}' y planifica el siguiente paso.\n\n"
            "Fuentes obligatorias de reconocimiento ya ejecutadas:\n"
            f"{json.dumps(recon_sources, ensure_ascii=False, indent=2)}\n\n"
            "Usa únicamente los datos JSON proporcionados; no dependas de archivos compartidos."
        )
    )

    logger.info("[RECON] Contexto compacto para LLM chars=%d",len(json.dumps(recon_sources, ensure_ascii=False)),)

    try:
        # Salida estructurada del LLM
        structured_output = await structured_llm.ainvoke([system_prompt, user_message])

    except (OutputParserException, ValidationError) as error:
        if not is_sqli:
            raise
        logger.warning("[RECON] El LLM no devolvio una salida compatible con ReconPlannerOutput (%s); ""usando peticiones observadas de deep_crawler.",error,)
        parsed_dict = build_sqli_fallback_output(target_url, deep_crawler_data)
    else:
        if not isinstance(structured_output, ReconPlannerOutput):
            raise TypeError("El LLM estructurado no devolvió una instancia de ReconPlannerOutput")
        
        logger.info("[RECON] Salida original del agente antes del procesamiento:\n%s",structured_output.model_dump_json(indent=2),)
        
        parsed_dict = structured_output.model_dump()

    recon_output = build_recon_output_from_dict(
        parsed_dict,
        target_url,
        attack_type_filter,
        deep_crawler_data if is_sqli else None,
    )
    logger.info("[RECON] Plan JSON validado targets=%d ", len(recon_output.high_priority_targets),)

    return recon_output, "clean"
