import json
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_llm
from pydantic import ValidationError

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.exceptions import OutputParserException

from attack_types import (
    is_access_control_attack,
    is_crypto_attack,
    is_sqli_attack,
    is_xss_attack,
    is_jwt_attack
)
from contract_schemas import ReconPlannerOutput

from mcp_skills import get_mcp_catalog

from helpers import (
    build_access_control_fallback_output,
    build_recon_output_from_dict,
    build_sqli_recon_context,
    build_sqli_fallback_output,
    build_xss_recon_context,
    build_crypto_recon_context,
    build_crypto_fallback_output,
    ensure_crypto_entry_point_coverage,
    ensure_access_control_target_coverage,
    ensure_sqli_entry_point_coverage,
    ensure_xss_entry_point_coverage,
    update_recon_context_snapshot,
    write_recon_context_snapshot,
    build_access_control_recon_context,
    clean_scraping_report
)

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

async def process_recon_task(
    channel: aio_pika.Channel,
    target_url: str,
    attack_type_filter: str = "full",
    *,
    scraping_report: dict,
) -> tuple[ReconPlannerOutput, str, list[dict]]:

    started_at = datetime.now(timezone.utc).isoformat()
    is_sqli = is_sqli_attack(attack_type_filter)
    is_xss = is_xss_attack(attack_type_filter)
    is_crypto = is_crypto_attack(attack_type_filter)
    is_access_control = is_access_control_attack(attack_type_filter)
    is_jwt = is_jwt_attack(attack_type_filter)

    tool_timings: list[dict] = []

    logger.info("🟡 [RECON] Inicio target=%s attack_type=%s started_at=%s",target_url,attack_type_filter,started_at)

    clean_scraping_report_data = clean_scraping_report(scraping_report)

    # Obtenemos el catálogo después de validar y limpiar la entrada externa.
    catalog = await get_mcp_catalog(channel, tool_timings)

    if is_sqli:
        recon_sources = build_sqli_recon_context(clean_scraping_report_data, catalog)
    elif is_xss:
        recon_sources = build_xss_recon_context(clean_scraping_report_data, catalog)
    elif is_crypto:
        recon_sources = build_crypto_recon_context(clean_scraping_report_data, catalog)
    elif is_access_control:
        recon_sources = build_access_control_recon_context(clean_scraping_report_data, catalog)
    elif is_jwt:
        recon_sources = build_jwt_recon_context(clean_scraping_report_data, catalog)


    context_path = None

    try:
        context_path = write_recon_context_snapshot(
            target_url,
            attack_type_filter,
            recon_sources,
            tool_timings=tool_timings,
        )

        logger.info("[RECON] Contexto LLM guardado en %s", context_path)
    except OSError:
        logger.exception("[RECON] No se pudo guardar el contexto LLM")
    logger.info(
        "[RECON] Scraping limpio requests=%d endpoints=%d",
        len(clean_scraping_report_data["requests"]),
        len(clean_scraping_report_data["observed_endpoints"]),
    )

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

    llm_output = {}

    try:
        # Salida estructurada del LLM
        structured_output = await structured_llm.ainvoke([system_prompt, user_message])

    except (OutputParserException, ValidationError) as error:
        if not (is_sqli or is_crypto or is_xss):
            raise
        logger.warning(
            "[RECON] El LLM no devolvio una salida compatible con ReconPlannerOutput "
            "(%s); usando cobertura basada en peticiones observadas.",
            error,
        )
        if is_sqli:
            parsed_dict = build_sqli_fallback_output(target_url, recon_sources)
        elif is_xss:
            parsed_dict = build_xss_fallback_output(target_url, recon_sources)
        elif is_crypto:
            parsed_dict = build_crypto_fallback_output(target_url, recon_sources)
        elif is_access_control:
            parsed_dict = build_access_control_fallback_output(target_url, recon_sources)
        elif is_jwt:
            parsed_dict = build_jwt_fallback_output(target_url, recon_sources)

        llm_output = {"error": str(error), "fallback": "recon_sources"}
    else:
        if not isinstance(structured_output, ReconPlannerOutput):
            raise TypeError("El LLM estructurado no devolvió una instancia de ReconPlannerOutput")
        
        logger.info("[RECON] Salida original del agente antes del procesamiento:\n%s",structured_output.model_dump_json(indent=2),)
        parsed_dict = structured_output.model_dump()
        llm_output = parsed_dict

    if is_sqli:
        parsed_dict = ensure_sqli_entry_point_coverage(parsed_dict, recon_sources)

    elif is_xss:
        parsed_dict = ensure_xss_entry_point_coverage(parsed_dict, recon_sources)

    elif is_crypto:
        parsed_dict = ensure_crypto_entry_point_coverage(parsed_dict, recon_sources, target_url)

    elif is_access_control:
        parsed_dict = ensure_access_control_target_coverage(parsed_dict, recon_sources, target_url)

    recon_output = build_recon_output_from_dict(
        parsed_dict,
        target_url,
        attack_type_filter,
        recon_sources if (is_sqli or is_xss or is_crypto or is_access_control) else None,
    )
    logger.info("[RECON] Plan JSON validado targets=%d ", len(recon_output.high_priority_targets),)

    if context_path is not None:
        try:
            update_recon_context_snapshot(
                context_path,
                llm_output,
                recon_output.model_dump(),
            )
        except OSError:
            logger.exception("[RECON] No se pudo completar el contexto guardado")

    return recon_output, "clean", tool_timings
