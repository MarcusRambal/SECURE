import json
import logging
import aio_pika
from datetime import datetime, timezone
from validate_prompts import get_system_prompt
from llm_factory import get_llm

from langchain_core.messages import HumanMessage, SystemMessage

from contract_schemas import ValidateOutput
from helpers import (
    build_validate_output_from_dict,
    write_validate_context_snapshot,
)
from attack_validators import get_validation_strategy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")


logger.info("🟢 [VALIDATE] Cargando LLM de validación")
    
llm = get_llm("MODEL_VALIDATE")
structured_llm = llm.with_structured_output(ValidateOutput, method="json_schema",)

# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================

async def process_validate_task(channel: aio_pika.Channel,target_url: str,attack_type: str,targets: list[dict],task_id: str | None = None,) -> tuple[ValidateOutput, str, list[dict]]:
   
    started_at = datetime.now(timezone.utc).isoformat()
    trace_id = task_id or "unknown"
    tool_timings: list[dict] = []

    strategy = get_validation_strategy(attack_type)
    logger.info(
        "[VALIDATE] task_id=%s phase=start target_url=%s attack_type=%s is_sqli=%s targets_received=%d",
        trace_id,
        target_url,
        attack_type,
        strategy.is_sqli,
        len(targets),
    )

    selected_targets = [
        {
            "url": target.get("endpoint", ""),
            "method": target.get("method") or "GET",
            "target_id": target.get("target_id"),
            "request_id": target.get("request_id"),
            "recommended_tool": target.get("recommended_tool"),
            "request": target.get("request", {}), 
        }
        for target in targets
        if isinstance(target, dict) and target.get("endpoint")
    ]

    # Manejo de caso borde: Vino vacio
    if not selected_targets:
        logger.warning(
            "[VALIDATE_SKILLS] task_id=%s phase=skipped reason=no_valid_targets",
            trace_id,
        )
        logger.warning("Recon no devolvió objetivos prioritarios válidos. Omisión de la fase de validación.")
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{"reason": "Recon sin objetivos válidos para analizar"}],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",  # Omisión controlada
            tool_timings,
        )

    evidence = await strategy.execute(
        channel,
        target_url,
        selected_targets,
        trace_id,
        tool_timings,
    )

    system_prompt = SystemMessage(content=get_system_prompt(attack_type))
    validation_context = strategy.build_validation_context(evidence)

    user_message = HumanMessage(
        content=(
            "Analiza la evidencia disponible de las herramientas y determina si "
            "confirma la vulnerabilidad solicitada.\n\n"
            "Fuentes obligatorias de validacion ya ejecutadas:\n"
            f"{json.dumps(validation_context, ensure_ascii=False, indent=2)}\n\n"
            "Copia target_id, request_id y endpoint exclusivamente de la ejecucion que "
            "aporta la evidencia. No inventes IDs, endpoints, URLs ni comandos."
        ),
    )

    try:
        snapshot_path = write_validate_context_snapshot(
            target_url,
            attack_type,
            {
                "system_prompt": system_prompt.content,
                "user_message": user_message.content,
            },
            evidence.pre_executed_context,
            task_id=trace_id,
        )
        logger.info(
            "[VALIDATE] task_id=%s phase=context_snapshot path=%s",
            trace_id,
            snapshot_path,
        )
    except OSError:
        logger.exception("[VALIDATE] No se pudo guardar el contexto")


    structured_output = await structured_llm.ainvoke([system_prompt, user_message])
    if not isinstance(structured_output, ValidateOutput):
        raise TypeError("El LLM estructurado no devolvió una instancia de ValidateOutput")

    logger.info(
        "[VALIDATE] Salida original del agente antes del procesamiento:\n%s",
        structured_output.model_dump_json(indent=2),
    )
    parsed_dict = structured_output.model_dump()

    parsed_dict = strategy.merge_findings(parsed_dict, evidence, trace_id)

    validate_output = build_validate_output_from_dict(
        parsed_dict,
        target_url,
        started_at,
        evidence.executed_commands,
    )
    logger.info(
        "[VALIDATE] task_id=%s phase=complete vulnerabilities=%d unconfirmed=%d output=%s",
        trace_id,
        len(validate_output.vulnerabilities),
        len(validate_output.unconfirmed_findings),
        validate_output.model_dump_json(),
    )

    return validate_output, "clean", tool_timings
