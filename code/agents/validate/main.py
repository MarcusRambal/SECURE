import asyncio
import json
import logging
import aio_pika
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urljoin, urlsplit
from validate_prompts import get_system_prompt
from llm_factory import get_llm

from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.exceptions import OutputParserException

from contract_schemas import ValidateOutput
from helpers import (
    build_validate_sqli_context,
    build_validate_output_from_dict,
    build_fallback_validate_output,
    get_sqli_test_parameters,
    merge_sqlmap_findings,
    merge_sqli_agent_findings,
    merge_sqli_map_findings,
    sanitize_endpoint_for_context,
    write_validate_context_snapshot,
)
from mcp_skills import build_validation_tools, call_mcp_skill, get_mcp_catalog
from attack_types import is_sqli_attack

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")
SQLI_AGENT_MAX_CONCURRENCY = 3


logger.info("🟢 [VALIDATE] Cargando LLM de validación")
    
llm = get_llm("MODEL_VALIDATE")
structured_llm = llm.with_structured_output(ValidateOutput, method="json_schema",)

# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================

async def process_validate_task(
    channel: aio_pika.Channel,
    target_url: str,
    attack_type: str,
    targets: list[dict],
    task_id: str | None = None,
) -> tuple[ValidateOutput, str, list[dict]]:
   
    started_at = datetime.now(timezone.utc).isoformat()
    trace_id = task_id or "unknown"
    tool_timings: list[dict] = []

    is_sqli = is_sqli_attack(attack_type)
    logger.info(
        "[VALIDATE] task_id=%s phase=start target_url=%s attack_type=%s is_sqli=%s targets_received=%d",
        trace_id,
        target_url,
        attack_type,
        is_sqli,
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

    # Construcción del catálogo de herramientas MCP y preparación de la ejecución
    catalog = await get_mcp_catalog(channel, tool_timings)
    raw_tool_outputs: list[str] = []
    executed_commands: list[dict] = []
    pre_executed_context: list[dict] = []

    if is_sqli:
        logger.info(
            "[VALIDATE] task_id=%s Ejecutando pruebas SQLi acotadas sobre campos observados",
            trace_id,
        )
        jobs = []
        for target in selected_targets:
            request = target.get("request")
            request = request if isinstance(request, dict) else {}
            headers = request.get("headers")
            headers = headers if isinstance(headers, dict) else {}
            body = request.get("body")
            endpoint = str(request.get("url") or target["url"])
            endpoint_url = urljoin(f"{target_url.rstrip('/')}/", endpoint)
            safe_endpoint = sanitize_endpoint_for_context(endpoint_url)
            root_parts = urlsplit(target_url)
            endpoint_parts = urlsplit(endpoint_url)
            if (
                not root_parts.hostname
                or not endpoint_parts.hostname
                or root_parts.hostname.casefold() != endpoint_parts.hostname.casefold()
                or root_parts.port != endpoint_parts.port
            ):
                pre_executed_context.append(
                    {
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": safe_endpoint,
                        "tool": "sqli_agent",
                        "status": "SKIPPED",
                        "reason": "endpoint_outside_target_origin",
                    }
                )
                continue

            for parameter, location in get_sqli_test_parameters(endpoint_url, request):
                test_body = body
                if isinstance(test_body, str):
                    if location == "json_body":
                        test_body = json.loads(test_body)
                    elif location == "form_body":
                        test_body = dict(parse_qsl(test_body, keep_blank_values=True))
                jobs.append(
                    {
                        "target": target,
                        "endpoint": endpoint_url,
                        "safe_endpoint": safe_endpoint,
                        "method": target["method"],
                        "headers": headers,
                        "body": test_body,
                        "request": {
                            **request,
                            "url": endpoint_url,
                            "method": target["method"],
                            "headers": headers,
                            "body": test_body,
                        },
                        "location": location,
                        "parameter": parameter,
                    }
                )

        semaphore = asyncio.Semaphore(SQLI_AGENT_MAX_CONCURRENCY)

        async def execute_sqli_check(job: dict) -> tuple[dict, str]:
            async with semaphore:
                output = await call_mcp_skill(
                    channel,
                    "sqli_agent",
                    {
                        "target_url": job["endpoint"],
                        "param": job["parameter"],
                        "method": job["method"],
                        "location": job["location"],
                        "headers": job["headers"],
                        "body": job["body"],
                    },
                    tool_timings,
                )
            return job, output

        for job, output in await asyncio.gather(
            *(execute_sqli_check(job) for job in jobs)
        ):
            report = json.loads(output)
            if not isinstance(report, dict):
                raise TypeError("El agente SQLi no devolvió un objeto JSON")
            report.pop("target", None)
            safe_report = json.dumps(report, ensure_ascii=False)
            raw_tool_outputs.append(safe_report)
            command = (
                f"MCP sqli_agent --param {job['parameter']} "
                f"--location {job['location']}"
            )
            execution = {
                "tool": "sqli_agent",
                "command": command,
                "target_id": job["target"].get("target_id"),
                "request_id": job["target"].get("request_id"),
                "endpoint": job["safe_endpoint"],
                "parameter": job["parameter"],
                "output": safe_report,
            }
            executed_commands.append(execution)
            pre_executed_context.append(
                {
                    **execution,
                    "method": job["method"],
                    "location": job["location"],
                    "status": (
                        "ERROR"
                        if report.get("error") or report.get("persistence_error")
                        else "COMPLETED"
                    ),
                }
            )

        if not jobs:
            pre_executed_context.append(
                {
                    "tool": "sqli_agent",
                    "status": "SKIPPED",
                    "reason": "no_supported_captured_parameters",
                }
            )
            pre_executed_context.append(
                {
                    "tool": "sqli_map",
                    "status": "SKIPPED",
                    "reason": "no_supported_captured_parameters",
                }
            )
        else:
            logger.info(
                "[VALIDATE] task_id=%s phase=sqli_map starting scans=%d after=sqli_agent",
                trace_id,
                len(jobs),
            )
            for job in jobs:
                output = await call_mcp_skill(
                    channel,
                    "sqli_map",
                    {
                        "target_url": job["endpoint"],
                        "request": job["request"],
                        "param": job["parameter"],
                    },
                    tool_timings,
                )
                report = json.loads(output)
                if not isinstance(report, dict):
                    raise TypeError("SQLMap skill no devolvió un objeto JSON")
                safe_report = json.dumps(report, ensure_ascii=False)
                raw_tool_outputs.append(safe_report)
                command = (
                    f"MCP sqli_map --param {json.dumps(job['parameter'])} "
                    "--action detect"
                )
                execution = {
                    "tool": "sqli_map",
                    "command": command,
                    "target_id": job["target"].get("target_id"),
                    "request_id": job["target"].get("request_id"),
                    "endpoint": job["safe_endpoint"],
                    "parameter": job["parameter"],
                    "output": safe_report,
                }
                executed_commands.append(execution)
                pre_executed_context.append(
                    {
                        **execution,
                        "method": job["method"],
                        "location": job["location"],
                        "status": (
                            "ERROR"
                            if report.get("error") or report.get("persistence_error")
                            else "COMPLETED"
                        ),
                    }
                )

    excluded_tools = {"sqlmap", "sqli_map"} if is_sqli else set()
    tools = build_validation_tools(
        catalog, channel, attack_type, excluded_tools, tool_timings
    )
    logger.info("Herramientas Validate activas: %s", [tool.name for tool in tools])

    

    system_prompt = SystemMessage(content=get_system_prompt(attack_type))

    validation_context = pre_executed_context
    if is_sqli:
        validation_context = build_validate_sqli_context(pre_executed_context)

    user_message = HumanMessage(content=(
            "Analiza la evidencia disponible de las herramientas y determina si "
            "confirma la vulnerabilidad solicitada.\n\n"
            "Fuentes obligatorias de validacion ya ejecutadas:\n"
                f"{json.dumps(validation_context, ensure_ascii=False, indent=2)}\n\n"
                "Copia target_id, request_id y endpoint exclusivamente de la ejecucion que "
                "aporta la evidencia. No inventes IDs, endpoints, URLs ni comandos."
            ))

    try:
        snapshot_path = write_validate_context_snapshot(
            target_url,
            attack_type,
            {
                "system_prompt": system_prompt.content,
                "user_message": user_message.content,
            },
            pre_executed_context,
            task_id=trace_id,
        )
        logger.info(
            "[VALIDATE] task_id=%s phase=context_snapshot path=%s",
            trace_id,
            snapshot_path,
        )
    except OSError:
        logger.exception("[VALIDATE] No se pudo guardar el contexto")


    try:
        # Salida estructurada del LLM
        structured_output = await structured_llm.ainvoke([system_prompt, user_message])

    except (OutputParserException, ValidationError) as error:
        if not is_sqli:
            raise
        logger.warning(
            "[VALIDATE] El LLM no devolvio ValidateOutput compatible (%s); usando resultados de herramientas.",
            error,
        )
        parsed_dict = build_fallback_validate_output(target_url, raw_tool_outputs, executed_commands, started_at)
    else:
        if not isinstance(structured_output, ValidateOutput):
            raise TypeError("El LLM estructurado no devolvió una instancia de ValidateOutput")
        
        logger.info("[VALIDATE] Salida original del agente antes del procesamiento:\n%s",structured_output.model_dump_json(indent=2),)
        
        parsed_dict = structured_output.model_dump()

    if is_sqli:
        parsed_dict = merge_sqli_agent_findings(parsed_dict, executed_commands)
        parsed_dict = merge_sqlmap_findings(parsed_dict, executed_commands)
        parsed_dict = merge_sqli_map_findings(parsed_dict, executed_commands)
        logger.info(
            "[VALIDATE] task_id=%s vulnerabilidades tras incorporar SQLi=%d",
            trace_id,
            len(parsed_dict.get("vulnerabilities", [])),
        )

    validate_output = build_validate_output_from_dict(parsed_dict,target_url,started_at,executed_commands)
    logger.info(
        "[VALIDATE] task_id=%s phase=complete vulnerabilities=%d unconfirmed=%d output=%s",
        trace_id,
        len(validate_output.vulnerabilities),
        len(validate_output.unconfirmed_findings),
        validate_output.model_dump_json(),
    )

    return validate_output, "clean", tool_timings
