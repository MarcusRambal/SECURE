import json
import logging
import aio_pika
from datetime import datetime, timezone
from urllib.parse import urljoin
from validate_prompts import get_system_prompt
from llm_factory import get_llm

from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.exceptions import OutputParserException

from contract_schemas import ValidateOutput
from helpers import (
    build_validate_output_from_dict,
    build_fallback_validate_output,
    build_real_command,
    prepare_sqlmap_request,
    write_validate_context_snapshot,
)
from mcp_skills import build_validation_tools, call_mcp_skill, get_mcp_catalog
from attack_types import is_sqli_attack

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")


logger.info("🟢 [VALIDATE] Cargando LLM de validación")
    
llm = get_llm("MODEL_VALIDATE")
structured_llm = llm.with_structured_output(ValidateOutput, method="json_schema",)

# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================

async def process_validate_task(channel: aio_pika.Channel,target_url: str,attack_type: str,targets: list[dict],) -> tuple[ValidateOutput, str]:
   
    started_at = datetime.now(timezone.utc).isoformat()

    is_sqli = is_sqli_attack(attack_type)
    logger.info("[VALIDATE] Es ataque SQLi: %s", is_sqli)

    selected_targets = [
        {
            "url": target.get("endpoint", ""),
            "method": target.get("method", "GET"),
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
        )

    # Construcción del catálogo de herramientas MCP y preparación de la ejecución
    catalog = await get_mcp_catalog(channel)
    raw_tool_outputs: list[str] = []
    executed_commands: list[dict] = []
    pre_executed_context: list[str] = []

    if is_sqli:
        logger.info( "[VALIDATE] Ejecutando SQLMap de forma obligatoria sobre %d endpoint(s)",len(selected_targets))
        
        for target in selected_targets:
            request_data = target.get("request", {})
            if isinstance(request_data, dict) and request_data:
                tool_args = {
                    "request": prepare_sqlmap_request(
                        request_data,
                        target_url,
                        target["url"],
                        target["method"],
                    )
                }
            else:
                tool_args = {
                    "target_url": urljoin(
                        f"{target_url.rstrip('/')}/",
                        target["url"],
                    )
                }
            
            try:
                output = await call_mcp_skill(channel, "sqlmap", tool_args)
                raw_tool_outputs.append(output)
                
                # Construir registro de comandos ejecutados
                executed_command = {
                    "tool": "sqlmap",
                    "args": tool_args,
                    "command": build_real_command("sqlmap", tool_args),
                    "target_id": target.get("target_id"),
                    "request_id": target.get("request_id"),
                    "endpoint": (
                        tool_args.get("request", {}).get("url")
                        or tool_args.get("target_url")
                    ),
                    "output": output,
                }
                executed_commands.append(executed_command)
                
                # Contexto formateado para que el LLM lo analice
                pre_executed_context.append(
                    {
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": executed_command["endpoint"],
                        "method": target["method"],
                        "request": tool_args.get("request"),
                        "tool_args": tool_args,
                        "headers": tool_args.get("request", {}).get("headers", {}),
                        "tool": "sqlmap",
                        "output": output,
                    }
                )
            except Exception as err:
                logger.error(f"Fallo en ejecución obligatoria de SQLMap en {target['url']}: {err}")


    excluded_tools = {"sqlmap"} if is_sqli else set()
    tools = build_validation_tools(catalog, channel, attack_type, excluded_tools)
    logger.info("Herramientas Validate activas: %s", [tool.name for tool in tools])

    

    system_prompt = SystemMessage(content=get_system_prompt(attack_type))

    user_message = HumanMessage(content=(
                f"Analiza los resultados de SQLMap y determina si existe vulnerabilidad.\n\n"
                "Fuentes obligatorias de validacion ya ejecutadas:\n"
                f"{json.dumps(pre_executed_context, ensure_ascii=False, indent=2)}\n\n"
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
        )
        logger.info("[VALIDATE] Contexto guardado en %s", snapshot_path)
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

    validate_output = build_validate_output_from_dict(parsed_dict,target_url,started_at,executed_commands)
    logger.info("[VALIDATE] Salida normalizada vulnerabilidades=%d no_confirmados=%d", len(validate_output.vulnerabilities), len(validate_output.unconfirmed_findings))

    return validate_output, "clean"

