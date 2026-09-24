import json
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_llm

from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.agents import create_agent

from contract_schemas import ValidateOutput
from helpers import (
    _build_output_from_args,
    build_fallback_validate_output,
    build_real_command,
    clean_json_response,
)
from mcp_skills import build_validation_tools, call_mcp_skill, get_mcp_catalog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")

# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================


async def process_validate_task(channel: aio_pika.Channel,target_url: str,attack_type: str,targets: list[dict],) -> tuple[ValidateOutput, str]:
    """
    Ejecuta la fase de validación con entrega estructurada y fallback basado en evidencia.

    Retorna:
        (ValidateOutput, recovery_mode)
        recovery_mode ∈ {"clean", "fallback"}
    """
    started_at = datetime.now(timezone.utc).isoformat()


    selected_targets = [
        {
            "url": target.get("endpoint", ""),
            "method": target.get("method", "GET"),
            "target_id": target.get("target_id"),
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

    
    mandatory_sqlmap = attack_type == "sqli" and bool(selected_targets)

    logger.info("[Validate] Resultados de si es sqlmap obligatorio: %s", mandatory_sqlmap)

    # Construcción del catálogo de herramientas MCP y preparación de la ejecución
    catalog = await get_mcp_catalog(channel)

    raw_tool_outputs: list[str] = []
    executed_commands: list[dict] = []
    pre_executed_context: list[str] = []

    # 1. Ejecución Obligatoria de SQLMap si aplica
    if mandatory_sqlmap:
        logger.info(
            "[VALIDATE] Ejecutando SQLMap de forma obligatoria sobre %d endpoint(s)",
            len(selected_targets),
        )
        for target in selected_targets:
            request_data = target.get("request", {})
            tool_args = {"request": request_data} if request_data else {"target_url": target["url"]}
            
            try:
                output = await call_mcp_skill(channel, "sqlmap", tool_args)
                raw_tool_outputs.append(output)
                
                # Construir registro de comandos ejecutados
                executed_commands.append(
                    {
                        "tool": "sqlmap",
                        "args": tool_args,
                        "command": build_real_command("sqlmap", tool_args),
                    }
                )
                
                # Contexto formateado para que el LLM lo analice
                pre_executed_context.append(
                    f"--- RESULTADO PRE-EJECUCIÓN SQLMAP PARA {target['url']} ---\n{output}\n"
                )
            except Exception as err:
                logger.error(f"Fallo en ejecución obligatoria de SQLMap en {target['url']}: {err}")

    excluded_tools = {"sqlmap"} if mandatory_sqlmap else set()
    tools = build_validation_tools(catalog, channel, attack_type, excluded_tools)
    logger.info("Herramientas Validate activas: %s", [tool.name for tool in tools])

    try:
        llm = get_llm("validate")
    except ValueError as e:
        logger.error(f"Error cargando LLM en Validate: {e}")
        fallback = build_fallback_validate_output(target_url, [], [], started_at)
        return fallback, "fallback"
    # 3. Construcción del Prompt del Sistema
    extra_instructions = ""

    if mandatory_sqlmap:
        extra_instructions = (
            "\nAVISO IMPORTANTE: SQLMap ya se ejecutó automáticamente para los endpoints proporcionados. "
            "Revisa los resultados adjuntos en la conversación antes de tomar decisiones. "
            "La herramienta 'sqlmap' no está disponible en esta fase y no debes intentar repetirla. "
            "Si la evidencia de SQLMap confirma la vulnerabilidad, procede directamente a invocar "
            "'submit_validate_output'.\n"
        )

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Especialista en Validación de Vulnerabilidades de Ciberseguridad.\n"
            f"Tu objetivo es comprobar fallos en la URL objetivo auditando endpoints prioritarios (Modalidad: '{attack_type}').\n\n"
            "REGLAS SOBRE PETICIONES:\n"
            "1. Cada target puede tener un campo 'request' con method, url, headers y body.\n"
            "2. Para SQLMap usa 'request' cuando exista; el servidor creará un archivo temporal dentro del contenedor.\n"
            "3. Solo si no existe 'request', usa 'target_url'. No inventes file_path ni rutas de archivos.\n\n"
            "GUÍA DE HERRAMIENTAS SEGÚN VECTOR:\n"
            "- Endpoints con parámetros de búsqueda o BD (SQLi) → 'sqlmap' (prefiere 'request')\n"
            "- Endpoints con parámetros reflejados o inputs de texto (XSS) → 'dalfox'\n"
            "- Endpoints con ejecuciones del sistema, pings o subida de archivos (Command Injection) → 'commix'\n"
            "- Cobertura multivectorial basada en plantillas → 'nuclei'\n"
            "- Fuzzing de rutas o parámetros con 'ffuf': la URL objetivo DEBE contener la palabra literal 'FUZZ'.\n\n"
            "REGLAS ESTRICTAS DE OPERACIÓN:\n"
            "1. Los parámetros de las herramientas se llaman EXACTAMENTE como aparecen en su schema. "
            "Por ejemplo, 'dalfox' espera 'target_url' (no 'url' ni 'target'), y 'sqlmap' acepta tanto "
            "'target_url' como alternativa a 'request'.\n\n"
            "REGLA CRÍTICA DE FINALIZACIÓN:\n"
            "Cuando termines, llama obligatoriamente a la herramienta 'submit_validate_output'. "
            "NO devuelvas el JSON como texto plano. "
            "NO inventes nombres de herramientas como 'ValidateOutput', 'json' o 'Vulnerability'. "
            "Estructura de argumentos de salida:\n"
            "- target_url: string\n"
            "- vulnerabilities: array de objetos con campos:\n"
            "    * type: 'SQL Injection', 'Cross-Site Scripting (XSS)', etc.\n"
            "    * severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'\n"
            "    * endpoint: URL afectada\n"
            "    * parameter: nombre del parámetro vulnerable (o vacío '')\n"
            "    * evidence: fragmento concreto de la respuesta anómala\n"
            "    * confidence: 'HIGH', 'MEDIUM', 'LOW'\n"
            "    * tools_used: ['sqlmap'] por ejemplo\n\n"
            "NO incluyas 'reproducible_command' en tu respuesta. El sistema lo asignará automáticamente.\n\n"
            + extra_instructions
        )
    )

    agent_executor = create_agent(model=llm, tools=tools, system_prompt=system_prompt)

    
    endpoints_str = json.dumps(selected_targets, indent=2)

    prompt_content = f"Valida vulnerabilidades en '{target_url}' (Filtro: {attack_type}).\n"
    prompt_content += f"Endpoints prioritarios a evaluar ({len(selected_targets)}):\n{endpoints_str}\n\n"

    if pre_executed_context:
        prompt_content += "EVIDENCIA DE HERRAMIENTAS PRE-EJECUTADAS:\n" + "\n".join(pre_executed_context)

    initial_input = {
        "messages": [
            HumanMessage(content=prompt_content)
        ]
    }

    raw_final_output = ""
    submitted_args: dict | None = None



    # Stream normal y detección de la herramienta de entrega estructurada.
    try:
        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 10}):
            for value in event.values():
                last_msg = value["messages"][-1]

                # tool_calls incluye tanto tools reales como el submit_validate_output
                if last_msg.type == "ai" and getattr(last_msg, "tool_calls", None):
                    for tc in last_msg.tool_calls:
                        tc_name = (
                            tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None)
                        )
                        tc_args = (
                            tc.get("args", {})
                            if isinstance(tc, dict)
                            else getattr(tc, "args", {}) or {}
                        )

                        if tc_name == "submit_validate_output":
                            submitted_args = tc_args
                            logger.info(
                                "[VALIDATE] Submit estructurado recibido con %d hallazgo(s).",
                                len(tc_args.get("vulnerabilities", [])),
                            )
                        elif tc_name:
                            cmd_str = build_real_command(tc_name, tc_args)
                            executed_commands.append(
                                {
                                    "tool": tc_name,
                                    "args": tc_args,
                                    "command": cmd_str,
                                }
                            )

                if last_msg.type == "tool":
                    if isinstance(last_msg.content, str):
                        raw_tool_outputs.append(last_msg.content)

                elif last_msg.type == "ai" and not getattr(last_msg, "tool_calls", None):
                    if isinstance(last_msg.content, str):
                        raw_final_output = last_msg.content

    except Exception as error:
        logger.error("Error durante la ejecución del agente Validate: %s", error)

    # Prioridad 1: argumentos de la herramienta de entrega.
    if submitted_args:
        try:
            validate_output = _build_output_from_args(submitted_args, target_url, started_at, executed_commands)
            mode = "clean"

            logger.info(f"✅ ValidateOutput construido ({len(validate_output.vulnerabilities)} " f"vulnerabilidades, mode={mode}).")
            logger.info(f"✅ ValidateOutput detalles: {validate_output}")

            return validate_output, mode
        except (ValidationError, KeyError, TypeError) as e:
            logger.warning(f"⚠️ Argumentos del submit tool inválidos: {e}")

    # PRIORIDAD 2: JSON en texto plano
    cleaned_json_str = clean_json_response(raw_final_output)
    if cleaned_json_str:
        try:
            parsed = json.loads(cleaned_json_str)
            parsed["scan_started_at"] = started_at
            parsed["scan_finished_at"] = datetime.now(timezone.utc).isoformat()

            # El LLM puede inventar comandos; sustituimos por el comando real que ejecutamos.
            for vuln in parsed.get("vulnerabilities", []):
                tool_list = vuln.get("tools_used", [])
                if not tool_list or not isinstance(tool_list, list):
                    continue

                tool_used = tool_list[0]
                real_cmd = next(
                    (c["command"] for c in executed_commands if c["tool"] == tool_used),
                    None,
                )

                if real_cmd:
                    vuln["reproducible_command"] = real_cmd
                else:
                    vuln["reproducible_command"] = (
                        f"Comando no verificado en ejecución real ({tool_used})"
                    )

            validate_output = ValidateOutput.model_validate(parsed)
            logger.info(
                f"✅ JSON de texto plano validado con éxito "
                f"({len(validate_output.vulnerabilities)} vulnerabilidades)."
            )
            return validate_output, "clean"
        except (ValidationError, json.JSONDecodeError) as e:
            logger.error(f"❌ Fallo al validar JSON de texto plano: {e}")

    return build_fallback_validate_output(target_url, raw_tool_outputs, executed_commands, started_at), "fallback"