import os
import re
import json
import uuid
import asyncio
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_int_env, get_llm

from pydantic import BaseModel, Field, ValidationError
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from langgraph.prebuilt import create_react_agent
from groq import APIStatusError

from contract_schemas import ValidateOutput, Vulnerability

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
SKILLS_QUEUE = "skills_queue"
VALIDATE_QUEUE = "validate_queue"

MAX_ENDPOINTS_TO_VALIDATE = get_int_env("MAX_ENDPOINTS_TO_VALIDATE", 10)
MCP_OUTPUT_MAX_CHARS = get_int_env("MCP_OUTPUT_MAX_CHARS", 1500)
MAX_VALIDATE_TOOL_CALLS = get_int_env("MAX_VALIDATE_TOOL_CALLS", 3)
VALIDATE_ONLY_TOOL = os.getenv("VALIDATE_ONLY_TOOL", "").strip().lower()
ALLOWED_ATTACK_TYPES = {"full", "sql_injection", "xss", "command_injection"}

# Mapeo estricto de herramientas permitidas según attack_type
TOOL_MAP = {
    "full": ["sqlmap", "dalfox", "commix", "nuclei", "ffuf"],
    "sql_injection": ["sqlmap"],
    "xss": ["dalfox"],
    "command_injection": ["commix"],
}

# IMPORTANTE: mantener sincronizado con skills_controller/tools/mcp_tools_registry.py
TOOL_COMMAND_TEMPLATES = {
    "sqlmap": 'sqlmap -r "{req_file_path}" --batch --level=5 --risk=3 --ignore-stdin --ignore-code=401 --no-escape',
    "dalfox": 'dalfox url "{target_url}" --silence',
    "commix": 'commix --url="{target_url}" --batch',
    "nuclei": 'nuclei -u "{target_url}" -tags {tags} -silent -nc',
    "ffuf": 'ffuf -u "{target_url}" -w /wordlists/common.txt -s',
}


# ============================================================================
# SCHEMAS PARA EL SUBMIT TOOL
# ============================================================================


class SimpleVulnerability(BaseModel):
    """Versión simplificada de Vulnerability para tool calling.

    Nota: reproducible_command NO se le pide al modelo. El código lo asigna
    después a partir de los comandos reales ejecutados.
    """

    type: str = Field(description="Tipo (ej: SQL Injection, XSS, OS Command Injection)")
    severity: str = Field(description="Severidad: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    endpoint: str = Field(description="Endpoint o URL afectada")
    parameter: str = Field(default="", description="Parámetro vulnerable (vacío si no aplica)")
    evidence: str = Field(
        description="Evidencia concreta observada (fragmento de respuesta anómala)"
    )
    confidence: str = Field(description="Certeza: HIGH, MEDIUM, LOW")
    tools_used: list[str] = Field(
        description="Herramientas que confirmaron el hallazgo (ej: ['sqlmap'])"
    )


class SubmitValidateInput(BaseModel):
    """Schema plano del submit tool para ValidateOutput."""

    target_url: str = Field(description="URL objetivo de la auditoría")
    vulnerabilities: list[SimpleVulnerability] = Field(
        description="Lista de vulnerabilidades confirmadas. Lista vacía [] si no hay."
    )


async def _submit_validate_executor(**kwargs) -> str:
    """Ejecutor del submit tool. No hace nada real, solo acuse."""
    return "Validation report received. Task complete."


submit_validate_tool = StructuredTool.from_function(
    coroutine=_submit_validate_executor,
    name="submit_validate_output",
    description=(
        "OBLIGATORIO: Llama a esta herramienta EXACTAMENTE UNA VEZ al terminar la validación "
        "para entregar el reporte final de vulnerabilidades confirmadas. Esta es la ÚNICA "
        "forma válida de terminar. NO devuelvas el JSON como texto plano. NO inventes "
        "nombres de herramientas como 'ValidateOutput', 'json' o 'Vulnerability'."
    ),
    args_schema=SubmitValidateInput,
)


# ============================================================================
# HELPERS EXISTENTES
# ============================================================================


def sanitize_attack_type(attack_type: str) -> str:
    """Valida y sanitiza el attack_type recibido."""
    if VALIDATE_ONLY_TOOL == "sqlmap":
        return "sql_injection"
    if not attack_type or attack_type.lower() not in ALLOWED_ATTACK_TYPES:
        logger.warning(f"attack_type '{attack_type}' no reconocido. Aplicando 'full'.")
        return "full"
    return attack_type.lower()


def prioritize_endpoints(endpoints: list[dict]) -> list[dict]:
    """Deduplica endpoints y los prioriza según parámetros o rutas sensibles."""
    seen_urls = set()
    unique_endpoints = []

    for ep in endpoints:
        url = ep.get("url", "").strip()
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_endpoints.append(ep)

    def score(ep: dict) -> int:
        u = ep.get("url", "").lower()
        params = ep.get("parameters", [])
        s = 0
        if params:
            s += 10
        if any(kw in u for kw in ["login", "admin", "api", "rest", "user", "search", "query", "="]):
            s += 5
        return s

    sorted_endpoints = sorted(unique_endpoints, key=score, reverse=True)
    if MAX_ENDPOINTS_TO_VALIDATE <= 0:
        return sorted_endpoints
    return sorted_endpoints[:MAX_ENDPOINTS_TO_VALIDATE]


def build_real_command(tool_name: str, args: dict) -> str:
    """Construye el comando CLI exacto según la plantilla real y los argumentos ejecutados."""
    template = TOOL_COMMAND_TEMPLATES.get(tool_name)
    if not template:
        return f"{tool_name} {json.dumps(args)}"
    try:
        # Copia local para no mutar el diccionario original
        local_args = dict(args)
        if "{tags}" in template and "tags" not in local_args:
            local_args["tags"] = "xss,sqli,rce"
        return template.format(**local_args)
    except Exception:
        return f"{tool_name} {json.dumps(args)}"


def extract_evidence_line(raw_outputs: list[str], pattern: str, max_len: int = 300) -> str:
    """Extrae la primera línea de evidencia concreta truncada a max_len."""
    regex = re.compile(pattern, re.IGNORECASE)
    for output in raw_outputs:
        for line in output.splitlines():
            if regex.search(line):
                return line.strip()[:max_len]
    return ""


def clean_json_response(raw_response: str) -> str:
    """Limpia la salida del LLM eliminando bloques de código Markdown."""
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _extract_from_groq_error(error: APIStatusError) -> dict | None:
    """
    Capa 2: Intenta recuperar el JSON que el modelo quiso entregar cuando Groq
    rechazó un tool_call inventado (code='tool_use_failed'). Devuelve el dict de
    arguments si tiene éxito, o None si el JSON viene truncado o corrupto.
    """
    try:
        error_body = getattr(error, "body", None) or {}
        if not isinstance(error_body, dict):
            return None

        inner = error_body.get("error", error_body)
        if not isinstance(inner, dict):
            return None

        code = inner.get("code")
        if code != "tool_use_failed":
            return None

        failed_gen = inner.get("failed_generation", "")
        if not failed_gen:
            return None

        logger.info(
            f"🔍 [RECOVERY] Intentando recuperar JSON de failed_generation "
            f"({len(failed_gen)} chars)"
        )

        parsed = json.loads(failed_gen)
        args = parsed.get("arguments") if isinstance(parsed, dict) else None

        if isinstance(args, str):
            args = json.loads(args)

        if isinstance(args, dict):
            return args

    except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as e:
        logger.warning(f"⚠️ [RECOVERY] No se pudo recuperar JSON del error: {e}")

    return None


def _build_output_from_args(
    args: dict,
    target_url: str,
    started_at: str,
    executed_commands: list[dict],
) -> ValidateOutput:
    """Construye un ValidateOutput desde los argumentos del submit tool o del recovery.

    Reemplaza el campo reproducible_command por el comando real ejecutado según
    la primera herramienta listada en tools_used.
    """
    vulns_raw = args.get("vulnerabilities", []) or []
    vulnerabilities: list[Vulnerability] = []

    for v in vulns_raw:
        if not isinstance(v, dict):
            continue

        tools_used = v.get("tools_used", []) or []
        if isinstance(tools_used, str):
            tools_used = [t.strip() for t in tools_used.split(",") if t.strip()]

        # Determinar comando reproducible real
        real_cmd = "Comando no verificado"
        if tools_used:
            tool_used = tools_used[0]
            real_cmd = next(
                (c["command"] for c in executed_commands if c["tool"] == tool_used),
                f"Comando no verificado en ejecución real ({tool_used})",
            )
        else:
            real_cmd = (
                f"Comando no verificado (sin tools_used) para {v.get('endpoint', target_url)}"
            )

        parameter = v.get("parameter", "") or None

        try:
            vulnerabilities.append(
                Vulnerability(
                    type=v.get("type", "Unknown"),
                    severity=v.get("severity", "MEDIUM"),
                    endpoint=v.get("endpoint", target_url),
                    parameter=parameter,
                    evidence=v.get("evidence", "Sin evidencia textual"),
                    reproducible_command=real_cmd,
                    confidence=v.get("confidence", "MEDIUM"),
                    tools_used=tools_used,
                )
            )
        except ValidationError as e:
            logger.warning(f"⚠️ Vulnerabilidad descartada por schema inválido: {e}")

    return ValidateOutput(
        target_url=args.get("target_url", target_url),
        vulnerabilities=vulnerabilities,
        unconfirmed_findings=[],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


def build_fallback_validate_output(
    target_url: str,
    raw_tool_outputs: list[str],
    executed_commands: list[dict],
    started_at: str,
) -> ValidateOutput:
    """Capa 3: Construye un ValidateOutput por regex extrayendo evidencia truncada."""
    logger.warning("Construyendo ValidateOutput mediante fallback por regex extendido...")
    vulnerabilities = []

    # 1. SQLMap
    sql_evidence = extract_evidence_line(raw_tool_outputs, r"sqlmap identified|dbms:|syntax error")
    if sql_evidence:
        cmd = next(
            (c["command"] for c in executed_commands if c["tool"] == "sqlmap"),
            f"sqlmap -u '{target_url}' --batch",
        )
        vulnerabilities.append(
            Vulnerability(
                type="SQL Injection",
                severity="HIGH",
                endpoint=target_url,
                evidence=sql_evidence,
                reproducible_command=cmd,
                confidence="HIGH",
                tools_used=["sqlmap"],
            )
        )

    # 2. DalFox (XSS)
    xss_evidence = extract_evidence_line(raw_tool_outputs, r"\[POC\]|\[V\]|\[FOUND\]|xss payload")
    if xss_evidence:
        cmd = next(
            (c["command"] for c in executed_commands if c["tool"] == "dalfox"),
            f"dalfox url '{target_url}'",
        )
        vulnerabilities.append(
            Vulnerability(
                type="Cross-Site Scripting (XSS)",
                severity="MEDIUM",
                endpoint=target_url,
                evidence=xss_evidence,
                reproducible_command=cmd,
                confidence="HIGH",
                tools_used=["dalfox"],
            )
        )

    # 3. Commix (Command Injection)
    rce_evidence = extract_evidence_line(
        raw_tool_outputs, r"vulnerable to.*command injection|is vulnerable|os command"
    )
    if rce_evidence:
        cmd = next(
            (c["command"] for c in executed_commands if c["tool"] == "commix"),
            f"commix --url='{target_url}' --batch",
        )
        vulnerabilities.append(
            Vulnerability(
                type="OS Command Injection",
                severity="CRITICAL",
                endpoint=target_url,
                evidence=rce_evidence,
                reproducible_command=cmd,
                confidence="HIGH",
                tools_used=["commix"],
            )
        )

    # 4. Nuclei
    nuclei_evidence = extract_evidence_line(raw_tool_outputs, r"\[(critical|high|medium|low)\]")
    if nuclei_evidence:
        cmd = next(
            (c["command"] for c in executed_commands if c["tool"] == "nuclei"),
            f"nuclei -u '{target_url}'",
        )
        sev = "HIGH"
        if "[critical]" in nuclei_evidence.lower():
            sev = "CRITICAL"
        elif "[medium]" in nuclei_evidence.lower():
            sev = "MEDIUM"
        elif "[low]" in nuclei_evidence.lower():
            sev = "LOW"

        vulnerabilities.append(
            Vulnerability(
                type="Template Vulnerability (Nuclei)",
                severity=sev,
                endpoint=target_url,
                evidence=nuclei_evidence,
                reproducible_command=cmd,
                confidence="HIGH",
                tools_used=["nuclei"],
            )
        )

    return ValidateOutput(
        target_url=target_url,
        vulnerabilities=vulnerabilities,
        unconfirmed_findings=[
            {"fallback_note": "Respuesta LLM corrupta. Hallazgos recuperados desde logs."}
        ],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


# ============================================================================
# MCP SKILLS
# ============================================================================


async def call_mcp_skill(channel: aio_pika.Channel, tool_name: str, arguments: dict) -> str:
    """Invoca una herramienta de validación MCP a través de RabbitMQ."""
    correlation_id = str(uuid.uuid4())
    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                if not future.done():
                    future.set_result(json.loads(message.body.decode("utf-8")))

    consumer_tag = await reply_queue.consume(on_response)

    mcp_payload = {
        "jsonrpc": "2.0",
        "id": correlation_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(mcp_payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
        ),
        routing_key=SKILLS_QUEUE,
    )

    try:
        response = await asyncio.wait_for(future, timeout=1000.0)
        content = response.get("result", {}).get("content", [])
        raw_output = content[0].get("text", "") if content else json.dumps(response)
        await asyncio.sleep(2)

        # NOTA: el output de la herramienta se acumula en el contexto del LLM
        # y consume ITPM. Limitamos a 1500 caracteres para preservar el cupo.
        if MCP_OUTPUT_MAX_CHARS > 0 and len(raw_output) > MCP_OUTPUT_MAX_CHARS:
            raw_output = (
                raw_output[:MCP_OUTPUT_MAX_CHARS]
                + f"\n\n[... salida truncada. Total original: {len(raw_output)} caracteres]"
            )
        return raw_output
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


async def get_mcp_catalog(channel: aio_pika.Channel) -> list:
    """Obtiene el catálogo de herramientas activas en el servidor MCP."""
    correlation_id = str(uuid.uuid4())
    reply_queue = await channel.declare_queue(exclusive=True)
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                if not future.done():
                    future.set_result(json.loads(message.body.decode("utf-8")))

    consumer_tag = await reply_queue.consume(on_response)

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(
                {"jsonrpc": "2.0", "id": correlation_id, "method": "tools/list"}
            ).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
        ),
        routing_key=SKILLS_QUEUE,
    )

    try:
        response = await asyncio.wait_for(future, timeout=30.0)
        return response.get("result", {}).get("tools", [])
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


def build_validation_tools(mcp_catalog: list, channel: aio_pika.Channel, attack_type: str) -> list:
    """Construye herramientas LangChain orientadas al attack_type + submit tool."""
    langchain_tools = []
    allowed_tools = (
        [VALIDATE_ONLY_TOOL] if VALIDATE_ONLY_TOOL else TOOL_MAP.get(attack_type, TOOL_MAP["full"])
    )

    from pydantic import create_model, Field

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        if tool_name not in allowed_tools:
            continue

        description = mcp_tool["description"]
        input_schema = mcp_tool.get("inputSchema", {})
        properties = input_schema.get("properties", {})
        required_fields = input_schema.get("required", [])

        fields = {}
        for prop_name, prop_info in properties.items():
            prop_type = int if prop_info.get("type") == "integer" else str
            prop_desc = prop_info.get("description", "")
            if prop_name in required_fields:
                fields[prop_name] = (prop_type, Field(..., description=prop_desc))
            else:
                fields[prop_name] = (
                    prop_type,
                    Field(prop_info.get("default", None), description=prop_desc),
                )

        ArgsSchema = create_model(f"{tool_name}_schema", **fields)

        def make_executor(name):
            async def _executor(**kwargs):
                return await call_mcp_skill(channel, name, kwargs)

            return _executor

        tool_instance = StructuredTool.from_function(
            coroutine=make_executor(tool_name),
            name=tool_name,
            description=description,
            args_schema=ArgsSchema,
        )
        langchain_tools.append(tool_instance)

    langchain_tools.append(submit_validate_tool)
    return langchain_tools


# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================


async def process_validate_task(
    channel: aio_pika.Channel,
    target_url: str,
    attack_type: str,
    recon_data: dict,
) -> tuple[ValidateOutput, str]:
    """
    Ejecuta la fase de validación con 3 capas de resiliencia.

    Retorna:
        (ValidateOutput, recovery_mode)
        recovery_mode ∈ {"clean", "recovered", "fallback"}
    """
    started_at = datetime.now(timezone.utc).isoformat()
    clean_attack_type = sanitize_attack_type(attack_type)

    raw_endpoints = recon_data.get("endpoints", [])
    if not raw_endpoints:
        raw_endpoints = [
            {
                "url": target.get("endpoint", ""),
                "method": target.get("method", "GET"),
                "parameters": target.get("injectable_parameters", []),
                "req_file_path": target.get("req_file_path", ""),
            }
            for target in recon_data.get("high_priority_targets", [])
            if isinstance(target, dict) and target.get("endpoint")
        ]

    if not raw_endpoints:
        logger.warning("Recon no devolvió endpoints. Omisión de la fase de validación.")
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{"reason": "Recon sin endpoints descubiertos"}],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",  # No es fallback real, es omisión controlada
        )

    selected_endpoints = prioritize_endpoints(raw_endpoints)

    catalog = await get_mcp_catalog(channel)
    tools = build_validation_tools(catalog, channel, clean_attack_type)
    logger.info("Herramientas Validate activas: %s", [tool.name for tool in tools])

    real_tools = [t for t in tools if t.name != "submit_validate_output"]
    if not real_tools:
        logger.error(
            f"No hay herramientas MCP disponibles para el attack_type '{clean_attack_type}'."
        )
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
        )

    try:
        llm = get_llm("validate")
    except ValueError as e:
        logger.error(f"Error cargando LLM en Validate: {e}")
        fallback = build_fallback_validate_output(target_url, [], [], started_at)
        return fallback, "fallback"

    tool_limit_text = (
        "sin límite artificial"
        if MAX_VALIDATE_TOOL_CALLS <= 0
        else f"máximo {MAX_VALIDATE_TOOL_CALLS}"
    )

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Especialista en Validación de Vulnerabilidades de Ciberseguridad.\n"
            f"Tu objetivo es comprobar fallos en la URL objetivo auditando endpoints prioritarios (Modalidad: '{clean_attack_type}').\n\n"
            "REGLAS SOBRE RUTAS DE PETICIÓN:\n"
            "1. Cada target en 'high_priority_targets' puede tener un campo 'req_file_path' "
            "con la ruta a un archivo .req que contiene la petición HTTP completa (método, headers, body).\n"
            "2. PREFIERE SIEMPRE usar 'req_file_path' sobre 'target_url' cuando exista. "
            "Las herramientas lo necesitan para atacar endpoints con POST, headers o body específicos.\n"
            "3. Solo si 'req_file_path' no existe o está vacío, usa 'target_url'.\n\n"
            "GUÍA DE HERRAMIENTAS SEGÚN VECTOR:\n"
            "- Endpoints con parámetros de búsqueda o BD (SQLi) → 'sqlmap' (prefiere 'req_file_path')\n"
            "- Endpoints con parámetros reflejados o inputs de texto (XSS) → 'dalfox'\n"
            "- Endpoints con ejecuciones del sistema, pings o subida de archivos (Command Injection) → 'commix'\n"
            "- Cobertura multivectorial basada en plantillas → 'nuclei'\n"
            "- Fuzzing de rutas o parámetros con 'ffuf': la URL objetivo DEBE contener la palabra literal 'FUZZ'.\n\n"
            "REGLAS ESTRICTAS DE OPERACIÓN:\n"
            f"1. Ejecuta {tool_limit_text} veces la herramienta '{VALIDATE_ONLY_TOOL or 'permitida'}'.\n"
            "2. Los parámetros de las herramientas se llaman EXACTAMENTE como aparecen en su schema. "
            "Por ejemplo, 'dalfox' espera 'target_url' (no 'url' ni 'target'), y 'sqlmap' acepta tanto "
            "'target_url' como 'req_file_path'.\n\n"
            "REGLA CRÍTICA DE FINALIZACIÓN:\n"
            "Cuando termines, NO devuelvas el JSON como texto plano. "
            "ESTÁS OBLIGADO a llamar a la herramienta 'submit_validate_output' pasando tus hallazgos "
            "como argumentos estructurados (target_url, vulnerabilities). "
            "NO inventes nombres de herramientas como 'ValidateOutput', 'json' o 'Vulnerability'. "
            "La ÚNICA herramienta de finalización válida es 'submit_validate_output'.\n\n"
            "ESTRUCTURA DE ARGUMENTOS DE 'submit_validate_output':\n"
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
            "EJEMPLO DE LLAMADA VÁLIDA:\n"
            "submit_validate_output(\n"
            f'  target_url="{target_url}",\n'
            '  vulnerabilities=[{"type": "SQL Injection", "severity": "HIGH", '
            '"endpoint": "/rest/user/login", "parameter": "email", '
            '"evidence": "Payload boolean-based blind confirmado por SQLMap", '
            '"confidence": "HIGH", "tools_used": ["sqlmap"]}]\n'
            ")\n\n"
        )
    )

    agent_executor = create_react_agent(model=llm, tools=tools, prompt=system_prompt)

    endpoints_str = json.dumps(selected_endpoints, indent=2)
    initial_input = {
        "messages": [
            HumanMessage(
                content=(
                    f"Valida vulnerabilidades en '{target_url}' (Filtro: {clean_attack_type}).\n"
                    f"Endpoints prioritarios a evaluar ({len(selected_endpoints)}):\n{endpoints_str}"
                )
            )
        ]
    }

    raw_final_output = ""
    raw_tool_outputs: list[str] = []
    executed_commands: list[dict] = []
    submitted_args: dict | None = None

    # CAPA 1: stream normal + detección de submit tool
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
                            logger.info("🎯 [SUBMIT TOOL] Recibidos argumentos del submit tool.")
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

    except APIStatusError as e:
        # CAPA 2: recuperar del error 400 de Groq
        logger.warning(f"⚠️ Groq APIStatusError interceptado (status={e.status_code})")
        recovered = _extract_from_groq_error(e)
        if recovered:
            submitted_args = recovered
            logger.info("🎯 [RECOVERY] JSON recuperado del error de Groq.")

    # PRIORIDAD 1: submit tool o recovery
    if submitted_args:
        try:
            validate_output = _build_output_from_args(
                submitted_args, target_url, started_at, executed_commands
            )
            mode = "recovered" if not raw_final_output else "clean"
            logger.info(
                f"✅ ValidateOutput construido ({len(validate_output.vulnerabilities)} "
                f"vulnerabilidades, mode={mode})."
            )
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

    # PRIORIDAD 3: fallback regex (degradado)
    fallback = build_fallback_validate_output(
        target_url, raw_tool_outputs, executed_commands, started_at
    )
    return fallback, "fallback"


# ============================================================================
# WORKER
# ============================================================================


async def start_validate_worker():
    """Worker asíncrono que procesa solicitudes en validate_queue."""
    while True:
        try:
            logger.info(f"Conectando Validate-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(VALIDATE_QUEUE, durable=True)
                logger.info(f"🎧 Validate-Agent escuchando activamente en '{VALIDATE_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to

                            try:
                                payload = json.loads(message.body.decode("utf-8"))
                                target_url = payload.get("target_url")
                                attack_type = payload.get("attack_type", "full")
                                recon_data = payload.get("recon_data", {})

                                logger.info(
                                    f"📥 [VALIDATE-AGENT] Tarea de validación recibida para {target_url}"
                                )

                                validate_data, recovery_mode = await process_validate_task(
                                    channel, target_url, attack_type, recon_data
                                )

                                if recovery_mode == "fallback":
                                    status = "PARTIAL"
                                    used_fallback = True
                                else:
                                    status = "SUCCESS"
                                    used_fallback = False

                                response_body = json.dumps(
                                    {
                                        "status": status,
                                        "used_fallback": used_fallback,
                                        "recovery_mode": recovery_mode,
                                        "validation_data": validate_data.model_dump(),
                                    }
                                )
                            except Exception as msg_error:
                                logger.error(
                                    f"❌ Error procesando mensaje Validate: {msg_error}",
                                    exc_info=True,
                                )
                                response_body = json.dumps(
                                    {
                                        "status": "ERROR",
                                        "error": str(msg_error),
                                    }
                                )

                            if reply_to:
                                try:
                                    await channel.default_exchange.publish(
                                        aio_pika.Message(
                                            body=response_body.encode("utf-8"),
                                            correlation_id=correlation_id,
                                            content_type="application/json",
                                        ),
                                        routing_key=reply_to,
                                    )
                                    logger.info(
                                        f"📤 [VALIDATE-AGENT] Respuesta enviada a '{reply_to}'"
                                    )
                                except Exception as pub_error:
                                    logger.error(
                                        f"❌ No se pudo publicar respuesta RPC: {pub_error}"
                                    )
        except Exception as e:
            logger.warning(f"Error en Validate Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_validate_worker())
