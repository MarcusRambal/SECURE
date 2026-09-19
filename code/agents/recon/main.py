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

from contract_schemas import ReconOutput, DiscoveredEndpoint

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-agent-worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
SKILLS_QUEUE = "skills_queue"
RECON_QUEUE = "recon_queue"
MAX_ENDPOINTS_IN_OUTPUT = get_int_env("MAX_ENDPOINTS_IN_OUTPUT", 10)
MCP_OUTPUT_MAX_CHARS = get_int_env("MCP_OUTPUT_MAX_CHARS", 1500)
MAX_RECON_TOOL_CALLS = get_int_env("MAX_RECON_TOOL_CALLS", 2)
RECON_ONLY_TOOL = os.getenv("RECON_ONLY_TOOL", "").strip().lower()


# ============================================================================
# SCHEMAS PARA EL SUBMIT TOOL
# ============================================================================


class SimpleEndpoint(BaseModel):
    """Versión simplificada de DiscoveredEndpoint para tool calling."""

    url: str = Field(description="URL completa o ruta relativa del endpoint")
    method: str = Field(description="Método HTTP: GET, POST, PUT, DELETE, etc.")
    parameters: list[str] = Field(
        description="Parámetros detectados en la URL o body. Lista vacía [] si no hay."
    )


class SubmitReconInput(BaseModel):
    """Schema plano del submit tool para ReconOutput."""

    target_url: str = Field(description="URL principal analizada")
    endpoints: list[SimpleEndpoint] = Field(
        description="Lista completa de endpoints descubiertos"
    )
    technologies: list[str] = Field(
        description="Tecnologías detectadas (ej: Angular, Express). Lista vacía [] si no hay."
    )


async def _submit_recon_executor(**kwargs) -> str:
    """Ejecutor del submit tool. No hace nada real, solo devuelve acuse."""
    return "Recon report received. Task complete."


submit_recon_tool = StructuredTool.from_function(
    coroutine=_submit_recon_executor,
    name="submit_recon_output",
    description=(
        "OBLIGATORIO: Llama a esta herramienta EXACTAMENTE UNA VEZ al terminar el reconocimiento "
        "para entregar el reporte final estructurado. Esta es la ÚNICA forma válida de terminar. "
        "NO devuelvas el JSON como texto plano."
    ),
    args_schema=SubmitReconInput,
)


# ============================================================================
# HELPERS
# ============================================================================


def parse_raw_text_to_urls(raw_text: str) -> list[str]:
    """Extrae URLs de salidas crudas de herramientas MCP mediante expresiones regulares."""
    if not raw_text:
        return []
    urls_found = re.findall(r'https?://[^\s><")]+', raw_text)
    return list(dict.fromkeys(urls_found))


def clean_json_response(raw_response: str) -> str:
    """Elimina delimitadores de Markdown de código JSON si los hay."""
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

        # Caso típico: '{"name": "json", "arguments": {...}}'
        parsed = json.loads(failed_gen)
        args = parsed.get("arguments") if isinstance(parsed, dict) else None

        # A veces arguments viene como string JSON escapado
        if isinstance(args, str):
            args = json.loads(args)

        if isinstance(args, dict):
            return args

    except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as e:
        logger.warning(f"⚠️ [RECOVERY] No se pudo recuperar JSON del error: {e}")

    return None


def _build_from_submitted_args(args: dict, target_url: str, started_at: str) -> ReconOutput:
    """Construye un ReconOutput desde los argumentos del submit tool o del recovery."""
    endpoints_raw = args.get("endpoints", [])
    endpoints: list[DiscoveredEndpoint] = []

    for ep in endpoints_raw:
        if isinstance(ep, dict):
            endpoints.append(
                DiscoveredEndpoint(
                    url=ep.get("url", ""),
                    method=ep.get("method", "GET"),
                    parameters=ep.get("parameters", []) or [],
                    source="submit_tool",
                    notes=ep.get("notes", "") or "",
                )
            )

    technologies = args.get("technologies", [])
    if isinstance(technologies, str):
        technologies = [t.strip() for t in technologies.split(",") if t.strip()]

    recon_output = ReconOutput(
        target_url=args.get("target_url", target_url),
        endpoints=endpoints,
        technologies=technologies,
        passive_findings=[],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info("ReconOutput preparado con %d endpoints", len(recon_output.endpoints))
    return recon_output


def build_fallback_recon_output(
    target_url: str,
    raw_llm_text: str,
    raw_tool_outputs: list[str],
    started_at: str,
) -> ReconOutput:
    """
    Capa 3: Construye un ReconOutput usando las salidas crudas de las herramientas.
    Es la opción más degradada (marcada como PARTIAL por el worker).
    """
    logger.warning("Construyendo ReconOutput mediante fallback de regex...")

    combined_text = "\n".join(raw_tool_outputs) + "\n" + (raw_llm_text or "")
    urls = parse_raw_text_to_urls(combined_text)

    endpoint_limit = MAX_ENDPOINTS_IN_OUTPUT if MAX_ENDPOINTS_IN_OUTPUT > 0 else None
    endpoints = [
        DiscoveredEndpoint(url=u, method="GET", source="fallback_regex")
        for u in (urls[:endpoint_limit] if endpoint_limit else urls)
    ]
    if not endpoints:
        endpoints = [DiscoveredEndpoint(url=target_url, method="GET", source="target_root")]

    return ReconOutput(
        target_url=target_url,
        endpoints=endpoints,
        technologies=["Uncertain"],
        passive_findings=[],
        scan_started_at=started_at,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
    )


# ============================================================================
# MCP SKILLS
# ============================================================================


async def call_mcp_skill(channel: aio_pika.Channel, tool_name: str, arguments: dict) -> str:
    """Invoca una herramienta MCP en skills_controller a través de RabbitMQ."""
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
    """Consulta las herramientas MCP registradas en skills_controller."""
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


def build_recon_tools(mcp_catalog: list, channel: aio_pika.Channel) -> list:
    """Crea StructuredTools de LangChain para reconocimiento + submit tool."""
    langchain_tools = []
    recon_keywords = ["katana", "zap", "spider", "nikto"]

    from pydantic import create_model, Field

    for mcp_tool in mcp_catalog:
        tool_name = mcp_tool["name"]
        if RECON_ONLY_TOOL and tool_name.lower() != RECON_ONLY_TOOL:
            continue
        if not RECON_ONLY_TOOL and not any(kw in tool_name.lower() for kw in recon_keywords):
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

    langchain_tools.append(submit_recon_tool)
    return langchain_tools


# ============================================================================
# FLUJO PRINCIPAL DE RECONOCIMIENTO
# ============================================================================


async def process_recon_task(channel: aio_pika.Channel, target_url: str) -> tuple[ReconOutput, str]:
    """
    Ejecuta el pipeline de reconocimiento con 3 capas de resiliencia.

    Retorna:
        (ReconOutput, recovery_mode)
        recovery_mode ∈ {"clean", "recovered", "fallback"}
          - "clean": submit tool llamada correctamente.
          - "recovered": JSON recuperado del error 400 de Groq.
          - "fallback": regex sobre logs crudos (degradado).
    """
    started_at = datetime.now(timezone.utc).isoformat()

    catalog = await get_mcp_catalog(channel)
    tools =  build_recon_tools(catalog, channel)
    logger.info("Herramientas Recon activas: %s", [tool.name for tool in tools])

    if not tools or len(tools) <= 1:

        # Solo está el submit tool, no hay herramientas reales
        logger.error("No se encontraron herramientas MCP de reconocimiento disponibles.")
        empty = ReconOutput(
            target_url=target_url,
            endpoints=[],
            technologies=[],
            passive_findings=[],
            scan_started_at=started_at,
            scan_finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return empty, "fallback"

    llm = get_llm("recon")
    tool_limit_text = (
        "sin límite artificial"
        if MAX_RECON_TOOL_CALLS <= 0
        else f"máximo {MAX_RECON_TOOL_CALLS}"
    )
    endpoint_limit_text = (
        "sin límite artificial"
        if MAX_ENDPOINTS_IN_OUTPUT <= 0
        else f"máximo {MAX_ENDPOINTS_IN_OUTPUT}"
    )

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Especialista en Reconocimiento de Aplicaciones Web.\n"
            f"Tu objetivo es mapear la superficie del objetivo usando exclusivamente la herramienta '{RECON_ONLY_TOOL or 'las herramientas MCP disponibles'}'.\n\n"
            "REGLAS ESTRICTAS DE OPERACIÓN:\n"
            f"1. Puedes ejecutar {tool_limit_text} veces la herramienta '{RECON_ONLY_TOOL or 'de reconocimiento'}'.\n"
            f"2. Incluye {endpoint_limit_text} endpoints, priorizando rutas con parámetros, /api/, /rest/, /admin/, /login y formularios.\n\n"
            "REGLA CRÍTICA DE FINALIZACIÓN:\n"
            "Cuando termines de ejecutar las herramientas, NO escribas el JSON como texto plano. "
            "ESTÁS OBLIGADO a llamar a la herramienta 'submit_recon_output' pasando tus hallazgos "
            "como argumentos estructurados (target_url, endpoints, technologies). "
            "Esta es la ÚNICA forma válida de entregar tu reporte final. "
            "El sistema se encargará de procesarlo. Después de llamar a 'submit_recon_output', "
            "tu tarea termina.\n\n"
            "ESTRUCTURA DE ARGUMENTOS DE 'submit_recon_output':\n"
            "- target_url: string (URL principal)\n"
            "- endpoints: array completo de {url, method, parameters}\n"
            "- technologies: array de strings\n\n"
            "EJEMPLO DE LLAMADA VÁLIDA:\n"
            "submit_recon_output(\n"
            f'  target_url="{target_url}",\n'
            '  endpoints=[{"url": "/rest/user/login", "method": "POST", "parameters": ["email", "password"]}],\n'
            '  technologies=["Express", "Angular"]\n'
            ")"
        )
    )

    agent_executor = create_react_agent(model=llm, tools=tools, prompt=system_prompt)
    initial_input = {
        "messages": [HumanMessage(content=f"Analiza la superficie del objetivo '{target_url}'.")]
    }

    raw_final_output = ""
    raw_tool_outputs: list[str] = []
    submitted_args: dict | None = None

    # CAPA 1: stream normal + detección de submit tool
    try:
        async for event in agent_executor.astream(initial_input, config={"recursion_limit": 10}):
            for value in event.values():
                last_msg = value["messages"][-1]

                # Capturar salidas de herramientas para el fallback
                if last_msg.type == "tool":
                    if isinstance(last_msg.content, str):
                        raw_tool_outputs.append(last_msg.content)

                # Detectar tool_calls (reales y submit)
                elif last_msg.type == "ai" and getattr(last_msg, "tool_calls", None):
                    for tc in last_msg.tool_calls:
                        tc_name = (
                            tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", None)
                        )
                        if tc_name == "submit_recon_output":
                            tc_args = (
                                tc.get("args")
                                if isinstance(tc, dict)
                                else getattr(tc, "args", None)
                            )
                            if tc_args:
                                submitted_args = tc_args
                                logger.info(
                                    "🎯 [SUBMIT TOOL] Recibidos argumentos del submit tool."
                                )

                # Capturar texto plano final (por si el modelo ignora el submit)
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
            recon_output = _build_from_submitted_args(submitted_args, target_url, started_at)
            mode = "recovered" if not raw_final_output else "clean"
            logger.info(
                f"✅ ReconOutput construido ({len(recon_output.endpoints)} endpoints, "
                f"mode={mode})."
            )
            return recon_output, mode
        except (ValidationError, KeyError, TypeError) as e:
            logger.warning(f"⚠️ Argumentos del submit tool inválidos: {e}")

    # PRIORIDAD 2: JSON en texto plano
    cleaned_json_str = clean_json_response(raw_final_output)
    if cleaned_json_str:
        try:
            parsed = json.loads(cleaned_json_str)
            parsed["scan_started_at"] = started_at
            parsed["scan_finished_at"] = datetime.now(timezone.utc).isoformat()
            recon_output = ReconOutput.model_validate(parsed)
            logger.info(
                f"✅ JSON de texto plano validado con éxito "
                f"({len(recon_output.endpoints)} endpoints)."
            )
            return recon_output, "clean"
        except (ValidationError, json.JSONDecodeError) as e:
            logger.error(f"❌ Fallo al validar JSON de texto plano: {e}")

    # PRIORIDAD 3: fallback regex (degradado)
    fallback = build_fallback_recon_output(
        target_url, raw_final_output, raw_tool_outputs, started_at
    )
    return fallback, "fallback"


# ============================================================================
# WORKER
# ============================================================================


async def start_recon_worker():
    """Worker asíncrono que escucha solicitudes en recon_queue y responde con ReconOutput JSON."""
    while True:
        try:
            logger.info(f"Conectando Recon-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(RECON_QUEUE, durable=True)
                logger.info(f"🎧 Recon-Agent escuchando activamente en '{RECON_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to

                            try:
                                payload = json.loads(message.body.decode("utf-8"))
                                target_url = payload.get("target_url")
                                logger.info(f"📥 [RECON-AGENT] Tarea recibida para {target_url}")

                                recon_data, recovery_mode = await process_recon_task(
                                    channel, target_url
                                )

                                if recovery_mode == "fallback":
                                    status = "PARTIAL"
                                    used_fallback = True
                                else:
                                    # "clean" y "recovered" son éxitos limpios
                                    status = "SUCCESS"
                                    used_fallback = False

                                response_body = json.dumps(
                                    {
                                        "status": status,
                                        "used_fallback": used_fallback,
                                        "recovery_mode": recovery_mode,
                                        "recon_data": recon_data.model_dump(),
                                    }
                                )
                            except Exception as msg_error:
                                logger.error(
                                    f"❌ Error procesando mensaje Recon: {msg_error}",
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
                                        f"📤 [RECON-AGENT] Respuesta enviada a '{reply_to}'"
                                    )
                                except Exception as pub_error:
                                    logger.error(
                                        f"❌ No se pudo publicar respuesta RPC: {pub_error}"
                                    )
        except Exception as e:
            logger.warning(f"Error en Recon Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_recon_worker())
