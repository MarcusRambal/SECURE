import os
import re
import json
import uuid
import asyncio
import logging
import aio_pika
from datetime import datetime, timezone
from llm_factory import get_int_env, get_llm

from typing import List
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.agents import create_agent

from contract_schemas import ReconSummary, HighPriorityTarget, ReconPlannerOutput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-agent-worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
SKILLS_QUEUE = "skills_queue"
RECON_QUEUE = "recon_queue"
MCP_OUTPUT_MAX_CHARS = get_int_env("MCP_OUTPUT_MAX_CHARS", 1500)


def log_preview(value: object, limit: int = 500) -> str:
    """Resume valores grandes para mantener los logs legibles y seguros."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text)} chars]"


# ============================================================================
# HELPERS
# ============================================================================


def clean_json_response(raw_response: str) -> str:
    """Extrae exclusivamente el JSON del bloque Markdown final del LLM."""
    match = re.search(r"```json\s*(.*?)\s*```", raw_response, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        raise ValueError("La respuesta del LLM no contiene un bloque ```json```")
    return match.group(1).strip()


def deduplicate_urls(*url_groups: list[str]) -> list[str]:
    """Combina descubrimientos manteniendo el primer origen de cada URL."""
    unique_urls: list[str] = []
    seen: set[str] = set()
    for group in url_groups:
        for url in group:
            normalized_url = url.strip().rstrip(".,);]")
            if normalized_url and normalized_url not in seen:
                seen.add(normalized_url)
                unique_urls.append(normalized_url)
    return unique_urls


def extract_urls_from_katana(raw_output: str) -> list[str]:
    """Extrae URLs tanto de la salida plana como de líneas JSON de Katana."""
    return deduplicate_urls(
        re.findall(r"https?://[^\s\"<>]+", raw_output or "")
    )


def load_request_context(max_files: int = 12, max_chars: int = 18000) -> dict:
    """Lee una muestra priorizada de requests raw y resume el HAR disponible."""
    requests_dir = "/app/requests"
    request_files = []
    for filename in os.listdir(requests_dir) if os.path.isdir(requests_dir) else []:
        if filename.endswith(".req"):
            request_files.append(filename)

    def request_priority(filename: str) -> tuple[int, str]:
        upper_name = filename.upper()
        priority = 0
        if "POST" in upper_name:
            priority -= 3
        if any(keyword in upper_name for keyword in ("LOGIN", "SEARCH", "QUERY", "USER")):
            priority -= 2
        return priority, filename

    selected_files = sorted(request_files, key=request_priority)[:max_files]
    samples = []
    chars_used = 0
    for filename in selected_files:
        path = os.path.join(requests_dir, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as request_file:
                content = request_file.read()
        except OSError:
            logger.warning("[RECON] No se pudo leer request raw: %s", path)
            continue

        remaining = max_chars - chars_used
        if remaining <= 0:
            break
        content = content[:remaining]
        samples.append({"file": f"/app/requests/{filename}", "raw": content})
        chars_used += len(content)

    har_path = os.path.join(requests_dir, "session_traffic.har")
    har_summary = {
        "file": "/app/requests/session_traffic.har",
        "exists": os.path.isfile(har_path),
        "size_bytes": os.path.getsize(har_path) if os.path.isfile(har_path) else 0,
    }
    if har_summary["exists"]:
        try:
            with open(har_path, "r", encoding="utf-8") as har_file:
                har_data = json.load(har_file)
            har_summary["entries"] = len(har_data.get("log", {}).get("entries", []))
        except (OSError, json.JSONDecodeError):
            har_summary["entries"] = "unavailable"

    return {
        "request_files_available": len(request_files),
        "request_samples": samples,
        "har": har_summary,
    }


def persist_recon_artifact(filename: str, content: str) -> None:
    """Guarda artefactos del reconocimiento en el volumen compartido."""
    artifact_path = os.path.join("/app/requests", filename)
    try:
        os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
        with open(artifact_path, "w", encoding="utf-8") as artifact_file:
            artifact_file.write(content)
        logger.info("[RECON] Artefacto guardado: %s", artifact_path)
    except OSError:
        logger.exception("[RECON] No se pudo guardar el artefacto: %s", artifact_path)


def build_planner_output_from_dict( data: dict, target_url: str, attack_type_filter: str) -> ReconPlannerOutput:
    """
    Capa 1/2: Construye y valida un ReconPlannerOutput a partir de un diccionario JSON
    extraído de la respuesta del LLM.
    """
    summary_data = data.get("recon_summary", {})
    targets_data = data.get("high_priority_targets", [])

    # Garantizar campos mínimos en recon_summary si vienen incompletos
    summary = ReconSummary(
        target_url=summary_data.get("target_url", target_url),
        attack_type_filter=summary_data.get("attack_type_filter", attack_type_filter),
        total_targets_identified=summary_data.get("total_targets_identified", len(targets_data)),
        har_session_file=summary_data.get("har_session_file", "/app/requests/session_traffic.har")
    )

    targets: List[HighPriorityTarget] = []
    for idx, t in enumerate(targets_data, start=1):
        if isinstance(t, dict):
            targets.append(
                HighPriorityTarget(
                    target_id=t.get("target_id", f"target_{idx:03d}"),
                    vulnerability_target=t.get("vulnerability_target", f"{attack_type_filter} Vulnerability"),
                    endpoint=t.get("endpoint", target_url),
                    method=t.get("method", "GET").upper(),
                    req_file_path=t.get("req_file_path", ""),
                    recommended_tool=t.get("recommended_tool", "sqlmap")
                )
            )

    output = ReconPlannerOutput(
        recon_summary=summary,
        high_priority_targets=targets
    )
    
    logger.info("ReconPlannerOutput preparado con %d objetivos prioritarios", len(output.high_priority_targets))
    return output


# ============================================================================
# MCP SKILLS
# ============================================================================


async def call_mcp_skill(
    channel: aio_pika.Channel,
    tool_name: str,
    arguments: dict,
    max_output_chars: int | None = None,
) -> str:
    """Invoca una herramienta MCP en skills_controller a través de RabbitMQ."""
    correlation_id = str(uuid.uuid4())
    logger.info(
        "[MCP] Publicando tool=%s correlation_id=%s arguments=%s",
        tool_name,
        correlation_id,
        log_preview(arguments),
    )
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
        logger.info(
            "[MCP] Respuesta recibida tool=%s correlation_id=%s is_error=%s",
            tool_name,
            correlation_id,
            response.get("result", {}).get("isError", False),
        )
        is_error = response.get("result", {}).get("isError", False)
        content = response.get("result", {}).get("content", [])
        raw_output = content[0].get("text", "") if content else json.dumps(response)
        if is_error:
            raise RuntimeError(f"MCP tool '{tool_name}' failed: {raw_output}")
        await asyncio.sleep(2)

        # NOTA: el output de la herramienta se acumula en el contexto del LLM
        # y consume ITPM. Limitamos a 1500 caracteres para preservar el cupo.
        output_limit = MCP_OUTPUT_MAX_CHARS if max_output_chars is None else max_output_chars
        if output_limit > 0 and len(raw_output) > output_limit:
            raw_output = (
            raw_output[:output_limit]
                + f"\n\n[... salida truncada. Total original: {len(raw_output)} caracteres]"
            )
        logger.info(
            "[MCP] Resultado tool=%s chars=%d preview=%s",
            tool_name,
            len(raw_output),
            log_preview(raw_output),
        )
        return raw_output
    except Exception:
        logger.exception("[MCP] Error esperando respuesta tool=%s correlation_id=%s", tool_name, correlation_id)
        raise
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


async def get_mcp_catalog(channel: aio_pika.Channel) -> list:
    """Consulta las herramientas MCP registradas en skills_controller."""
    correlation_id = str(uuid.uuid4())
    logger.info("[MCP] Solicitando catálogo correlation_id=%s", correlation_id)
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
        tools = response.get("result", {}).get("tools", [])
        logger.info(
            "[MCP] Catálogo recibido correlation_id=%s tools=%d names=%s",
            correlation_id,
            len(tools),
            [tool.get("name") for tool in tools],
        )
        return tools
    except Exception:
        logger.exception("[MCP] Error obteniendo catálogo correlation_id=%s", correlation_id)
        raise
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


# ============================================================================
# FLUJO PRINCIPAL DE RECONOCIMIENTO
# ============================================================================


async def process_recon_task(
    channel: aio_pika.Channel,
    target_url: str,
    attack_type_filter: str = "full",
) -> tuple[ReconPlannerOutput, str]:
    """
    Ejecuta el pipeline de reconocimiento con 3 capas de resiliencia.

        Retorna el plan validado y el modo de recuperación usado.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    logger.info(
        "[RECON] Inicio target=%s attack_type=%s started_at=%s output_limit=%s",
        target_url,
        attack_type_filter,
        started_at,
        MCP_OUTPUT_MAX_CHARS,
    )

    catalog = await get_mcp_catalog(channel)
    catalog_names = {tool.get("name") for tool in catalog}
    mandatory_tools = {"spa_crawler", "katana_full"}
    missing_tools = mandatory_tools - catalog_names
    if missing_tools:
        raise RuntimeError(
            f"Faltan herramientas obligatorias de Recon en MCP: {sorted(missing_tools)}"
        )

    logger.info("[RECON] Fase obligatoria 1/2: ejecutando spa_crawler target=%s", target_url)
    crawler_output = await call_mcp_skill(
        channel,
        "spa_crawler",
        {"target_url": target_url},
        max_output_chars=max(MCP_OUTPUT_MAX_CHARS, 12000),
    )
    try:
        crawler_data = json.loads(crawler_output)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"spa_crawler no devolvió JSON válido: {error}") from error

    crawler_data["har_file"] = "/app/requests/session_traffic.har"
    logger.info(
        "[RECON] spa_crawler completado captured=%s routes=%d api=%d har=%s",
        crawler_data.get("captured_requests_count", "unknown"),
        len(crawler_data.get("navigation_routes", [])),
        len(crawler_data.get("api_endpoints", [])),
        crawler_data["har_file"],
    )

    logger.info("[RECON] Fase obligatoria 2/2: ejecutando katana_full target=%s", target_url)
    katana_output = await call_mcp_skill(
        channel,
        "katana_full",
        {"target_url": target_url},
        max_output_chars=max(MCP_OUTPUT_MAX_CHARS, 12000),
    )
    katana_urls = extract_urls_from_katana(katana_output)
    crawler_urls = deduplicate_urls(
        crawler_data.get("navigation_routes", []),
        crawler_data.get("api_endpoints", []),
    )
    discovered_urls = deduplicate_urls(crawler_urls, katana_urls)
    request_context = load_request_context()
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
        "request_context": request_context,
        "available_validation_tools": available_tools,
    }
    persist_recon_artifact(
        "recon_sources.json",
        json.dumps(recon_sources, ensure_ascii=False, indent=2),
    )
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
            "1. Las fases obligatorias spa_crawler y katana_full ya fueron ejecutadas. Analiza ambas salidas y los requests raw incluidos en request_context.\n"
            "2. Usa el contenido real de los .req para identificar método, ruta, query, headers y body. El HAR completo está disponible en la ruta indicada, pero no lo inventes ni asumas su contenido más allá del resumen.\n"
            f"3. Limpia los duplicados usando la lista consolidada y filtra las rutas y parámetros sospechosos de ser vulnerables a '{attack_type_filter}'.\n"
            "4. Decide después el plan de acción: objetivos prioritarios, método, archivo '.req' y herramienta recomendada.\n"
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
            '    "har_session_file": "/app/requests/session_traffic.har"\n'
            "  },\n"
            '  "high_priority_targets": [\n'
            "    {\n"
            '      "target_id": "target_001",\n'
            f'      "vulnerability_target": "{attack_type_filter} (POST-based Auth Bypass)",\n'
            '      "endpoint": "http://...",\n'
            '      "method": "POST",\n'
            '      "req_file_path": "/app/requests/req_008_POST_rest_user_login.req",\n'
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
                    "Los artefactos persistidos están disponibles en /app/requests/: "
                    "session_traffic.har y los archivos .req. Usa esas rutas exactas en el plan."
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
    persist_recon_artifact("recon_llm_output.txt", full_llm_output)
    logger.info("[RECON] Parseando bloque JSON final chars=%d", len(raw_final_output))
    parsed_dict = json.loads(clean_json_response(raw_final_output))
    recon_output = build_planner_output_from_dict(parsed_dict, target_url, attack_type_filter)
    persist_recon_artifact(
        "recon_plan.json",
        json.dumps(recon_output.model_dump(), ensure_ascii=False, indent=2),
    )
    logger.info("[RECON] Plan JSON validado targets=%d", len(recon_output.high_priority_targets))
    return recon_output, "clean"


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
                                attack_type_filter = payload.get("attack_type", "full")
                                logger.info(f"📥 [RECON-AGENT] Tarea recibida para {target_url}")

                                recon_data, recovery_mode = await process_recon_task(
                                    channel,
                                    target_url,
                                    attack_type_filter,
                                )

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
