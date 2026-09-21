import os
import json
import uuid
import asyncio
import logging
import aio_pika
from pydantic import BaseModel, Field
from langchain_core.tools import StructuredTool

logger = logging.getLogger("orchestrator-tools")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
RECON_QUEUE = "recon_queue"
VALIDATE_QUEUE = "validate_queue"
REPORTER_QUEUE = "reporter_queue"

# Estado compartido temporal en memoria durante el pipeline: task_id -> dict
TASK_STATE: dict[str, dict] = {}


class TaskReferenceInput(BaseModel):
    task_id: str = Field(description="UUID único de la tarea de auditoría en curso.")


async def _send_rpc_request(
    channel: aio_pika.Channel, queue_name: str, payload: dict, timeout: float = 3600.0
) -> dict:
    """Envía peticiones RPC reutilizando el canal RabbitMQ activo del worker."""
    reply_queue = await channel.declare_queue(exclusive=True)
    correlation_id = str(uuid.uuid4())
    future = asyncio.get_running_loop().create_future()

    async def on_response(message: aio_pika.IncomingMessage):
        async with message.process():
            if message.correlation_id == correlation_id:
                if not future.done():
                    future.set_result(json.loads(message.body.decode("utf-8")))

    consumer_tag = await reply_queue.consume(on_response)

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(payload).encode("utf-8"),
            correlation_id=correlation_id,
            reply_to=reply_queue.name,
            content_type="application/json",
        ),
        routing_key=queue_name,
    )

    try:
        return await asyncio.wait_for(future, timeout=timeout)
    except asyncio.TimeoutError:
        logger.error(f"⏰ Timeout ({timeout}s) en cola '{queue_name}'")
        return {"status": "ERROR", "error": f"Timeout superado en la cola {queue_name}"}
    finally:
        await reply_queue.cancel(consumer_tag)
        await reply_queue.delete(if_unused=False, if_empty=False)


def create_orchestrator_tools(channel: aio_pika.Channel) -> list[StructuredTool]:
    """Crea e inyecta el canal de RabbitMQ persistente en las herramientas de LangChain."""

    async def call_recon_agent(task_id: str) -> str:
        state = TASK_STATE.get(task_id)
        if not state:
            return f"Error: No existe estado activo para task_id '{task_id}'."

        target_url = state["target_url"]
        logger.info(f"📤 [ORQUESTADOR -> RECON] Escaneando {target_url}...")

        rpc_response = await _send_rpc_request(
            channel,
            RECON_QUEUE,
            {
                "target_url": target_url,
                "attack_type": state.get("attack_type", "full"),
            },
        )

        # Si el RPC falla o devuelve ERROR, marcar la tarea como fallida
        if not rpc_response or rpc_response.get("status") == "ERROR":
            error_msg = (rpc_response or {}).get("error", "Sin respuesta del Recon Agent")
            state["status"] = "FAILED"
            state["error_stage"] = "recon"
            state["error_message"] = error_msg
            # recon_data vacío pero con forma válida: Validate lo asume como input.
            state["recon_data"] = {
                "target_url": target_url,
                "endpoints": [],
                "technologies": [],
                "passive_findings": [],
            }
            state["recon_used_fallback"] = False
            state["recon_recovery_mode"] = "error"
            return f"Fallo en Recon Agent: {error_msg}"

        recon_data = rpc_response.get("recon_data") or {
            "target_url": target_url,
            "endpoints": [],
            "technologies": [],
            "passive_findings": [],
        }
        used_fallback = rpc_response.get("used_fallback", False)
        recovery_mode = rpc_response.get("recovery_mode", "clean")
        status = rpc_response.get("status", "SUCCESS")

        state["recon_data"] = recon_data
        state["recon_used_fallback"] = used_fallback
        state["recon_recovery_mode"] = recovery_mode

        # Trazabilidad explícita: "recovered" también cuenta como éxito limpio
        if recovery_mode == "recovered":
            logger.info(
                f"♻️ [ORQUESTADOR] Recon recuperado de error de tool calling "
                f"(JSON válido). Se trata como éxito limpio."
            )

        if status == "PARTIAL":
            state["status"] = "PARTIAL"

        endpoints_count = len(
            recon_data.get("endpoints", [])
            or recon_data.get("high_priority_targets", [])
        )
        return (
            f"Reconocimiento completado para '{task_id}'. "
            f"Endpoints: {endpoints_count}. "
            f"Estado: {status} (Recovery: {recovery_mode})."
        )

    async def call_validate_agent(task_id: str) -> str:
        state = TASK_STATE.get(task_id)
        if not state:
            return f"Error: No existe estado activo para task_id '{task_id}'."

        if state.get("status") == "FAILED":
            # Validate se salta porque Recon falló, pero el Reporter espera
            # validation_data con forma válida. Inicializamos vacío.
            state["validation_data"] = state.get("validation_data") or {
                "target_url": state["target_url"],
                "vulnerabilities": [],
                "unconfirmed_findings": [],
            }
            state["validate_used_fallback"] = False
            state["validate_recovery_mode"] = "skipped"
            return "Validación omitida debido a un fallo en la fase de Reconocimiento."

        recon_data = state.get("recon_data") or {
            "target_url": state["target_url"],
            "endpoints": [],
            "technologies": [],
            "passive_findings": [],
        }

        if not (
            recon_data.get("endpoints")
            or recon_data.get("high_priority_targets")
        ):
            logger.warning(f"Recon sin endpoints para {task_id}. Omisión directa de validación.")
            state["recon_data"] = recon_data
            state["validation_data"] = {
                "target_url": state["target_url"],
                "vulnerabilities": [],
                "unconfirmed_findings": [],
            }
            state["validate_used_fallback"] = False
            state["validate_recovery_mode"] = "skipped"
            return "Validación omitida: La fase de reconocimiento no descubrió endpoints."

        payload = {
            "target_url": state["target_url"],
            "attack_type": state["attack_type"],
            "recon_data": recon_data,
        }

        logger.info(
            f"📤 [ORQUESTADOR -> VALIDATE] Auditando {state['target_url']} ({state['attack_type']})..."
        )
        rpc_response = await _send_rpc_request(channel, VALIDATE_QUEUE, payload)

        if not rpc_response or rpc_response.get("status") == "ERROR":
            error_msg = (rpc_response or {}).get("error", "Sin respuesta del Validate Agent")
            state["status"] = "FAILED"
            state["error_stage"] = "validate"
            state["error_message"] = error_msg
            # El Reporter asume validation_data con esta forma; inicializar vacío si Validate falló.
            state["validation_data"] = {
                "target_url": state["target_url"],
                "vulnerabilities": [],
                "unconfirmed_findings": [],
            }
            state["validate_used_fallback"] = False
            state["validate_recovery_mode"] = "error"
            return f"Fallo en Validate Agent: {error_msg}"

        validation_data = rpc_response.get("validation_data") or {
            "target_url": state["target_url"],
            "vulnerabilities": [],
            "unconfirmed_findings": [],
        }
        used_fallback = rpc_response.get("used_fallback", False)
        recovery_mode = rpc_response.get("recovery_mode", "clean")
        status = rpc_response.get("status", "SUCCESS")

        state["validation_data"] = validation_data
        state["validate_used_fallback"] = used_fallback
        state["validate_recovery_mode"] = recovery_mode

        if recovery_mode == "recovered":
            logger.info(
                f"♻️ [ORQUESTADOR] Validate recuperado de error de tool calling "
                f"(JSON válido). Se trata como éxito limpio."
            )

        if status == "PARTIAL" or state.get("status") == "PARTIAL":
            state["status"] = "PARTIAL"

        vulns_count = len(validation_data.get("vulnerabilities", []))
        return (
            f"Validación completada para '{task_id}'. "
            f"Vulnerabilidades confirmadas: {vulns_count}. "
            f"Estado: {status} (Recovery: {recovery_mode})."
        )

    async def call_reporter_agent(task_id: str) -> str:
        state = TASK_STATE.get(task_id)
        if not state:
            return f"Error: No existe estado activo para task_id '{task_id}'."

        # El Reporter asume recon_data y validation_data con forma válida;
        # enviamos dicts vacíos con la estructura esperada si alguna fase no dejó datos.
        target_url = state["target_url"]
        payload = {
            "task_id": task_id,
            "target_url": target_url,
            "attack_type": state["attack_type"],
            "recon_used_fallback": state.get("recon_used_fallback", False) or False,
            "validate_used_fallback": state.get("validate_used_fallback", False) or False,
            "recon_data": state.get("recon_data")
            or {
                "target_url": target_url,
                "endpoints": [],
                "technologies": [],
                "passive_findings": [],
            },
            "validation_data": state.get("validation_data")
            or {
                "target_url": target_url,
                "vulnerabilities": [],
                "unconfirmed_findings": [],
            },
        }

        logger.info(f"📤 [ORQUESTADOR -> REPORTER] Solicitando informe Markdown para {task_id}...")
        rpc_response = await _send_rpc_request(channel, REPORTER_QUEUE, payload)

        if not rpc_response or rpc_response.get("status") == "ERROR":
            error_msg = (rpc_response or {}).get("error", "Sin respuesta del Reporter Agent")
            state["status"] = "FAILED"
            state["error_stage"] = "reporter"
            state["error_message"] = error_msg
            return f"Fallo en Reporter Agent: {error_msg}"

        markdown_report = rpc_response.get("report_markdown") or ""
        used_fallback = rpc_response.get("used_fallback", False)
        status = rpc_response.get("status", "SUCCESS")

        state["report_markdown"] = markdown_report
        state["reporter_used_fallback"] = used_fallback

        # Determinar estado final respetando fallos previos
        current_status = state.get("status", "PROCESSING")
        if current_status in ("FAILED", "PARTIAL"):
            # Ya marcado como fallo/parcial por una fase previa, no sobrescribir
            pass
        elif (
            status == "PARTIAL"
            or state.get("recon_used_fallback")
            or state.get("validate_used_fallback")
        ):
            state["status"] = "PARTIAL"
        else:
            state["status"] = "COMPLETED"

        # Resumen del pipeline completo: útil para correlacionar recon/validate/reporter en logs.
        logger.info(
            f"🏁 [ORQUESTADOR] Estado final: {state['status']} | "
            f"recon_recovery={state.get('recon_recovery_mode', 'n/a')} | "
            f"validate_recovery={state.get('validate_recovery_mode', 'n/a')} | "
            f"reporter_fallback={state.get('reporter_used_fallback', False)}"
        )

        return (
            f"Informe generado exitosamente para task_id '{task_id}'. "
            f"Longitud: {len(markdown_report)} caracteres. "
            f"Estado final: {state['status']}."
        )

    recon_tool = StructuredTool.from_function(
        coroutine=call_recon_agent,
        name="recon_agent",
        description="Invoca al Agente de Reconocimiento pasando el task_id.",
        args_schema=TaskReferenceInput,
    )

    validate_tool = StructuredTool.from_function(
        coroutine=call_validate_agent,
        name="validate_agent",
        description="Invoca al Agente de Validación pasando el task_id.",
        args_schema=TaskReferenceInput,
    )

    reporter_tool = StructuredTool.from_function(
        coroutine=call_reporter_agent,
        name="reporter_agent",
        description="Invoca al Agente Reportador para generar el informe Markdown pasando el task_id.",
        args_schema=TaskReferenceInput,
    )

    return [recon_tool, validate_tool, reporter_tool]
