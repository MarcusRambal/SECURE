import os
import json
import asyncio
import logging
import aio_pika

from llm_factory import get_llm
from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage

from contract_schemas import ReporterInput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reporter-agent-worker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL")
REPORTER_QUEUE = "reporter_queue"


def build_fallback_markdown_report(reporter_input: ReporterInput, raw_error: str) -> str:
    """Construye un informe Markdown concatenando strings de forma segura (sin errores de sintaxis f-string)."""
    vulns = reporter_input.validation_data.vulnerabilities
    endpoints = reporter_input.recon_data.endpoints
    unconfirmed = reporter_input.validation_data.unconfirmed_findings

    parts = []
    parts.append("# 🛡️ Informe de Auditoría de Ciberseguridad\n")
    parts.append(f"**ID de Tarea:** `{reporter_input.task_id}`")
    parts.append(f"**Objetivo Auditado:** `{reporter_input.target_url}`")
    parts.append(f"**Modalidad:** `{reporter_input.attack_type}`\n")

    if reporter_input.recon_used_fallback or reporter_input.validate_used_fallback:
        parts.append(
            "> ⚠️ **Advertencia de Análisis Degradado:** Fases previas utilizaron mecanismos "
            "de respaldo por regex. La cobertura del reporte puede ser parcial.\n"
        )

    parts.append(
        "> ⚠️ **Nota del Sistema:** Este informe se estructuró mediante la plantilla "
        "de respaldo debido a una anomalía durante la generación narrativa del LLM."
    )
    parts.append(f"> 🔍 **Debug Error:** `{raw_error[:200]}`\n")

    parts.append("## 📊 Resumen Ejecutivo\n")
    parts.append(f"* **Endpoints Descubiertos:** {len(endpoints)}")
    parts.append(f"* **Vulnerabilidades Confirmadas:** {len(vulns)}")
    parts.append(f"* **Pruebas Sin Confirmación:** {len(unconfirmed)}\n")

    parts.append("## 🔎 Detalle de Hallazgos\n")
    if not vulns:
        parts.append(
            "*No se confirmaron vulnerabilidades explotables durante esta auditoría de seguridad.*\n"
        )
    else:
        for v in vulns:
            parts.append(f"### ⚠️ [{v.severity}] {v.type}")
            parts.append(f"- **Endpoint:** `{v.endpoint}`")
            parts.append(f"- **Parámetro:** `{v.parameter or 'N/A'}`")
            parts.append(f"- **Certeza:** `{v.confidence}`")
            parts.append(f"- **Evidencia:** `{v.evidence}`")
            parts.append("- **Comando Reproducible:**")
            parts.append("```bash")
            parts.append(v.reproducible_command)
            parts.append("```")
            parts.append(f"- **Herramientas Utilizadas:** {', '.join(v.tools_used)}\n")
            parts.append("---\n")

    if unconfirmed:
        parts.append("## 🧪 Pruebas sin Confirmación\n")
        parts.append(
            f"Se ejecutaron {len(unconfirmed)} pruebas/evaluaciones adicionales "
            "que no arrojaron evidencia suficiente de explotación directa.\n"
        )

    return "\n".join(parts)


def build_reporter_context(reporter_input: ReporterInput) -> str:
    """Genera un resumen JSON compacto recortando evidencias y limitando endpoints para evitar desbordamiento de tokens."""
    ctx = {
        "task_id": reporter_input.task_id,
        "target_url": reporter_input.target_url,
        "attack_type": reporter_input.attack_type,
        "degradation_warnings": {
            "recon_used_fallback": reporter_input.recon_used_fallback,
            "validate_used_fallback": reporter_input.validate_used_fallback,
        },
        "recon_summary": {
            "endpoints_count": len(reporter_input.recon_data.endpoints),
            "top_endpoints": [
                {"url": e.url, "method": e.method, "parameters": e.parameters, "source": e.source}
                for e in reporter_input.recon_data.endpoints[:15]
            ],
            "technologies": reporter_input.recon_data.technologies,
            "scan_started_at": reporter_input.recon_data.scan_started_at,
            "scan_finished_at": reporter_input.recon_data.scan_finished_at,
        },
        "validation_summary": {
            "vulnerabilities": [
                {
                    "type": v.type,
                    "severity": v.severity,
                    "endpoint": v.endpoint,
                    "parameter": v.parameter,
                    "confidence": v.confidence,
                    "evidence": (v.evidence[:200] + "...") if len(v.evidence) > 200 else v.evidence,
                    "reproducible_command": v.reproducible_command,
                    "tools_used": v.tools_used,
                }
                for v in reporter_input.validation_data.vulnerabilities
            ],
            "unconfirmed_count": len(reporter_input.validation_data.unconfirmed_findings),
            "scan_started_at": reporter_input.validation_data.scan_started_at,
            "scan_finished_at": reporter_input.validation_data.scan_finished_at,
        },
    }
    return json.dumps(ctx, indent=2, ensure_ascii=False)


async def process_report_task(payload: dict) -> tuple[str, bool]:
    """Procesa el payload RPC, valida los modelos Pydantic e invoca al LLM. Retorna (markdown_text, used_fallback)."""
    try:
        raw_recon = payload.get("recon_data", {})
        raw_val = payload.get("validation_data", {})

        reporter_input = ReporterInput(
            task_id=payload.get("task_id", "N/A"),
            target_url=payload.get("target_url", "N/A"),
            attack_type=payload.get("attack_type", "full"),
            recon_used_fallback=payload.get("recon_used_fallback", False),
            validate_used_fallback=payload.get("validate_used_fallback", False),
            recon_data=raw_recon,
            validation_data=raw_val,
        )
    except ValidationError as e:
        logger.error(f"❌ Fallo al validar contrato ReporterInput: {e}")
        error_msg = f"Los datos del payload RPC no cumplen con el contrato ReporterInput Pydantic:\n{str(e)}"
        fallback_input = ReporterInput(
            task_id=payload.get("task_id", "N/A"),
            target_url=payload.get("target_url", "N/A"),
            attack_type=payload.get("attack_type", "full"),
            recon_data={"target_url": payload.get("target_url", "N/A"), "endpoints": []},
            validation_data={"target_url": payload.get("target_url", "N/A"), "vulnerabilities": []},
        )
        return build_fallback_markdown_report(fallback_input, error_msg), True

    try:
        llm = get_llm("reporter")
    except ValueError as e:
        logger.error(f"Error cargando LLM en Reporter: {e}")
        return build_fallback_markdown_report(reporter_input, str(e)), True

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Reportador Senior de Ciberseguridad.\n"
            "Tu tarea es recibir la información resumida de las fases de Reconocimiento y Validación y redactar un informe profesional de auditoría web en formato MARKDOWN.\n\n"
            "ESTRUCTURA OBLIGATORIA DEL INFORME:\n"
            "1. # 🛡️ Reporte de Auditoría de Seguridad Web\n"
            "   - Metadatos: ID de Tarea, Objetivo, Tipo de Análisis, Fechas de Inicio y Fin.\n"
            "2. ## 📊 Resumen Ejecutivo\n"
            "   - Visión general de la superficie auditada y nivel global de riesgo.\n"
            "   - Métricas (Total Endpoints, Vulnerabilidades por Severidad: CRITICAL, HIGH, MEDIUM, LOW, INFO).\n"
            "   - SI 'unconfirmed_count' > 0, menciona brevemente cuántas evaluaciones/pruebas se realizaron sin confirmar evidencia de hallazgo.\n"
            "   - SI 'recon_used_fallback' o 'validate_used_fallback' son True, INCLUYE UNA ADVERTENCIA destacada indicando que el análisis operó en modo degradado parcial.\n"
            "   - SI 'vulnerabilities' está vacío, INDÍCALO EXPLÍCITAMENTE: 'No se confirmaron vulnerabilidades explotables durante esta auditoría'. NO inventes hallazgos.\n"
            "3. ## 🔍 Hallazgos y Vulnerabilidades Confirmadas\n"
            "   - Por cada vulnerabilidad reportada:\n"
            "     * Nombre y Severidad.\n"
            "     * Mapeo Estándar (CWE aproximado y OWASP Top 10 aplicable).\n"
            "     * Endpoint afectado y Parámetro.\n"
            "     * Evidencia técnica observada.\n"
            "     * Comando reproducible exacto (bloque bash intacto).\n"
            "     * Recomendación de mitigación técnica detallada.\n"
            "4. ## 🌐 Superficie de Ataque y Reconocimiento\n"
            "   - Resumen de tecnologías detectadas y endpoints principales.\n"
            "5. ## 📝 Conclusiones y Próximos Pasos\n\n"
            "REGLAS STRICTAS:\n"
            "- NO inventes hallazgos que no estén presentes en validation_summary.\n"
            "- MANTÉN INTACTOS los comandos de `reproducible_command` sin alterarlos.\n"
            "- Sé conciso. Prioriza los hallazgos críticos y altos. Para severidades bajas, agrupa en una línea. Máximo 900 tokens de salida.\n"
            "- Retorna ÚNICAMENTE el texto en MARKDOWN puro. Sin envoltorios JSON."
        )
    )

    context_str = build_reporter_context(reporter_input)
    human_msg = HumanMessage(
        content=f"Genera el informe final en Markdown para la siguiente auditoría:\n\n```json\n{context_str}\n```"
    )

    try:
        response = await llm.ainvoke([system_prompt, human_msg])
        markdown_text = response.content.strip()
        logger.info(f"✅ Informe Markdown generado exitosamente ({len(markdown_text)} caracteres).")
        return markdown_text, False
    except Exception as e:
        logger.error(
            f"❌ Fallo al invocar el LLM para el reporte ({e}). Generando reporte fallback..."
        )
        return build_fallback_markdown_report(reporter_input, str(e)), True


async def start_reporter_worker():
    """Worker asíncrono que escucha peticiones RPC en reporter_queue."""
    while True:
        try:
            logger.info(f"Conectando Reporter-Agent a RabbitMQ en {RABBITMQ_URL}...")
            connection = await aio_pika.connect_robust(RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                queue = await channel.declare_queue(REPORTER_QUEUE, durable=True)
                logger.info(f"🎧 Reporter-Agent escuchando activamente en '{REPORTER_QUEUE}'...")

                async with queue.iterator() as queue_iter:
                    async for message in queue_iter:
                        async with message.process():
                            correlation_id = message.correlation_id
                            reply_to = message.reply_to

                            try:
                                payload = json.loads(message.body.decode("utf-8"))
                                logger.info(
                                    f"📥 [REPORTER-AGENT] Generando informe para tarea {payload.get('task_id')}"
                                )

                                report_markdown, used_fallback = await process_report_task(payload)

                                status = "PARTIAL" if used_fallback else "SUCCESS"
                                response_body = json.dumps(
                                    {
                                        "status": status,
                                        "used_fallback": used_fallback,
                                        "report_markdown": report_markdown,
                                    }
                                )
                            except Exception as msg_error:
                                logger.error(
                                    f"❌ Error procesando mensaje Reporter: {msg_error}",
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
                                        f"📤 [REPORTER-AGENT] Respuesta enviada a '{reply_to}'"
                                    )
                                except Exception as pub_error:
                                    logger.error(
                                        f"❌ No se pudo publicar respuesta RPC: {pub_error}"
                                    )
        except Exception as e:
            logger.warning(f"Error en Reporter Worker ({e}). Reintentando en 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(start_reporter_worker())
