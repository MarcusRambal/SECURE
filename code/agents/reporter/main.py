import logging

from llm_factory import get_llm
from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage

from contract_schemas import ReporterInput
from config import LOG_RPC_PAYLOADS
from helpers import (
    build_fallback_markdown_report,
    build_fallback_reporter_input,
    build_reporter_context,
)

logger = logging.getLogger("reporter-agent-worker")

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
        logger.info(
            "[REPORTER] Contrato validado: task_id=%s targets=%d vulnerabilities=%d unconfirmed=%d",
            reporter_input.task_id,
            len(reporter_input.recon_data.high_priority_targets),
            len(reporter_input.validation_data.vulnerabilities),
            len(reporter_input.validation_data.unconfirmed_findings),
        )
    except ValidationError as e:
        logger.error(f"❌ Fallo al validar contrato ReporterInput: {e}")
        error_msg = f"Los datos del payload RPC no cumplen con el contrato ReporterInput Pydantic:\n{str(e)}"
        fallback_input = build_fallback_reporter_input(payload)
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
            "   - Resumen de objetivos prioritarios, endpoints y herramientas recomendadas.\n"
            "5. ## 📝 Conclusiones y Próximos Pasos\n\n"
            "REGLAS STRICTAS:\n"
            "- NO inventes hallazgos que no estén presentes en validation_summary.\n"
            "- MANTÉN INTACTOS los comandos de `reproducible_command` sin alterarlos.\n"
            "- Sé conciso, pero incluye todos los hallazgos y evidencias recibidos.\n"
            "- Retorna ÚNICAMENTE el texto en MARKDOWN puro. Sin envoltorios JSON."
        )
    )

    context_str = build_reporter_context(reporter_input)
    if LOG_RPC_PAYLOADS:
        logger.info("[REPORTER -> LLM] Contexto completo: %s", context_str)
    human_msg = HumanMessage(
        content=f"Genera el informe final en Markdown para la siguiente auditoría:\n\n```json\n{context_str}\n```"
    )

    try:
        response = await llm.ainvoke([system_prompt, human_msg])
        markdown_text = response.content.strip()
        logger.info(
            "[REPORTER <- LLM] Informe Markdown generado (%d caracteres).",
            len(markdown_text),
        )
        if LOG_RPC_PAYLOADS:
            logger.info("[REPORTER <- LLM] Informe Markdown completo:\n%s", markdown_text)
        return markdown_text, False
    except Exception as e:
        logger.error(
            f"❌ Fallo al invocar el LLM para el reporte ({e}). Generando reporte fallback..."
        )
        return build_fallback_markdown_report(reporter_input, str(e)), True
