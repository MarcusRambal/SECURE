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
            "Recibes la información consolidada de las fases de Reconocimiento y Validación y debes redactar un informe profesional de auditoría web en formato MARKDOWN.\n\n"
            "FUENTE DE VERDAD (OBLIGATORIA):\n"
            "- El array `validation_summary.findings` contiene la salida unificada de las herramientas (incluido crypto_inspector). "
            "Cada elemento incluye: finding_id, type, severity, endpoint, parameter, confidence, cwe, owasp, context_role, "
            "attack_demonstrated, attack_result, attack_chain, evidence, reproducible_command y tools_used.\n"
            "- Debes ITERAR el array COMPLETO y reportar CADA hallazgo. Está PROHIBIDO omitir, agrupar o resumir hallazgos sin listarlos.\n"
            "- Usa `validation_summary.severity_summary` y `total_findings` para las métricas; los números deben coincidir exactamente con los hallazgos listados.\n"
            "- El array ya llega ordenado por severidad (CRITICAL primero). Mantén ese orden en el informe.\n\n"
            "ESTRUCTURA OBLIGATORIA DEL INFORME:\n"
            "1. # 🛡️ Reporte de Auditoría de Seguridad Web\n"
            "   - Metadatos: ID de Tarea, Objetivo, Tipo de Análisis, Fechas de Inicio y Fin.\n"
            "2. ## 📊 Resumen Ejecutivo\n"
            "   - Visión general de la superficie auditada y nivel global de riesgo (si hay al menos un CRITICAL, el riesgo global es CRITICAL).\n"
            "   - Métricas exactas por severidad: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n"
            "   - Menciona explícitamente cuántos CRITICAL hay y cuántas credenciales fueron recuperadas, si aplica.\n"
            "   - SI 'unconfirmed_count' > 0, menciona brevemente cuántas evaluaciones se realizaron sin confirmar evidencia.\n"
            "   - SI 'recon_used_fallback' o 'validate_used_fallback' son True, INCLUYE UNA ADVERTENCIA destacada de análisis degradado.\n"
            "   - SI `findings` está vacío, INDÍCALO EXPLÍCITAMENTE: 'No se confirmaron vulnerabilidades explotables durante esta auditoría'. NO inventes hallazgos.\n"
            "3. ## 🔍 Hallazgos y Vulnerabilidades Confirmadas (CRITICAL primero)\n"
            "   - Ordena estrictamente por severidad: CRITICAL → HIGH → MEDIUM → LOW → INFO.\n"
            "   - Por cada hallazgo, en una subsección numerada:\n"
            "     * Título (`type`) y Severidad (`severity`) EXACTOS del JSON.\n"
            "     * `finding_id` y `context_role` (rol del dato en la seguridad).\n"
            "     * Mapeo Estándar: copia `cwe` y `owasp` LITERALMENTE del JSON. Si son null usa 'No reportado por la herramienta'. PROHIBIDO inferir, corregir o inventar CWE/OWASP.\n"
            "     * Endpoint afectado y parámetro (`parameter`).\n"
            "     * Evidencia técnica (`evidence`), sin recortarla.\n"
            "     * Si `attack_demonstrated` == 'dictionary_attack' y `attack_result` no es null: la severidad DEBE ser CRITICAL e incluir literalmente la línea 'Contraseña recuperada: <attack_result>'.\n"
            "     * Si `attack_result` no es null con otra técnica: incluir 'Resultado del ataque: <attack_result>'.\n"
            "     * 'Cadena de ataque': reproduce `attack_chain` como lista numerada, sin omitir ni parafrasear pasos.\n"
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
            "     * Método HTTP y pasos de verificación, si están presentes en los datos.\n"
            "     * Evidencia técnica observada.\n"
            "     * Comando reproducible exacto (bloque bash intacto).\n"
            "     * Recomendación de mitigación técnica específica para ese hallazgo.\n"
            "   - HALLAZGOS NO EXPLOTABLES: si `context_role` == 'static_checksum' (p. ej. hashes SHA1 de configuración o constantes), reportarlos como LOW o INFO, etiquetados como 'Falso positivo controlado / checksum estático', y NO los presentes como riesgo explotable.\n"
            "4. ## 🌐 Superficie de Ataque y Reconocimiento\n"
            "   - Resumen de objetivos prioritarios, endpoints y herramientas recomendadas.\n"
            "5. ## 📝 Conclusiones y Próximos Pasos\n\n"
            "REGLAS STRICTAS:\n"
            "- NO inventes hallazgos ni datos ausentes del JSON.\n"
            "- NO alteres la severidad de un hallazgo, salvo las dos reglas explícitas: dictionary_attack con contraseña recuperada → CRITICAL; static_checksum → LOW/INFO.\n"
            "- MANTÉN INTACTOS los comandos de `reproducible_command` sin alterarlos.\n"
            "- Sé conciso en la narrativa, pero incluye TODOS los hallazgos y TODAS sus evidencias, cadenas de ataque y contraseñas recuperadas.\n"
            "- Retorna ÚNICAMENTE el texto en MARKDOWN puro. Sin envoltorios JSON."
            "- No inventes pasos de verificación; utiliza `verification_steps` solo cuando exista.\n"
            "- Si el comando usa `/tmp/dalfox-req.txt`, advierte que depende de un archivo temporal y no se puede repetir tal cual.\n"
            "- Sé conciso, pero incluye todos los hallazgos y evidencias recibidos.\n"
            "- Retorna ÚNICAMENTE el texto en MARKDOWN puro. Sin envoltorios JSON.\n"
            "- NO incluyas secciones de 'Contacto', 'Autor', 'Firma' ni placeholders como "
            "  '[su nombre]', '[su correo]', '[su teléfono]'. El informe TERMINA después "
            "  de la sección 'Conclusiones y Próximos Pasos' (o 'Acciones Recomendadas')."
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
