import logging

from llm_factory import get_llm
from pydantic import ValidationError
from langchain_core.messages import HumanMessage, SystemMessage

from contract_schemas import ReporterInput
from config import LOG_RPC_PAYLOADS
from helpers import (
    build_fallback_markdown_report,
    build_fallback_reporter_input,
    build_report_metrics,
    build_reporter_context,
    finalize_report_markdown,
    report_has_english_narrative,
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
        return (
            finalize_report_markdown(
                build_fallback_markdown_report(reporter_input, str(e)),
                reporter_input,
            ),
            True,
        )

    system_prompt = SystemMessage(
        content=(
            "Eres el Agente Reportador Senior de Ciberseguridad.\n"
            "Redacta el informe completo en español claro y conciso, incluidos todos los "
            "títulos, explicaciones, recomendaciones y conclusiones. Evita repeticiones "
            "y explica brevemente qué se probó, qué se observó y qué debe corregirse.\n"
            "Conserva literalmente los datos técnicos originales: nombres de hallazgos y "
            "herramientas, identificadores, severidades, URL, parámetros, comandos, "
            "valores, evidencia y cadenas de ataque, incluso si vienen en otro idioma. "
            "Identifícalos como datos o evidencia original y no los traduzcas ni alteres. "
            "Puedes explicarlos en español sin cambiar su significado.\n\n"
            "FUENTE DE VERDAD (OBLIGATORIA):\n"
            "- El array `validation_summary.findings` contiene los hallazgos clasificados de TODAS las herramientas ejecutadas "
            "(puede incluir `crypto_inspector`, `access_control_prober`, SQLi o XSS). "
            "No es una muestra ni un resumen.\n"
            "- Cada elemento incluye: `tool`, `tools_used`, `finding_id`, `type`, `severity`, `endpoint`, `method`, `parameter`, `confidence`, "
            "`cwe`, `owasp`, `context_role`, `attack_demonstrated`, `attack_result`, `attack_chain`, `evidence`, `reproducible_command`, "
            "`active_confirmation`, `confirmation_note`, `recovered_password`, `broken_hash` y `verification_steps`.\n"
            "- `classification_reference` es una referencia orientativa derivada del tipo de hallazgo, "
            "no un dato reportado por la herramienta. Si existe, inclúyela como tal.\n"
            "- `validation_summary.informational_findings` contiene los hallazgos informativos, con severidad null. "
            "Inclúyelos individualmente en una sección separada, sin contarlos como vulnerabilidades ni asignarles severidad.\n"
            "- Debes ITERAR ambos arrays COMPLETOS y reportar CADA hallazgo, de todas las herramientas. Está PROHIBIDO omitir, agrupar o resumir "
            "hallazgos sin listarlos individualmente.\n"
            "- Usa `executive_summary` y `validation_summary.severity_summary` para las métricas. Los números del informe deben coincidir "
            "exactamente con los hallazgos listados.\n"
            "- `findings` ya llega ordenado por severidad: HIGH → MEDIUM → LOW. Mantén ese orden.\n\n"
            "REGLAS POR HERRAMIENTA PARA `findings` (OBLIGATORIAS):\n"
            "A) Si `tool` == 'access_control_prober' (o está en `tools_used`):\n"
            "   - Presenta el hallazgo con la etiqueta visible '✅ Confirmada activamente'.\n"
            "   - Resalta que la vulnerabilidad fue confirmada mediante explotación real, según el tipo: IDOR, escalada vertical de "
            "privilegios, bypass de 403 o archivos/directorios expuestos.\n"
            "   - Incluye `confirmation_note` y reproduce `attack_chain` paso a paso. Estos hallazgos son de máxima prioridad.\n"
            "B) Si `tool` == 'crypto_inspector' (o está en `tools_used`):\n"
            "   - Si `recovered_password` o (`attack_demonstrated` == 'dictionary_attack' y `attack_result` no es null), incluye "
            "literalmente la línea 'Contraseña recuperada: <attack_result>'.\n"
            "   - Si `broken_hash` es true o `context_role` == 'static_checksum', resalta el hash/checksum roto u obsoleto y su evidencia.\n"
            "   - Si `attack_result` no es null con otra técnica, incluye 'Resultado del ataque: <attack_result>'.\n\n"
            "ESTRUCTURA OBLIGATORIA DEL INFORME:\n"
            "1. # 🛡️ Reporte de Auditoría de Seguridad Web\n"
            "   - Metadatos: ID de Tarea, Objetivo, Tipo de Análisis, Fechas de Inicio y Fin.\n"
            "2. ## 📊 Resumen Ejecutivo\n"
            "   - Visión general de la superficie auditada y nivel global de riesgo según los datos disponibles.\n"
            "   - Indica los hallazgos por severidad y por herramienta con resultados, "
            "sin repetir cifras ni incluir desgloses de herramientas sin hallazgos.\n"
            "   - Menciona confirmaciones activas, credenciales recuperadas y hashes rotos solo si existen.\n"
            "   - SI 'unconfirmed_count' > 0, menciona brevemente cuántas evaluaciones se realizaron sin confirmar evidencia.\n"
            "   - SI 'recon_used_fallback' o 'validate_used_fallback' son True, INCLUYE UNA ADVERTENCIA destacada de análisis degradado.\n"
            "   - SI `findings` está vacío, INDÍCALO EXPLÍCITAMENTE: 'No se confirmaron vulnerabilidades explotables durante esta auditoría'. NO inventes hallazgos.\n"
            "3. ## 🔍 Hallazgos y Vulnerabilidades Confirmadas\n"
            "   - Ordena estrictamente por severidad: HIGH → MEDIUM → LOW.\n"
            "   - Por cada hallazgo, en una subsección numerada, incluye OBLIGATORIAMENTE:\n"
            "     * Título (`type`) y Severidad (`severity`) EXACTOS del JSON.\n"
            "     * `finding_id`, `tool`/`tools_used` y `context_role`.\n"
            "     * Mapeo Estándar: copia `cwe` y `owasp` LITERALMENTE del JSON. Si son null usa 'No reportado por la herramienta'. "
            "Si existe `classification_reference`, menciónala como clasificación orientativa derivada, sin atribuirla a la herramienta. "
            "No inventes otros mapeos.\n"
            "     * Endpoint afectado, método (`method`) y parámetro (`parameter`), cuando estén disponibles.\n"
            "     * Evidencia técnica (`evidence`) completa.\n"
            "     * Si `tool` == 'access_control_prober': la etiqueta '✅ Confirmada activamente' y el tipo de explotación confirmada.\n"
            "     * Si aplica: 'Contraseña recuperada: <attack_result>' y/o 'Hash roto/obsoleto: <evidencia>'.\n"
            "     * 'Cadena de ataque': reproduce `attack_chain` como lista numerada, sin omitir ni parafrasear pasos. "
            "Es OBLIGATORIA para CADA hallazgo; si la herramienta no la aporta, escribe 'No documentada por la herramienta'.\n"
            "     * Comando reproducible exacto (bloque bash intacto).\n"
            "       Si es `browserXssValidator ... --plan` sin el plan, aclara que no es reproducible tal cual.\n"
            "     * Recomendación de mitigación técnica específica para ese hallazgo.\n"
            "   - HALLAZGOS NO EXPLOTABLES: si `context_role` == 'static_checksum', "
            "indica que es un checksum estático y no lo presentes como riesgo explotable; conserva la severidad recibida.\n"
            "   - Añade una sección separada de hallazgos informativos si `informational_findings` no está vacío; "
            "no afirmes explotación o confirmación sin evidencia.\n"
            "4. ## 🌐 Superficie de Ataque y Reconocimiento\n"
            "   - Resumen de objetivos prioritarios, endpoints y herramientas recomendadas.\n"
            "5. ## 📝 Conclusiones y Próximos Pasos\n\n"
            "REGLAS ESTRICTAS:\n"
            "- NO inventes hallazgos ni datos ausentes del JSON.\n"
            "- NO alteres la severidad de ningún hallazgo recibido.\n"
            "- MANTÉN INTACTOS los comandos de `reproducible_command` sin alterarlos.\n"
            "- Sé conciso en la narrativa, pero incluye TODOS los hallazgos de TODAS las herramientas, TODAS sus evidencias, "
            "TODAS sus cadenas de ataque y TODAS las contraseñas recuperadas.\n"
            "- No inventes pasos de verificación; utiliza `verification_steps` solo cuando exista.\n"
            "- Si el comando usa `/tmp/dalfox-req.txt`, advierte que depende de un archivo temporal y no se puede repetir tal cual.\n"
            "- Retorna ÚNICAMENTE el texto en MARKDOWN puro. Sin envoltorios JSON.\n"
            "- NO incluyas secciones de 'Contacto', 'Autor', 'Firma' ni placeholders como "
            "  '[su nombre]', '[su correo]', '[su teléfono]'. El informe TERMINA después "
            "  de la sección 'Conclusiones y Próximos Pasos' (o 'Acciones Recomendadas')."
        )
    )

    metrics = build_report_metrics(reporter_input)
    logger.info(
        "[REPORTER] Hallazgos: total=%d HIGH=%d MEDIUM=%d LOW=%d informativos=%d by_tool=%s",
        metrics["total_findings"],
        metrics["high_total"],
        metrics["severity_summary"]["MEDIUM"],
        metrics["severity_summary"]["LOW"],
        metrics["informational_count"],
        metrics["by_tool"],
    )

    context_str = build_reporter_context(reporter_input)
    if LOG_RPC_PAYLOADS:
        logger.info("[REPORTER -> LLM] Contexto completo: %s", context_str)
    human_msg = HumanMessage(
        content=f"Genera el informe final en español para la siguiente auditoría:\n\n```json\n{context_str}\n```"
    )

    try:
        response = await llm.ainvoke([system_prompt, human_msg])
        raw_markdown = response.content.strip()
        if not raw_markdown:
            raise ValueError("El modelo devolvió un informe vacío.")
        if report_has_english_narrative(raw_markdown, reporter_input):
            logger.warning("[REPORTER] Narración en inglés detectada; solicitando corrección.")
            correction = HumanMessage(
                content=(
                    "Reescribe la narración anterior completamente en español claro y conciso. "
                    "Conserva literalmente los datos técnicos originales, los comandos y las "
                    "cadenas de ataque. No omitas hallazgos ni inventes información.\n\n"
                    f"Informe anterior:\n\n{raw_markdown}"
                )
            )
            response = await llm.ainvoke(
                [system_prompt, human_msg, response, correction]
            )
            raw_markdown = response.content.strip()
            if not raw_markdown or report_has_english_narrative(raw_markdown, reporter_input):
                raise ValueError("No se pudo generar la narración del informe en español.")
        markdown_text = finalize_report_markdown(raw_markdown, reporter_input)
        if len(markdown_text) > len(raw_markdown):
            logger.warning(
                "[REPORTER] El LLM omitio el resumen ejecutivo, hallazgos o cadenas "
                "de ataque; se completo el informe con contenido determinista."
            )
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
        return (
            finalize_report_markdown(
                build_fallback_markdown_report(reporter_input, str(e)),
                reporter_input,
            ),
            True,
        )
