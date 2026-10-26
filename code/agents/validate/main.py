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

from contract_schemas import ValidateOutput, Vulnerability
from helpers import (
    build_validate_output_from_dict,
    build_fallback_validate_output,
    build_real_command,
    prepare_sqlmap_request,
    write_validate_context_snapshot,
)
from mcp_skills import build_validation_tools, call_mcp_skill, get_mcp_catalog
from attack_validators import get_validation_strategy
from attack_types import is_sqli_attack, is_jwt_attack, is_xss_attack

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validate-agent-worker")

logger.info("🟢 [VALIDATE] Cargando LLM de validación")

llm = get_llm("MODEL_VALIDATE")
structured_llm = llm.with_structured_output(ValidateOutput, method="json_schema")

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


# ============================================================================
# JWT: flujo determinista (sin LLM)
# ============================================================================

async def _process_jwt_validation(
    channel: aio_pika.Channel,
    target_url: str,
    token: str | None,
    started_at: str,
) -> tuple[ValidateOutput, str]:
    """Ejecuta jwt_tool y transforma su JSON estructurado a ValidateOutput.

    No pasa por el LLM: la salida del handler ya es el contrato final.
    """
    if not token:
        logger.warning("[VALIDATE] JWT requiere token; no se recibió uno.")
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{
                    "reason": (
                        "El ataque JWT requiere un token de sesión válido. "
                        "No se recibió token en el payload."
                    )
                }],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
        )

    logger.info("[VALIDATE] JWT: invocando jwt_tool para %s", target_url)

    try:
        raw_output = await call_mcp_skill(
            channel, "jwt_tool",
            {"target_url": target_url, "token": token},
        )
    except Exception as exc:
        logger.exception("[VALIDATE] Falló la invocación de jwt_tool")
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{"reason": f"jwt_tool falló: {exc}"}],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
        )

    try:
        report = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        logger.error("[VALIDATE] jwt_tool devolvió salida no-JSON: %s", exc)
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{
                    "reason": f"jwt_tool devolvió salida no-JSON: {str(exc)[:200]}",
                    "raw_preview": raw_output[:500] if isinstance(raw_output, str) else "",
                }],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
        )

    if report.get("error") and not report.get("findings"):
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{
                    "reason": f"jwt_tool error: {report.get('error')}",
                    "message": report.get("message", ""),
                    "hint": report.get("hint", ""),
                }],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
        )

    reproducible = (
        f"python jwt_tool_handler.py --target {target_url} --token <JWT>"
    )
    vulnerabilities: list[Vulnerability] = []

    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue

        sev = str(finding.get("severity", "MEDIUM")).upper()
        if sev not in VALID_SEVERITIES:
            sev = "MEDIUM"

        title = finding.get("title") or "JWT weakness"
        description = finding.get("description") or ""
        evidence_field = finding.get("evidence") or ""
        cwe = finding.get("cwe") or ""
        owasp = finding.get("owasp") or ""
        remediation = finding.get("remediation") or ""

        composed = " | ".join(p for p in (description, evidence_field) if p)
        mapping = " / ".join(x for x in (cwe, owasp) if x)
        if mapping and composed:
            evidence_text = f"[{mapping}] {composed}"
        elif composed:
            evidence_text = composed
        else:
            evidence_text = title

        if remediation:
            evidence_text += f" | Mitigation: {remediation}"

        evidence_text = evidence_text[:1500]

        try:
            vulnerabilities.append(
                Vulnerability(
                    type=title,
                    severity=sev,
                    endpoint=target_url,
                    parameter=None,
                    evidence=evidence_text,
                    reproducible_command=reproducible,
                    confidence="HIGH",
                    tools_used=["jwt_tool"],
                )
            )
        except ValidationError as exc:
            logger.warning("[VALIDATE] Finding JWT descartado por schema: %s", exc)

    context = {
        "jwt_analysis": report.get("jwt_analysis", {}),
        "attacks_summary": report.get("summary", {}),
        "discovery": report.get("discovery", {}),
    }

    logger.info(
        "[VALIDATE] JWT completado: findings=%d risk=%s",
        len(vulnerabilities),
        report.get("summary", {}).get("risk_level", "UNKNOWN"),
    )

    return (
        ValidateOutput(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            unconfirmed_findings=[context],
            scan_started_at=started_at,
            scan_finished_at=datetime.now(timezone.utc).isoformat(),
        ),
        "clean",
    )


# ============================================================================
# XSS: delega al strategy pattern de main
# ============================================================================

async def _process_xss_validation(
    channel: aio_pika.Channel,
    target_url: str,
    targets: list[dict],
    task_id: str,
    started_at: str,
) -> tuple[ValidateOutput, str, list[dict]]:
    """Ejecuta XSS usando la estrategia heredada de main."""
    strategy = get_validation_strategy("xss")
    tool_timings: list[dict] = []

    selected_targets = [
        {
            "url": t.get("endpoint", ""),
            "method": t.get("method", "GET"),
            "target_id": t.get("target_id"),
            "request_id": t.get("request_id"),
            "recommended_tool": t.get("recommended_tool"),
            "request": t.get("request", {}),
        }
        for t in targets if isinstance(t, dict) and t.get("endpoint")
    ]

    if not selected_targets:
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{"reason": "Recon sin objetivos válidos"}],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
            tool_timings,
        )

    evidence = await strategy.execute(
        channel, target_url, selected_targets, task_id, tool_timings
    )
    system_prompt = SystemMessage(content=get_system_prompt("xss"))
    validation_context = strategy.build_validation_context(evidence)

    user_message = HumanMessage(content=(
        "Analiza la evidencia disponible de las herramientas y determina si "
        "confirma la vulnerabilidad solicitada.\n\n"
        f"{json.dumps(validation_context, ensure_ascii=False, indent=2)}\n\n"
        "Copia target_id, request_id y endpoint exclusivamente de la ejecución "
        "que aporta la evidencia."
    ))

    try:
        snapshot_path = write_validate_context_snapshot(
            target_url, "xss",
            {
                "system_prompt": system_prompt.content,
                "user_message": user_message.content,
            },
            evidence.pre_executed_context,
        )
        logger.info("[VALIDATE] Contexto XSS guardado en %s", snapshot_path)
    except OSError:
        logger.exception("[VALIDATE] No se pudo guardar el contexto XSS")

    structured_output = await structured_llm.ainvoke([system_prompt, user_message])
    if not isinstance(structured_output, ValidateOutput):
        raise TypeError("El LLM no devolvió ValidateOutput")

    parsed_dict = structured_output.model_dump()
    parsed_dict = strategy.merge_findings(parsed_dict, evidence, task_id)

    validate_output = build_validate_output_from_dict(
        parsed_dict, target_url, started_at, evidence.executed_commands
    )
    return validate_output, "clean", tool_timings


# ============================================================================
# FLUJO PRINCIPAL DE VALIDACIÓN
# ============================================================================

async def process_validate_task(
    channel: aio_pika.Channel,
    target_url: str,
    attack_type: str,
    targets: list[dict],
    token: str | None = None,
    task_id: str | None = None,
) -> tuple[ValidateOutput, str, list[dict]]:

    started_at = datetime.now(timezone.utc).isoformat()
    trace_id = task_id or "unknown"

    is_sqli = is_sqli_attack(attack_type)
    is_jwt = is_jwt_attack(attack_type)
    is_xss = is_xss_attack(attack_type)
    logger.info(
        "[VALIDATE] attack_type=%s | SQLi=%s JWT=%s XSS=%s",
        attack_type, is_sqli, is_jwt, is_xss,
    )

    # JWT: flujo determinista (David)
    if is_jwt:
        validate_output, mode = await _process_jwt_validation(
            channel, target_url, token, started_at
        )
        return validate_output, mode, []

    # XSS: estrategia heredada de main
    if is_xss:
        return await _process_xss_validation(
            channel, target_url, targets, trace_id, started_at
        )

    # SQLi: flujo directo de David (probado end-to-end)
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

    if not selected_targets:
        logger.warning("Recon no devolvió objetivos válidos.")
        return (
            ValidateOutput(
                target_url=target_url,
                vulnerabilities=[],
                unconfirmed_findings=[{"reason": "Recon sin objetivos válidos"}],
                scan_started_at=started_at,
                scan_finished_at=datetime.now(timezone.utc).isoformat(),
            ),
            "clean",
            [],
        )

    catalog = await get_mcp_catalog(channel)
    raw_tool_outputs: list[str] = []
    executed_commands: list[dict] = []
    pre_executed_context: list[dict] = []

    if is_sqli:
        logger.info(
            "[VALIDATE] Ejecutando SQLMap sobre %d endpoint(s)", len(selected_targets),
        )
        for target in selected_targets:
            request_data = target.get("request", {})
            if isinstance(request_data, dict) and request_data:
                tool_args = {
                    "request": prepare_sqlmap_request(
                        request_data, target_url, target["url"], target["method"],
                    )
                }
            else:
                tool_args = {
                    "target_url": urljoin(f"{target_url.rstrip('/')}/", target["url"])
                }

            try:
                output = await call_mcp_skill(channel, "sqlmap", tool_args)
                raw_tool_outputs.append(output)

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
                logger.error(
                    "Fallo ejecutando SQLMap en %s: %s", target["url"], err,
                )

    system_prompt = SystemMessage(content=get_system_prompt(attack_type))
    user_message = HumanMessage(content=(
        "Analiza los resultados de las herramientas y determina si existe "
        "una vulnerabilidad confirmada.\n\n"
        f"{json.dumps(pre_executed_context, ensure_ascii=False, indent=2)}\n\n"
        "Copia target_id, request_id y endpoint exclusivamente de la ejecución "
        "que aporta la evidencia."
    ))

    try:
        snapshot_path = write_validate_context_snapshot(
            target_url, attack_type,
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
        structured_output = await structured_llm.ainvoke([system_prompt, user_message])
    except (OutputParserException, ValidationError) as error:
        if not is_sqli:
            raise
        logger.warning(
            "[VALIDATE] El LLM no devolvió ValidateOutput (%s); usando fallback.", error,
        )
        parsed_dict = build_fallback_validate_output(
            target_url, raw_tool_outputs, executed_commands, started_at
        )
    else:
        if not isinstance(structured_output, ValidateOutput):
            raise TypeError("El LLM no devolvió ValidateOutput")
        parsed_dict = structured_output.model_dump()

    validate_output = build_validate_output_from_dict(
        parsed_dict, target_url, started_at, executed_commands
    )
    return validate_output, "clean", []