import json
import logging
import shlex
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from datetime import datetime, timezone

import aio_pika
from pydantic import ValidationError

from attack_types import is_crypto_attack, is_sqli_attack, is_xss_attack, is_jwt_attack
from contract_schemas import ValidateOutput, Vulnerability
from dalfox_output import (
    build_dalfox_validator_context,
    merge_verified_dalfox_findings,
    parse_dalfox_output,
    sanitize_dalfox_output_for_snapshot,
)
from helpers import (
    build_validate_sqli_context,
    get_sqli_test_parameters,
    is_same_origin,
    merge_sqlmap_findings,
    merge_sqli_agent_findings,
    merge_sqli_map_findings,
    sanitize_endpoint_for_context,
)
from mcp_skills import call_mcp_skill

logger = logging.getLogger("validate-agent-worker")

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_sort_key(vulnerability: dict) -> tuple[int, str]:
    severity = str(vulnerability.get("severity") or "").upper()
    return (SEVERITY_RANK.get(severity, len(SEVERITY_RANK)), str(vulnerability.get("endpoint") or ""))


def _endpoint_key(endpoint: str) -> str:
    """Clave de comparación por ruta, sin host, para detectar duplicados."""
    if not isinstance(endpoint, str) or not endpoint:
        return ""
    return (urlsplit(endpoint).path.rstrip("/") or "/").casefold()


def _normalize_crypto_severity(finding: dict) -> str:
    """Respeta la severidad de la herramienta y degrada checksums estáticos."""
    severity = str(finding.get("severity") or "").strip().upper()
    if severity not in SEVERITY_RANK:
        severity = "INFO"

    context = finding.get("context") if isinstance(finding.get("context"), dict) else {}
    if str(context.get("role") or "").casefold() == "static_checksum" and severity in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    }:
        # Un checksum estático no participa en ninguna decisión de seguridad:
        # se reporta como falso positivo controlado (LOW), nunca como explotable.
        return "LOW"
    return severity


def _crypto_finding_to_vulnerability(finding: dict, execution: dict) -> dict:
    """Normaliza un elemento del array `findings` de crypto_inspector al contrato Vulnerability."""
    context = finding.get("context") if isinstance(finding.get("context"), dict) else {}
    severity = _normalize_crypto_severity(finding)

    attack_demonstrated = str(finding.get("attack_demonstrated") or "").strip()
    attack_result = finding.get("attack_result")
    attack_result = str(attack_result) if attack_result not in (None, "") else None

    evidence_parts: list[str] = []
    if finding.get("evidence"):
        evidence_parts.append(str(finding["evidence"]))

    if attack_result:
        if attack_demonstrated.casefold() == "dictionary_attack" and (
            str(context.get("role") or "").casefold() != "static_checksum"
        ):
            # Contraseña recuperada = compromiso real de credenciales.
            # (Un checksum estático roto no habilita autenticación: se mantiene LOW.)
            severity = "CRITICAL"
            evidence_parts.append(f"Contraseña recuperada: {attack_result}")
        else:
            evidence_parts.append(f"Resultado del ataque: {attack_result}")

    if not evidence_parts:
        evidence_parts.append("Hallazgo reportado por crypto_inspector sin evidencia textual.")

    return {
        "type": finding.get("title") or "Cryptographic Failure / Insecure Data Exposure",
        "severity": severity,
        "endpoint": execution.get("endpoint", ""),
        "parameter": finding.get("path") or finding.get("key") or None,
        "evidence": " | ".join(dict.fromkeys(evidence_parts)),
        "reproducible_command": execution.get("command", ""),
        "confidence": "HIGH",
        "tools_used": ["crypto_inspector"],
        "finding_id": finding.get("id"),
        "cwe": finding.get("cwe") or None,
        "owasp": finding.get("owasp") or None,
        "attack_demonstrated": attack_demonstrated or None,
        "attack_result": attack_result,
        "attack_chain": [str(step) for step in (finding.get("attack_chain") or []) if step],
        "context_role": context.get("role") or finding.get("context_role") or None,
    }


@dataclass
class ValidationEvidence:
    executed_commands: list[dict] = field(default_factory=list)
    pre_executed_context: list[dict] = field(default_factory=list)
    tool_diagnostics: list[dict] = field(default_factory=list)
    structured_result: dict | None = None
    execution_error: str | None = None


class ValidationStrategy:
    is_sqli = False
    requires_targets = True

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
        token: str | None = None,
    ) -> ValidationEvidence:
        return ValidationEvidence()

    def build_deterministic_output(
        self,
        evidence: ValidationEvidence,
        target_url: str,
        started_at: str,
    ) -> ValidateOutput | None:
        return None

    def build_validation_context(
        self, evidence: ValidationEvidence
    ) -> dict | list[dict]:
        return evidence.pre_executed_context

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        return parsed_output


class SqliValidationStrategy(ValidationStrategy):
    is_sqli = True

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
        token: str | None = None,
    ) -> ValidationEvidence:
        logger.info(
            "[VALIDATE] task_id=%s Ejecutando pruebas SQLi acotadas sobre campos observados",
            task_id,
        )
        evidence = ValidationEvidence()
        jobs = []

        for target in targets:
            request = target.get("request")
            request = request if isinstance(request, dict) else {}
            headers = request.get("headers")
            headers = headers if isinstance(headers, dict) else {}
            body = request.get("body")
            endpoint = str(request.get("url") or target["url"])
            endpoint_url = urljoin(f"{target_url.rstrip('/')}/", endpoint)
            safe_endpoint = sanitize_endpoint_for_context(endpoint_url)

            if not is_same_origin(target_url, endpoint_url):
                evidence.pre_executed_context.append(
                    {
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": safe_endpoint,
                        "tool": "sqli_agent",
                        "status": "SKIPPED",
                        "reason": "endpoint_outside_target_origin",
                    }
                )
                continue

            for parameter, location in get_sqli_test_parameters(endpoint_url, request):
                test_body = body
                if isinstance(test_body, str):
                    if location == "json_body":
                        test_body = json.loads(test_body)
                    elif location == "form_body":
                        test_body = dict(parse_qsl(test_body, keep_blank_values=True))

                jobs.append(
                    {
                        "target": target,
                        "endpoint": endpoint_url,
                        "safe_endpoint": safe_endpoint,
                        "method": target["method"],
                        "headers": headers,
                        "body": test_body,
                        "request": {
                            **request,
                            "url": endpoint_url,
                            "method": target["method"],
                            "headers": headers,
                            "body": test_body,
                        },
                        "location": location,
                        "parameter": parameter,
                    }
                )

        for job in jobs:
            output = await call_mcp_skill(
                channel,
                "sqli_agent",
                {
                    "target_url": job["endpoint"],
                    "param": job["parameter"],
                    "method": job["method"],
                    "location": job["location"],
                    "headers": job["headers"],
                    "body": job["body"],
                },
                tool_timings,
            )
            report = json.loads(output)
            if not isinstance(report, dict):
                raise TypeError("El agente SQLi no devolvió un objeto JSON")
            report.pop("target", None)
            safe_report = json.dumps(report, ensure_ascii=False)
            command = (
                f"MCP sqli_agent --param {job['parameter']} "
                f"--location {job['location']}"
            )
            execution = {
                "tool": "sqli_agent",
                "command": command,
                "target_id": job["target"].get("target_id"),
                "request_id": job["target"].get("request_id"),
                "endpoint": job["safe_endpoint"],
                "parameter": job["parameter"],
                "output": safe_report,
            }
            evidence.executed_commands.append(execution)
            evidence.pre_executed_context.append(
                {
                    **execution,
                    "method": job["method"],
                    "location": job["location"],
                    "status": (
                        "ERROR"
                        if report.get("error") or report.get("persistence_error")
                        else "COMPLETED"
                    ),
                }
            )

        if not jobs:
            evidence.pre_executed_context.extend(
                [
                    {
                        "tool": "sqli_agent",
                        "status": "SKIPPED",
                        "reason": "no_supported_captured_parameters",
                    },
                    {
                        "tool": "sqli_map",
                        "status": "SKIPPED",
                        "reason": "no_supported_captured_parameters",
                    },
                ]
            )
        else:
            logger.info(
                "[VALIDATE] task_id=%s phase=sqli_map starting scans=%d after=sqli_agent",
                task_id,
                len(jobs),
            )
            for job in jobs:
                output = await call_mcp_skill(
                    channel,
                    "sqli_map",
                    {
                        "target_url": job["endpoint"],
                        "request": job["request"],
                        "param": job["parameter"],
                        "action": "validate",
                    },
                    tool_timings,
                )
                report = json.loads(output)
                if not isinstance(report, dict):
                    raise TypeError("SQLMap skill no devolvió un objeto JSON")
                safe_report = json.dumps(report, ensure_ascii=False)
                command = (
                    f"MCP sqli_map --param {json.dumps(job['parameter'])} "
                    "--action validate"
                )
                execution = {
                    "tool": "sqli_map",
                    "command": command,
                    "target_id": job["target"].get("target_id"),
                    "request_id": job["target"].get("request_id"),
                    "endpoint": job["safe_endpoint"],
                    "parameter": job["parameter"],
                    "output": safe_report,
                }
                profile = report.get("profile")
                if report.get("error") or report.get("persistence_error"):
                    status = "ERROR"
                elif isinstance(profile, dict) and profile.get("status") == "partial":
                    status = "PARTIAL"
                else:
                    status = "COMPLETED"
                evidence.executed_commands.append(execution)
                evidence.pre_executed_context.append(
                    {
                        **execution,
                        "method": job["method"],
                        "location": job["location"],
                        "status": status,
                    }
                )

        return evidence

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return build_validate_sqli_context(evidence.pre_executed_context)

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        parsed_output = merge_sqli_agent_findings(parsed_output, evidence.executed_commands)
        parsed_output = merge_sqlmap_findings(parsed_output, evidence.executed_commands)
        parsed_output = merge_sqli_map_findings(parsed_output, evidence.executed_commands)
        logger.info(
            "[VALIDATE] task_id=%s vulnerabilidades tras incorporar SQLi=%d",
            task_id,
            len(parsed_output.get("vulnerabilities", [])),
        )
        return parsed_output


class XssValidationStrategy(ValidationStrategy):
    """Execute Dalfox per captured endpoint and expose only normalized evidence."""

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
        token: str | None = None,
    ) -> ValidationEvidence:
        evidence = ValidationEvidence()
        for target in targets:
            request = target.get("request")
            request = request if isinstance(request, dict) else {}
            endpoint_url = str(request.get("url") or target["url"])
            endpoint_url = urljoin(f"{target_url.rstrip('/')}/", endpoint_url)
            safe_endpoint = sanitize_endpoint_for_context(endpoint_url)

            if not is_same_origin(target_url, endpoint_url):
                evidence.pre_executed_context.append(
                    {
                        "tool": "dalfox",
                        "status": "SKIPPED",
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": safe_endpoint,
                        "method": str(target.get("method") or "GET").upper(),
                        "reason": "endpoint_outside_target_origin",
                        "findings": [],
                    }
                )
                continue

            raw_output = await call_mcp_skill(
                channel,
                "dalfox",
                {"target_url": endpoint_url, "request": request},
                tool_timings,
            )
            result = parse_dalfox_output(raw_output)
            method = str(request.get("method") or target.get("method") or "GET").upper()
            normalized_output = {
                "status": result.status,
                "findings": [
                    {
                        "endpoint": sanitize_endpoint_for_context(finding.endpoint),
                        "method": finding.method or method,
                        "parameter": finding.parameter,
                        "verification": finding.verification,
                        "context": finding.context,
                        "payload": finding.payload,
                        "evidence": finding.evidence,
                    }
                    for finding in result.findings
                ],
                "message": result.message,
            }
            raw_output_snapshot, raw_output_truncated = (
                sanitize_dalfox_output_for_snapshot(raw_output)
            )
            evidence.tool_diagnostics.append(
                {
                    "tool": "dalfox",
                    "target_id": target.get("target_id"),
                    "request_id": target.get("request_id"),
                    "endpoint": safe_endpoint,
                    "method": method,
                    "raw_output_redacted": raw_output_snapshot,
                    "raw_output_truncated": raw_output_truncated,
                    "parsed_output": normalized_output,
                }
            )
            body = request.get("body") or ""
            has_body = bool(body)
            if method != "GET" or has_body:
                command = '/app/dalfox scan --input-type raw-http "/tmp/dalfox-req.txt"'
            else:
                command = f"/app/dalfox scan {shlex.quote(endpoint_url)}"
                headers = request.get("headers")
                if isinstance(headers, dict):
                    cookie = next(
                        (
                            value
                            for name, value in headers.items()
                            if isinstance(name, str) and name.casefold() == "cookie"
                        ),
                        None,
                    )
                    if cookie:
                        command += f" --cookies {shlex.quote(str(cookie))}"
            execution = {
                "tool": "dalfox",
                "command": command,
                "target_id": target.get("target_id"),
                "request_id": target.get("request_id"),
                "endpoint": safe_endpoint,
                "method": method,
                "output": json.dumps(normalized_output, ensure_ascii=False),
            }
            evidence.executed_commands.append(execution)
            evidence.pre_executed_context.append(
                build_dalfox_validator_context(
                    result,
                    target_id=target.get("target_id"),
                    request_id=target.get("request_id"),
                    endpoint=endpoint_url,
                    method=method,
                )
            )
        return evidence

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return {"dalfox_results": evidence.pre_executed_context}

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        merged = merge_verified_dalfox_findings(
            parsed_output, evidence.executed_commands
        )
        logger.info(
            "[VALIDATE] task_id=%s verified_dalfox_findings=%d",
            task_id,
            sum(
                1
                for item in evidence.pre_executed_context
                for finding in item.get("findings", [])
                if finding.get("verification") == "verified"
            ),
        )
        return merged

class CryptoValidationStrategy(ValidationStrategy):
    """Ejecuta crypto_inspector sobre el objetivo y compila la evidencia criptográfica."""

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
    ) -> ValidationEvidence:
        logger.info(
            "[VALIDATE] task_id=%s Ejecutando crypto_inspector sobre %s",
            task_id,
            target_url,
        )
        evidence = ValidationEvidence()

        for target in targets:
            request = target.get("request") or {}
            raw_endpoint = str(request.get("url") or target.get("url") or target.get("endpoint") or target_url)
            target_parts = urlsplit(target_url)
            endpoint_parts = urlsplit(raw_endpoint)

            if target_parts.netloc and endpoint_parts.netloc and target_parts.netloc != endpoint_parts.netloc:
                endpoint_url = urlunsplit((
                    target_parts.scheme or "http",
                    target_parts.netloc,
                    endpoint_parts.path or "/",
                    endpoint_parts.query,
                    "",
                ))
            else:
                endpoint_url = urljoin(f"{target_url.rstrip('/')}/", raw_endpoint)

            safe_endpoint = sanitize_endpoint_for_context(endpoint_url)

            if not is_same_origin(target_url, endpoint_url):
                evidence.pre_executed_context.append(
                    {
                        "tool": "crypto_inspector",
                        "status": "SKIPPED",
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": safe_endpoint,
                        "reason": "endpoint_outside_target_origin",
                    }
                )
                continue

            # Invocación de la habilidad MCP crypto_inspector
            output = await call_mcp_skill(
                channel,
                "crypto_inspector",
                {"target_url": endpoint_url},
                tool_timings,
            )

            try:
                report = json.loads(output)
            except (TypeError, json.JSONDecodeError):
                report = {"error": "Respuesta no válida de crypto_inspector", "raw": str(output)}

            safe_report = json.dumps(report, ensure_ascii=False)
            command = f"MCP crypto_inspector --target {shlex.quote(endpoint_url)}"

            execution = {
                "tool": "crypto_inspector",
                "command": command,
                "target_id": target.get("target_id"),
                "request_id": target.get("request_id"),
                "endpoint": safe_endpoint,
                "output": safe_report,
            }

            evidence.executed_commands.append(execution)
            evidence.pre_executed_context.append(
                {
                    **execution,
                    "status": "ERROR" if report.get("error") else "COMPLETED",
                }
            )

        return evidence

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return {"crypto_inspector_results": evidence.pre_executed_context}

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        merged = dict(parsed_output) if isinstance(parsed_output, dict) else {}
        llm_vulnerabilities = [
            vulnerability
            for vulnerability in (merged.get("vulnerabilities") or [])
            if isinstance(vulnerability, dict)
        ]
        crypto_executions = [
            item
            for item in evidence.executed_commands
            if item.get("tool") == "crypto_inspector"
        ]

        # 1. El array `findings` de la herramienta es la fuente de verdad:
        #    se normaliza completo (severidad, evidencia, cadena de ataque, CWE/OWASP).
        derived: list[dict] = []
        seen_keys: set[tuple] = set()
        for execution in crypto_executions:
            try:
                report = json.loads(execution.get("output") or "{}")
            except (TypeError, json.JSONDecodeError):
                logger.warning(
                    "[VALIDATE] task_id=%s salida de crypto_inspector no es JSON válido; se omite",
                    task_id,
                )
                continue

            findings = report.get("findings")
            if not isinstance(findings, list):
                logger.warning(
                    "[VALIDATE] task_id=%s crypto_inspector no devolvió el array 'findings'; "
                    "no se pueden promover hallazgos deterministas",
                    task_id,
                )
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                vulnerability = _crypto_finding_to_vulnerability(finding, execution)
                dedupe_key = (
                    _endpoint_key(vulnerability["endpoint"]),
                    vulnerability.get("finding_id") or vulnerability["type"],
                    vulnerability.get("parameter"),
                    vulnerability.get("attack_result"),
                )
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)
                derived.append(vulnerability)

        # 2. Del LLM solo conservamos lo que la herramienta no cubrió ya por endpoint,
        #    para no duplicar ni dejar que el LLM rebaje/omita hallazgos deterministas.
        covered_paths = {_endpoint_key(item["endpoint"]) for item in derived}
        kept_llm: list[dict] = []
        for vulnerability in llm_vulnerabilities:
            if _endpoint_key(str(vulnerability.get("endpoint") or "")) in covered_paths:
                continue
            tools_used = vulnerability.setdefault("tools_used", ["crypto_inspector"])
            if isinstance(tools_used, str):
                tools_used = [tool.strip() for tool in tools_used.split(",") if tool.strip()]
                vulnerability["tools_used"] = tools_used
            if "crypto_inspector" not in tools_used:
                tools_used.append("crypto_inspector")
            kept_llm.append(vulnerability)

        # 3. CRITICAL primero, para que el Reporter los reciba ordenados.
        merged["vulnerabilities"] = sorted(derived + kept_llm, key=_severity_sort_key)

        logger.info(
            "[VALIDATE] task_id=%s vulnerabilidades tras incorporar crypto_inspector=%d "
            "(deterministas=%d, llm_extra=%d)",
            task_id,
            len(merged["vulnerabilities"]),
            len(derived),
            len(kept_llm),
        )
        return merged

class JwtValidationStrategy(ValidationStrategy):
    requires_targets = False
    _valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
        token: str | None = None,
    ) -> ValidationEvidence:
        evidence = ValidationEvidence()
        if not token:
            evidence.execution_error = (
                "El ataque JWT requiere un token de sesión válido. "
                "No se recibió token en el payload."
            )
            logger.warning("[VALIDATE] JWT requiere token; no se recibió uno.")
            return evidence

        try:
            raw_output = await call_mcp_skill(
                channel,
                "jwt_tool",
                {"target_url": target_url, "token": token},
                tool_timings,
            )
        except Exception as exc:
            logger.exception("[VALIDATE] Falló la invocación de jwt_tool")
            evidence.execution_error = f"jwt_tool falló: {exc}"
            return evidence

        try:
            report = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.error("[VALIDATE] jwt_tool devolvió salida no-JSON: %s", exc)
            evidence.execution_error = (
                f"jwt_tool devolvió salida no-JSON: {str(exc)[:200]}"
            )
            evidence.pre_executed_context.append(
                {
                    "raw_preview": (
                        raw_output[:500] if isinstance(raw_output, str) else ""
                    )
                }
            )
            return evidence

        if not isinstance(report, dict):
            evidence.execution_error = "jwt_tool no devolvió un objeto JSON"
            return evidence

        evidence.structured_result = report
        if report.get("error"):
            evidence.execution_error = f"jwt_tool error: {report.get('error')}"
            evidence.pre_executed_context.append(
                {
                    "message": report.get("message", ""),
                    "hint": report.get("hint", ""),
                }
            )
        return evidence

    def build_deterministic_output(
        self,
        evidence: ValidationEvidence,
        target_url: str,
        started_at: str,
    ) -> ValidateOutput:
        now = datetime.now(timezone.utc).isoformat()
        report = evidence.structured_result or {}
        reproducible = f"python jwt_tool_handler.py --target {target_url} --token <JWT>"
        vulnerabilities: list[Vulnerability] = []

        for finding in report.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue

            severity = str(finding.get("severity", "MEDIUM")).upper()
            if severity not in self._valid_severities:
                severity = "MEDIUM"

            title = finding.get("title") or "JWT weakness"
            description = finding.get("description") or ""
            evidence_field = finding.get("evidence") or ""
            cwe = finding.get("cwe") or ""
            owasp = finding.get("owasp") or ""
            remediation = finding.get("remediation") or ""
            composed = " | ".join(
                str(part) for part in (description, evidence_field) if part
            )
            mapping = " / ".join(str(item) for item in (cwe, owasp) if item)
            evidence_text = (
                f"[{mapping}] {composed}"
                if mapping and composed
                else composed or str(title)
            )
            if remediation:
                evidence_text += f" | Mitigation: {remediation}"

            try:
                vulnerabilities.append(
                    Vulnerability(
                        type=str(title),
                        severity=severity,
                        endpoint=target_url,
                        parameter=None,
                        evidence=evidence_text[:1500],
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
        if evidence.execution_error:
            context = {
                "reason": evidence.execution_error,
                **(evidence.pre_executed_context[0]
                   if evidence.pre_executed_context else {}),
                **context,
            }
        return ValidateOutput(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            unconfirmed_findings=[context],
            scan_started_at=started_at,
            scan_finished_at=now,
        )


def get_validation_strategy(attack_type: str) -> ValidationStrategy:
    if is_jwt_attack(attack_type):
        return JwtValidationStrategy()
    if is_sqli_attack(attack_type):
        return SqliValidationStrategy()
    if is_xss_attack(attack_type):
        return XssValidationStrategy()
    if is_crypto_attack(attack_type):
        return CryptoValidationStrategy()
    return ValidationStrategy()
