import json
import logging
import shlex
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import aio_pika

from attack_types import is_crypto_attack, is_sqli_attack, is_xss_attack
from dalfox_output import (
    build_dalfox_validator_context,
    merge_verified_dalfox_findings,
    parse_dalfox_output,
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


@dataclass
class ValidationEvidence:
    executed_commands: list[dict] = field(default_factory=list)
    pre_executed_context: list[dict] = field(default_factory=list)


class ValidationStrategy:
    is_sqli = False

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
    ) -> ValidationEvidence:
        return ValidationEvidence()

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
            normalized_output = {
                "status": result.status,
                "findings": [
                    {
                        "endpoint": sanitize_endpoint_for_context(finding.endpoint),
                        "method": finding.method,
                        "parameter": finding.parameter,
                        "verification": finding.verification,
                        "context": finding.context,
                        "payload": finding.payload,
                    }
                    for finding in result.findings
                ],
                "message": result.message,
            }
            method = str(request.get("method") or target.get("method") or "GET").upper()
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
        vulnerabilities = list(merged.get("vulnerabilities") or [])
        crypto_executions = [
            item
            for item in evidence.executed_commands
            if item.get("tool") == "crypto_inspector"
        ]

        for vulnerability in vulnerabilities:
            if isinstance(vulnerability, dict):
                vulnerability.setdefault("tools_used", ["crypto_inspector"])
                if "crypto_inspector" not in vulnerability["tools_used"]:
                    vulnerability["tools_used"].append("crypto_inspector")

        # Si el LLM omitio clasificar los hallazgos positivos devueltos por crypto_inspector:
        if not vulnerabilities and crypto_executions:
            for item in crypto_executions:
                try:
                    report = json.loads(item.get("output", "{}"))
                except Exception:
                    continue

                json_findings = report.get("json_structure_findings", [])
                regex_matches = [
                    m for m in report.get("regex_matches", [])
                    if m.get("pattern") in {
                        "SHA1 Hash", "MD5 Hash", "SHA256 Hash", "JWT Token",
                        "Generic Secret Key", "RSA/Generic Private Key"
                    }
                ]
                multilevel = report.get("multilevel_decodings", [])

                if json_findings or regex_matches or multilevel:
                    evidence_snippets = []
                    for jf in json_findings:
                        evidence_snippets.append(f"Clave criptográfica expuesta: {jf.get('key')} (path: {jf.get('path')})")
                    for rm in regex_matches:
                        samples = rm.get("samples", [])
                        evidence_snippets.append(f"Patrón detectado: {rm.get('pattern')} ({len(samples)} muestras)")
                    for ml in multilevel:
                        evidence_snippets.append(f"Desofuscación multinivel: {ml.get('final_decoded_value')}")

                    vulnerabilities.append({
                        "type": "Cryptographic Failure / Insecure Data Exposure",
                        "severity": "HIGH",
                        "endpoint": item.get("endpoint", ""),
                        "parameter": None,
                        "evidence": " | ".join(evidence_snippets[:3]),
                        "reproducible_command": item.get("command", ""),
                        "confidence": "HIGH",
                        "tools_used": ["crypto_inspector"],
                    })

        merged["vulnerabilities"] = vulnerabilities
        logger.info(
            "[VALIDATE] task_id=%s vulnerabilidades tras incorporar crypto_inspector=%d",
            task_id,
            len(vulnerabilities),
        )
        return merged

def get_validation_strategy(attack_type: str) -> ValidationStrategy:
    if is_sqli_attack(attack_type):
        return SqliValidationStrategy()
    if is_xss_attack(attack_type):
        return XssValidationStrategy()
    if is_crypto_attack(attack_type):
        return CryptoValidationStrategy()
    return ValidationStrategy()
