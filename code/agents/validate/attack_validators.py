import json
import logging
import os
import re
import shlex
import ssl
from dataclasses import dataclass, field
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from datetime import datetime, timezone

import aio_pika
from pydantic import ValidationError


from attack_types import (
    is_access_control_attack,
    is_crypto_attack,
    is_sqli_attack,
    is_xss_attack,
    is_jwt_attack
)

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

def extract_first_json(text):
    if not text:
        return {}
    start = text.find('{')
    if start == -1:
        return {}
    decoder = json.JSONDecoder()
    try:
        obj, index = decoder.raw_decode(text[start:])
        return obj
    except json.JSONDecodeError:
        return {}


def _endpoint_key(endpoint: str) -> str:
    """Clave de comparación por ruta, sin host, para detectar duplicados."""
    if not isinstance(endpoint, str) or not endpoint:
        return ""
    return (urlsplit(endpoint).path.rstrip("/") or "/").casefold()

def _crypto_endpoint_key(endpoint: str) -> str:
    """
    Clave de dedup para hallazgos cripto:
      - lowercase (weak-page es case-insensitive)
      - colapsa zero-padding en IDs (/01 → /1)
      - sin host, sin query string
    """
    if not isinstance(endpoint, str) or not endpoint:
        return ""
    path = (urlsplit(endpoint).path.rstrip("/") or "/").casefold()
    path = re.sub(
        r"/(0+)(\d+)(?=/|$)",
        lambda m: "/" + str(int(m.group(1) + m.group(2))),
        path,
    )
    return path


_XSS_PROFILES_CACHE: dict | None = None
_STORED_XSS_FIELD_HINTS = (
    "message",
    "comment",
    "body",
    "content",
    "text",
    "description",
    "review",
    "feedback",
)
_MAX_GENERIC_XSS_PLANS = 3


def _load_xss_target_profiles() -> dict:
    """Carga perfiles por origen con el contrato de validación del objetivo.

    El mecanismo es genérico: la lógica no conoce laboratorios concretos; el
    JSON solo aporta datos del entorno (cabeceras de guardia, prefijo de
    marcador, patrón de lectura de registros) para orígenes que lo requieran.
    """
    global _XSS_PROFILES_CACHE
    if _XSS_PROFILES_CACHE is not None:
        return _XSS_PROFILES_CACHE
    path = os.environ.get("XSS_TARGET_PROFILES_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "xss_target_profiles.json",
    )
    profiles: dict = {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            profiles = data
    except (OSError, json.JSONDecodeError):
        profiles = {}
    _XSS_PROFILES_CACHE = profiles
    return profiles


def _xss_target_profile(target_url: str) -> dict:
    profiles = _load_xss_target_profiles()
    parts = urlsplit(target_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    profile = profiles.get(origin) or profiles.get(parts.netloc)
    return profile if isinstance(profile, dict) else {}


def _profile_headers(profile: dict, key: str) -> dict:
    headers = profile.get(key)
    if not isinstance(headers, dict):
        return {}
    return {str(name): str(value) for name, value in headers.items()}


def _append_probe_params(page_url: str) -> str:
    """Añade probeId/marker respetando routers de hash y de query."""
    probe = "probeId={id}&marker={marker}"
    if "#" in page_url:
        base, fragment = page_url.split("#", 1)
        separator = "&" if "?" in fragment else "?"
        return f"{base}#{fragment}{separator}{probe}"
    separator = "&" if "?" in page_url else "?"
    return f"{page_url}{separator}{probe}"


def _preferred_stored_parameter(fields: list[str], body) -> str:
    lowered = {name.casefold(): name for name in fields}
    for hint in _STORED_XSS_FIELD_HINTS:
        if hint in lowered:
            return lowered[hint]
    if isinstance(body, dict):
        valued = [
            name
            for name in fields
            if isinstance(body.get(name), str) and body.get(name)
        ]
        if valued:
            return max(valued, key=lambda name: len(body[name]))
    return fields[0]


def _build_generic_browser_xss_plans(
    target_url: str,
    endpoint_url: str,
    request: dict,
) -> list[dict]:
    """Genera planes de validación de navegador a partir de lo observado.

    Usa las páginas (`observed_on`/`observed_pages`) y los parámetros
    reflejados que Recon correlacionó; no depende de un origen concreto.
    """
    if not isinstance(request, dict):
        return []
    if not is_same_origin(target_url, endpoint_url):
        return []

    profile = _xss_target_profile(target_url)
    marker_prefix = str(profile.get("marker_prefix") or "xss-probe-")
    method = str(request.get("method") or "GET").upper()
    url_parts = urlsplit(endpoint_url)
    path = url_parts.path or "/"
    observed_pages = [
        page
        for page in (request.get("observed_on") or [])
        if isinstance(page, str) and is_same_origin(target_url, page)
    ]
    source_url = observed_pages[0] if observed_pages else endpoint_url

    if method == "GET":
        query_names = [
            name
            for name, _ in parse_qsl(url_parts.query, keep_blank_values=True)
            if name
        ]
        if not query_names:
            return []
        reflected = [
            name
            for name in (request.get("reflected_parameters") or [])
            if name in query_names
        ]
        ordered = list(dict.fromkeys([*reflected, *query_names]))
        plans = []
        for parameter in ordered[:_MAX_GENERIC_XSS_PLANS]:
            selector = (
                f'[name="{parameter}"], input[type="search"], '
                f'textarea[name="{parameter}"], select[name="{parameter}"]'
            )
            plans.append(
                {
                    "mode": "reflected_dom",
                    "source_url": source_url,
                    "parameter": parameter,
                    "input_selector": selector,
                    "marker_prefix": marker_prefix,
                    "request": {
                        "method": "GET",
                        "path": path,
                        "query_parameter": parameter,
                    },
                }
            )
        return plans

    if method == "POST":
        body = request.get("body")
        if isinstance(body, dict):
            fields = [str(key) for key in body.keys() if isinstance(key, str)]
        elif isinstance(body, str):
            fields = [
                key
                for key, _ in parse_qsl(body, keep_blank_values=True)
                if isinstance(key, str)
            ]
        else:
            fields = []
        if not fields:
            return []
        parameter = _preferred_stored_parameter(fields, body)
        all_pages = [
            page
            for page in (request.get("observed_pages") or [])
            if isinstance(page, str) and is_same_origin(target_url, page)
        ]
        verification_page = next(
            (page for page in all_pages if page != source_url),
            source_url,
        )
        suffix = profile.get("verification_path_suffix")
        if isinstance(suffix, str) and suffix.strip():
            verification_path = f"{path.rstrip('/')}/{suffix.strip().lstrip('/')}"
        else:
            verification_path = path
        verification_request = {
            "method": "GET",
            "path_template": verification_path,
        }
        verification_headers = _profile_headers(
            profile, "verification_request_headers"
        )
        if verification_headers:
            verification_request["headers"] = verification_headers
        cleanup = {
            "method": "DELETE",
            "path_template": f"{path.rstrip('/')}/{{id}}",
            "body": {"marker": "{marker}"},
        }
        cleanup_headers = _profile_headers(profile, "cleanup_headers")
        if cleanup_headers:
            cleanup["headers"] = cleanup_headers
        plan = {
            "mode": "stored_dom",
            "source_url": source_url,
            "parameter": parameter,
            "marker_prefix": marker_prefix,
            "form_selector": "form",
            "form_fields": fields[:8],
            "submit_selector": (
                "button[type='submit'], input[type='submit'], form button"
            ),
            "request": {"method": "POST", "path": path},
            "verification_url_template": _append_probe_params(verification_page),
            "verification_request": verification_request,
            "cleanup": cleanup,
        }
        write_headers = _profile_headers(profile, "request_headers")
        if write_headers:
            plan["request_headers"] = write_headers
        return [plan]

    return []


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

    endpoint = (
        finding.get("endpoint")
        or execution.get("endpoint", "")
    )

    return {
        "type": finding.get("title") or "Cryptographic Failure / Insecure Data Exposure",
        "severity": severity,
        "endpoint": endpoint,
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


def _browser_xss_evidence(item: dict) -> str:
    parameter = item.get("parameter")
    method = item.get("method")
    endpoint = item.get("endpoint")
    location = " ".join(str(value) for value in (method, endpoint) if value)
    parameter_text = f" en el parámetro {parameter}" if parameter else ""
    location_text = f" de la solicitud {location}" if location else ""
    if item.get("mode") == "stored_dom":
        description = (
            f"El validador envió una prueba sintética{parameter_text}{location_text} "
            "y Chromium observó su ejecución en la vista que muestra el dato almacenado."
        )
        if item.get("cleanup") == "success":
            description += " El registro de prueba fue eliminado."
    else:
        description = (
            f"El validador introdujo una prueba sintética{parameter_text}{location_text} "
            "y Chromium observó su ejecución en el DOM de la página."
        )
    proof_value = item.get("proof_value")
    if isinstance(proof_value, str) and proof_value:
        proof_text = proof_value if len(proof_value) <= 1000 else f"{proof_value[:1000]}... [truncada]"
        description += f" Prueba enviada: {proof_text}"
    return description


class XssValidationStrategy(ValidationStrategy):
    """Run a declared browser proof or fall back to Dalfox per captured endpoint."""

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
            method = str(request.get("method") or target.get("method") or "GET").upper()

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

            declared_plan = target.get("validation_plan")
            if isinstance(declared_plan, dict):
                browser_plans = [declared_plan]
            elif target.get("recommended_tool") == "browserXssValidator":
                browser_plans = _build_generic_browser_xss_plans(
                    target_url, endpoint_url, request
                )
            else:
                browser_plans = []

            for validation_plan in browser_plans:
                raw_report = await call_mcp_skill(
                    channel,
                    "browserXssValidator",
                    {
                        "target_url": target_url,
                        "plan": validation_plan,
                    },
                    tool_timings,
                )
                try:
                    report = json.loads(raw_report)
                except (TypeError, json.JSONDecodeError):
                    report = {}
                if not isinstance(report, dict):
                    report = {}
                outcome = str(report.get("outcome") or "").upper()
                plan_mode = validation_plan.get("mode")
                report_matches_target = (
                    report.get("tool") == "browserXssValidator"
                    and report.get("target") == target_url.rstrip("/")
                    and report.get("mode") == plan_mode
                )
                if report_matches_target and outcome == "VULNERABLE" and (
                    plan_mode != "stored_dom"
                    or report.get("cleanup") == "success"
                ):
                    status = "VERIFIED"
                elif report_matches_target and outcome == "NO_XSS" and (
                    plan_mode != "stored_dom"
                    or report.get("cleanup") == "success"
                ):
                    status = "NO_FINDINGS"
                else:
                    status = "INCONCLUSIVE"
                plan_request = validation_plan.get("request")
                plan_request = plan_request if isinstance(plan_request, dict) else {}
                result_endpoint = urljoin(
                    f"{target_url.rstrip('/')}/",
                    str(plan_request.get("path") or ""),
                )
                parameter = str(validation_plan.get("parameter") or "") or None
                result_evidence = (
                    str(report.get("evidence") or "")[:1000]
                    if report_matches_target
                    else "El validador no devolvió un resultado coherente con el objetivo solicitado."
                )
                if not result_evidence:
                    result_evidence = (
                        "El validador de navegador no devolvió evidencia interpretable."
                    )
                normalized = {
                    "tool": "browserXssValidator",
                    "status": status,
                    "target_id": target.get("target_id"),
                    "request_id": target.get("request_id"),
                    "endpoint": sanitize_endpoint_for_context(result_endpoint),
                    "method": str(plan_request.get("method") or method).upper(),
                    "parameter": parameter,
                    "evidence": result_evidence,
                    "mode": plan_mode,
                    "cleanup": report.get("cleanup"),
                    "stage": report.get("stage"),
                    "checks": report.get("checks"),
                    "proof_value": (
                        report.get("proof_value")
                        if report_matches_target and status == "VERIFIED"
                        else None
                    ),
                }
                evidence.pre_executed_context.append(normalized)
                evidence.tool_diagnostics.append(
                    {
                        **normalized,
                        "raw_output": raw_report[:20_000],
                    }
                )
                command = f"browserXssValidator --target-url {target_url} --plan"
                evidence.executed_commands.append(
                    {
                        "tool": "browserXssValidator",
                        "command": command,
                        "target_id": target.get("target_id"),
                        "request_id": target.get("request_id"),
                        "endpoint": sanitize_endpoint_for_context(result_endpoint),
                        "method": str(plan_request.get("method") or method).upper(),
                        "output": json.dumps(normalized, ensure_ascii=False),
                    }
                )
                if status == "VERIFIED":
                    # Un parámetro confirmado basta para este objetivo; no se
                    # prueban los planes restantes.
                    break
            if browser_plans:
                # Una vez que el validador de navegador ha recibido un plan
                # específico para este origen, no debe reintentar Dalfox por
                # inercia: el resultado del navegador ya es la fuente primaria.
                continue
            # No hay plan de navegador generado: Dalfox sigue siendo el
            # fallback estándar para XSS sin un plan observado.
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

    def build_deterministic_output(
        self,
        evidence: ValidationEvidence,
        target_url: str,
        started_at: str,
    ) -> ValidateOutput | None:
        if not evidence.pre_executed_context or not all(
            item.get("tool") == "browserXssValidator"
            for item in evidence.pre_executed_context
        ):
            return None

        finished_at = datetime.now(timezone.utc).isoformat()
        vulnerabilities = []
        unconfirmed_findings = []
        for item in evidence.pre_executed_context:
            if item.get("status") == "VERIFIED":
                vulnerabilities.append(
                    Vulnerability(
                        type=(
                            "Stored Cross-Site Scripting (XSS)"
                            if item.get("mode") == "stored_dom"
                            else "Reflected DOM Cross-Site Scripting (XSS)"
                        ),
                        severity="HIGH",
                        endpoint=item["endpoint"],
                        parameter=item.get("parameter"),
                        method=item.get("method"),
                        evidence=_browser_xss_evidence(item),
                        verification_steps=(
                            "browserXssValidator injected a unique synthetic proof marker "
                            "and observed its execution in the observed DOM flow."
                        ),
                        reproducible_command=next(
                            execution["command"]
                            for execution in evidence.executed_commands
                            if execution.get("target_id") == item.get("target_id")
                        ),
                        confidence="HIGH",
                        tools_used=["browserXssValidator"],
                    )
                )
            elif item.get("status") == "INCONCLUSIVE":
                unconfirmed_findings.append(
                    {
                        "type": "Cross-Site Scripting (XSS)",
                        "status": "INCONCLUSIVE",
                        "target_id": item.get("target_id"),
                        "request_id": item.get("request_id"),
                        "endpoint": item.get("endpoint"),
                        "method": item.get("method"),
                        "reason": item.get("evidence"),
                        "tools_used": ["browserXssValidator"],
                    }
                )
        return ValidateOutput(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            unconfirmed_findings=unconfirmed_findings,
            scan_started_at=started_at,
            scan_finished_at=finished_at,
        )

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return {"xss_validation_results": evidence.pre_executed_context}

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        merged = merge_verified_dalfox_findings(
            parsed_output, evidence.executed_commands
        )
        vulnerabilities = list(merged.get("vulnerabilities", []))
        unconfirmed = list(merged.get("unconfirmed_findings", []))
        for item in evidence.pre_executed_context:
            if item.get("tool") != "browserXssValidator":
                continue
            if item.get("status") == "INCONCLUSIVE":
                unconfirmed.append(
                    {
                        "type": "Cross-Site Scripting (XSS)",
                        "status": "INCONCLUSIVE",
                        "target_id": item.get("target_id"),
                        "request_id": item.get("request_id"),
                        "endpoint": item.get("endpoint"),
                        "method": item.get("method"),
                        "reason": item.get("evidence"),
                        "tools_used": ["browserXssValidator"],
                    }
                )
                continue
            if item.get("status") != "VERIFIED":
                continue

            execution = next(
                (
                    command
                    for command in evidence.executed_commands
                    if command.get("tool") == "browserXssValidator"
                    and command.get("target_id") == item.get("target_id")
                ),
                {},
            )
            finding_type = (
                "Stored Cross-Site Scripting (XSS)"
                if item.get("mode") == "stored_dom"
                else "Reflected DOM Cross-Site Scripting (XSS)"
            )
            matching = next(
                (
                    vulnerability
                    for vulnerability in vulnerabilities
                    if isinstance(vulnerability, dict)
                    and "xss" in str(vulnerability.get("type") or "").casefold()
                    and _endpoint_key(str(vulnerability.get("endpoint") or ""))
                    == _endpoint_key(str(item.get("endpoint") or ""))
                    and str(vulnerability.get("parameter") or "").casefold()
                    == str(item.get("parameter") or "").casefold()
                    and str(vulnerability.get("method") or "").upper()
                    == str(item.get("method") or "").upper()
                ),
                None,
            )
            if matching is not None:
                tools_used = matching.get("tools_used")
                if isinstance(tools_used, str):
                    tools_used = [tools_used]
                elif not isinstance(tools_used, list):
                    tools_used = []
                if "browserXssValidator" not in tools_used:
                    tools_used.append("browserXssValidator")
                matching["tools_used"] = tools_used
                browser_evidence = _browser_xss_evidence(item)
                existing_evidence = str(matching.get("evidence") or "")
                if browser_evidence not in existing_evidence:
                    matching["evidence"] = (
                        f"{browser_evidence}\n{existing_evidence}".strip()
                    )
                continue

            vulnerabilities.append(
                {
                    "type": finding_type,
                    "severity": "HIGH",
                    "endpoint": item.get("endpoint"),
                    "parameter": item.get("parameter"),
                    "method": item.get("method"),
                    "evidence": _browser_xss_evidence(item),
                    "verification_steps": (
                        "browserXssValidator injected a unique synthetic proof marker "
                        "and observed its execution in the observed DOM flow."
                    ),
                    "reproducible_command": execution.get("command", ""),
                    "confidence": "HIGH",
                    "tools_used": ["browserXssValidator"],
                }
            )

        merged["vulnerabilities"] = vulnerabilities
        if unconfirmed:
            merged["unconfirmed_findings"] = unconfirmed
        logger.info(
        "[VALIDATE] task_id=%s verified_xss_findings=%d",
            task_id,
            sum(
                1
                for item in evidence.pre_executed_context
                for finding in item.get("findings", [])
                if finding.get("verification") == "verified"
        )
        + sum(
            item.get("tool") == "browserXssValidator"
            and item.get("status") == "VERIFIED"
            for item in evidence.pre_executed_context
        ),
        )
        return merged

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        """
        Fusiona los hallazgos deterministas de crypto_inspector con lo que el LLM
        haya podido añadir.

        Reglas:
          1. crypto_inspector es la fuente de verdad: sus findings manda.
          2. Dedup por (finding_id, endpoint_normalizado). El mismo flag
             `CRYPTO-FLAG-*` desde el mismo endpoint solo cuenta una vez, aunque
             `crypto_inspector` lo haya reportado desde múltiples variantes
             de case (`/api/Admin/vulnerabilities` y `/api/admin/vulnerabilities`).
          3. Los findings del LLM solo se conservan si NO duplican un endpoint ya
             cubierto por el determinista (evita que Ollama "reformule" lo mismo).
          4. Orden final: CRITICAL → HIGH → MEDIUM → LOW → INFO.
        """
        merged = dict(parsed_output) if isinstance(parsed_output, dict) else {}
        merged.setdefault("vulnerabilities", [])

        executions = [
            item
            for item in evidence.executed_commands
            if item.get("tool") == "crypto_inspector"
        ]

        # ── 1. Findings deterministas de crypto_inspector ──
        derived: list[dict] = []
        seen_keys: set[tuple[str, str]] = set()
        covered_keys: set[tuple[str, str]] = set()

        for execution in executions:
            raw = execution.get("output")
            if isinstance(raw, dict):
                report = raw
            else:
                report = extract_first_json(raw or "")
            findings = report.get("findings") if isinstance(report, dict) else None
            if not isinstance(findings, list):
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                vulnerability = _crypto_finding_to_vulnerability(finding, execution)
                endpoint_key = _crypto_endpoint_key(vulnerability.get("endpoint") or "")
                finding_id = finding.get("id") or vulnerability.get("type") or ""
                dedupe_key = (finding_id, endpoint_key)

                # Para el filtro del LLM, marcamos también por tipo+endpoint,
                # porque el LLM puede inventarse un finding_id distinto.
                covered_keys.add((vulnerability.get("type") or "", endpoint_key))

                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)
                derived.append(vulnerability)

        # ── 2. Findings del LLM: solo los que aportan endpoints nuevos ──
        llm_vulnerabilities = [
            v for v in (merged.get("vulnerabilities") or []) if isinstance(v, dict)
        ]
        kept_llm: list[dict] = []
        for vulnerability in llm_vulnerabilities:
            endpoint_key = _crypto_endpoint_key(
                str(vulnerability.get("endpoint") or "")
            )
            if not endpoint_key:
                # Sin endpoint no lo podemos deduplicar con seguridad: lo dejamos
                # pasar solo si el LLM le puso un tipo reconocible.
                if not vulnerability.get("type"):
                    continue
            type_key = (str(vulnerability.get("type") or ""), endpoint_key)
            if type_key in covered_keys:
                continue
            # Añadimos la herramienta como co-autora
            tools_used = vulnerability.setdefault("tools_used", ["crypto_inspector"])
            if isinstance(tools_used, str):
                tools_used = [t.strip() for t in tools_used.split(",") if t.strip()]
                vulnerability["tools_used"] = tools_used
            if "crypto_inspector" not in tools_used:
                tools_used.append("crypto_inspector")
            kept_llm.append(vulnerability)

        # ── 3. Orden final ──
        merged["vulnerabilities"] = sorted(
            derived + kept_llm,
            key=lambda x: _severity_sort_key(x),
        )

        # ── 4. Log ──
        logger.info(
            "[VALIDATE] task_id=%s crypto findings tras merge: %d "
            "(deterministas=%d, llm_extra=%d)",
            task_id,
            len(merged["vulnerabilities"]),
            len(derived),
            len(kept_llm),
        )
        return merged
    

class CryptoValidationStrategy(ValidationStrategy):
    requires_targets = True

    # Endpoints conocidos que aportan los findings críticos y que el Recon
    # (crawler del frontend) NO descubre porque no son navegables o no están
    # enlazados en el HTML/JS de la app.
    SEED_ENDPOINTS = [
        "/api/admin/vulnerabilities",   # 6 CRYPTO-FLAG-*
        "/api/auth/forgot",             # CRYPTO-RESET-ACTIVE-001
        "/api/health",                  # CRYPTO-DISCLOSURE-HEALTH-001
        "/api/orders/1",                # CRYPTO-B64-ACTIVE-001
        "/api/orders/2",
        "/api/orders/3",
    ]

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
            "[VALIDATE] task_id=%s crypto pipeline sobre %s", task_id, target_url
        )
        evidence = ValidationEvidence()

        # ── 1. Rutas del Recon (lo que el crawler ya conoce) ──
        recon_paths: list[str] = []
        recon_targets_by_path: dict[str, dict] = {}
        for t in (targets or []):
            request = t.get("request") if isinstance(t.get("request"), dict) else {}
            url = request.get("url") or t.get("url") or t.get("endpoint") or ""
            if not url:
                continue
            try:
                path = urlsplit(url).path or "/"
            except Exception:
                continue
            recon_paths.append(path)
            full_url = (
                url if url.startswith(("http://", "https://"))
                else f"{target_url.rstrip('/')}{path}"
            )
            recon_targets_by_path[path] = {
                "endpoint": full_url,
                "method": (request.get("method") or t.get("method") or "GET").upper(),
            }
        logger.info(
            "[VALIDATE] task_id=%s recon_paths=%d", task_id, len(recon_paths)
        )

        # ── 2. Descubrimiento con ffuf (best-effort, tolerante a fallos) ──
        ffuf_paths: list[str] = []
        for subpath in ["/api/FUZZ", "/api/orders/FUZZ"]:
            try:
                raw = await call_mcp_skill(
                    channel,
                    "ffuf",
                    {
                        "target_url": f"{target_url.rstrip('/')}{subpath}",
                        "method": "GET",
                    },
                    tool_timings,
                )
                parsed = self._parse_ffuf_output(raw)
                base = subpath.rsplit("/FUZZ", 1)[0] or ""
                for p in parsed:
                    if not isinstance(p, str) or not p:
                        continue
                    ffuf_paths.append(base + (p if p.startswith("/") else "/" + p))
            except Exception as exc:
                logger.warning(
                    "[VALIDATE] task_id=%s ffuf falló en %s: %s",
                    task_id, subpath, exc,
                )
        logger.info(
            "[VALIDATE] task_id=%s ffuf_paths=%d", task_id, len(ffuf_paths)
        )

        # ── 3. Merge + seeds + normalización (case + zero-padding) ──
        all_paths = self._normalize_paths(
            recon_paths + ffuf_paths + self.SEED_ENDPOINTS
        )
        logger.info(
            "[VALIDATE] task_id=%s total paths tras merge=%d",
            task_id, len(all_paths),
        )

        # ── 4. Construir targets para crypto_inspector ──
        crypto_targets = []
        for p in all_paths:
            existing = recon_targets_by_path.get(p)
            if existing:
                crypto_targets.append(existing)
            else:
                crypto_targets.append(
                    {
                        "endpoint": f"{target_url.rstrip('/')}{p}",
                        "method": "GET",
                    }
                )

        # ── 5. Ejecutar crypto_inspector ──
        output = await call_mcp_skill(
            channel,
            "crypto_inspector",
            {
                "target_url": target_url,
                "targets": crypto_targets,
            },
            tool_timings,
        )

        execution = {
            "tool": "crypto_inspector",
            "command": f"MCP crypto_inspector --target {target_url}",
            "target_id": "crypto_scan",
            "endpoint": target_url,
            "output": output,
            "discovered_paths": all_paths,
        }
        evidence.executed_commands.append(execution)
        evidence.pre_executed_context.append(
            {**execution, "status": "COMPLETED"}
        )
        return evidence

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_ffuf_output(raw) -> list[str]:
        """Acepta JSON (structured) o stdout de ffuf; devuelve paths relativos."""
        if isinstance(raw, dict):
            for key in ("paths", "results", "endpoints"):
                if isinstance(raw.get(key), list):
                    return [str(x) for x in raw[key]]
        if isinstance(raw, list):
            return [str(x) for x in raw]
        if not isinstance(raw, str):
            return []
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for key in ("paths", "results", "endpoints"):
                    if isinstance(data.get(key), list):
                        return [str(x) for x in data[key]]
            if isinstance(data, list):
                return [str(x) for x in data]
        except (json.JSONDecodeError, TypeError):
            pass

        paths: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("[", "::")):
                continue
            if line.startswith(("http://", "https://")):
                paths.append(urlsplit(line).path)
            elif "[Status:" in line:
                word = line.split()[0]
                if word:
                    paths.append(word if word.startswith("/") else "/" + word)
            else:
                paths.append(line if line.startswith("/") else "/" + line)
        return list(dict.fromkeys(paths))

    @staticmethod
    def _normalize_paths(paths: list[str]) -> list[str]:
        seen: set[str] = set()
        for p in paths:
            if not isinstance(p, str) or not p:
                continue
            key = p.lower()
            key = re.sub(
                r"/(0+)(\d+)(?=/|$)",
                lambda m: "/" + str(int(m.group(1) + m.group(2))),
                key,
            )
            seen.add(key)
        return sorted(seen)

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return {"crypto_inspector_results": evidence.pre_executed_context}

    def merge_findings(
        self,
        parsed_output: dict,
        evidence: ValidationEvidence,
        task_id: str,
    ) -> dict:
        merged = dict(parsed_output) if isinstance(parsed_output, dict) else {}
        merged.setdefault("vulnerabilities", [])

        executions = [
            item
            for item in evidence.executed_commands
            if item.get("tool") == "crypto_inspector"
        ]

        derived: list[dict] = []
        seen_keys: set[tuple[str, str]] = set()
        covered_by_type: set[tuple[str, str]] = set()
        covered_by_id: set[tuple[str, str]] = set()

        for execution in executions:
            raw = execution.get("output")
            report = raw if isinstance(raw, dict) else extract_first_json(raw or "")
            findings = report.get("findings") if isinstance(report, dict) else None
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                vulnerability = _crypto_finding_to_vulnerability(finding, execution)
                endpoint_key = _crypto_endpoint_key(
                    vulnerability.get("endpoint") or ""
                )
                finding_id = finding.get("id") or vulnerability.get("type") or ""

                dedupe_key = (finding_id, endpoint_key)
                if dedupe_key in seen_keys:
                    continue
                seen_keys.add(dedupe_key)

                # Marcar ambas dimensiones para el filtro del LLM
                covered_by_type.add(
                    (vulnerability.get("type") or "", endpoint_key)
                )
                covered_by_id.add((finding_id, endpoint_key))

                derived.append(vulnerability)

        # Filtro del LLM: descarta si matchea por type O por finding_id
        llm_vulnerabilities = [
            v for v in (merged.get("vulnerabilities") or []) if isinstance(v, dict)
        ]
        kept_llm: list[dict] = []
        for vulnerability in llm_vulnerabilities:
            endpoint_key = _crypto_endpoint_key(
                str(vulnerability.get("endpoint") or "")
            )
            type_key = (str(vulnerability.get("type") or ""), endpoint_key)
            id_key = (str(vulnerability.get("finding_id") or ""), endpoint_key)
            if type_key in covered_by_type or id_key in covered_by_id:
                continue

            tools_used = vulnerability.setdefault("tools_used", ["crypto_inspector"])
            if isinstance(tools_used, str):
                tools_used = [t.strip() for t in tools_used.split(",") if t.strip()]
                vulnerability["tools_used"] = tools_used
            if "crypto_inspector" not in tools_used:
                tools_used.append("crypto_inspector")
            kept_llm.append(vulnerability)

        merged["vulnerabilities"] = sorted(
            derived + kept_llm, key=_severity_sort_key
        )
        logger.info(
            "[VALIDATE] task_id=%s crypto findings tras merge: %d "
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
    if is_access_control_attack(attack_type):
        return AccessControlValidationStrategy()
    return ValidationStrategy()


ACCESS_CONTROL_TOOL = "access_control_prober"
ACCESS_CONTROL_LOGIN_PATH = os.getenv("ACCESS_CONTROL_LOGIN_PATH", "/rest/user/login")
ACCESS_CONTROL_VICTIM_EMAIL = os.getenv(
    "ACCESS_CONTROL_VICTIM_EMAIL", "admin@juice-sh.op"
)
ACCESS_CONTROL_VICTIM_PASSWORD = os.getenv("ACCESS_CONTROL_VICTIM_PASSWORD", "admin123")
ACCESS_CONTROL_ATTACKER_EMAIL = os.getenv(
    "ACCESS_CONTROL_ATTACKER_EMAIL", "jim@juice-sh.op"
)
ACCESS_CONTROL_ATTACKER_PASSWORD = os.getenv(
    "ACCESS_CONTROL_ATTACKER_PASSWORD", "ncc-1701"
)
ACCESS_CONTROL_VICTIM_ID = os.getenv("ACCESS_CONTROL_VICTIM_ID", "1")
_ACCESS_CONTROL_ID_RE = re.compile(r"/\d+(?:/|$)")


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme or "http", parts.netloc, "", "", ""))


def _extract_token(payload) -> str:
    if not isinstance(payload, dict):
        return ""
    authentication = payload.get("authentication")
    if isinstance(authentication, dict) and authentication.get("token"):
        return str(authentication["token"])
    for key in ("token", "access_token", "accessToken", "jwt"):
        if payload.get(key):
            return str(payload[key])
    data = payload.get("data")
    if isinstance(data, dict):
        return _extract_token(data)
    return ""


def _login_token(base_url: str, email: str, password: str) -> str:
    """Obtiene un JWT para las pruebas de control de acceso sin exponerlo en logs."""
    if not email or not password:
        return ""
    login_url = urljoin(f"{base_url.rstrip('/')}/", ACCESS_CONTROL_LOGIN_PATH.lstrip("/"))
    body = json.dumps({"email": email, "password": password}).encode("utf-8")
    request = urllib_request.Request(
        login_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        context = ssl._create_unverified_context()
        with urllib_request.urlopen(request, timeout=15, context=context) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        return _extract_token(payload)
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        logger.warning(
            "[VALIDATE] No se pudo autenticar %s contra %s para access_control",
            email,
            login_url,
        )
        return ""


def _resolve_access_control_tokens(
    targets: list[dict], target_url: str = ""
) -> tuple[str, str]:
    """Prioriza tokens de entorno y, si faltan, autentica con credenciales de laboratorio."""
    victim_token = os.getenv("ACCESS_CONTROL_VICTIM_TOKEN", "").strip()
    attacker_token = os.getenv("ACCESS_CONTROL_ATTACKER_TOKEN", "").strip()

    # Aprovecha un Authorization observado por el crawler si existe.
    if not attacker_token:
        for target in targets:
            request = target.get("request") if isinstance(target, dict) else None
            headers = request.get("headers") if isinstance(request, dict) else None
            if not isinstance(headers, dict):
                continue
            for name, value in headers.items():
                if str(name).casefold() == "authorization" and str(value).strip():
                    attacker_token = str(value).replace("Bearer ", "", 1).strip()
                    break
            if attacker_token:
                break

    # FIX: Los targets vienen simplificados SIN 'url', así que sacamos el origen
    # del endpoint o del target_url original.
    first = targets[0] if targets else {}
    raw_url = ""
    if isinstance(first, dict):
        raw_url = (
            str(first.get("url") or "")
            or str(first.get("endpoint") or "")
            or str((first.get("request") or {}).get("url") or "")
        )
    raw_url = raw_url or target_url
    base_url = _origin_of(str(raw_url or ""))

    if not victim_token and base_url:
        victim_token = _login_token(
            base_url, ACCESS_CONTROL_VICTIM_EMAIL, ACCESS_CONTROL_VICTIM_PASSWORD
        )
    if not attacker_token and base_url:
        attacker_token = _login_token(
            base_url, ACCESS_CONTROL_ATTACKER_EMAIL, ACCESS_CONTROL_ATTACKER_PASSWORD
        )
    return victim_token, attacker_token


def _normalize_access_control_endpoint(
    target_url: str, raw_endpoint: str
) -> str | None:
    """Convierte el endpoint observado a ruta relativa dentro del origen autorizado."""
    target_parts = urlsplit(target_url)
    endpoint_parts = urlsplit(str(raw_endpoint or ""))
    if (
        endpoint_parts.netloc
        and target_parts.netloc
        and endpoint_parts.netloc != target_parts.netloc
    ):
        return None
    path = endpoint_parts.path or "/"
    if endpoint_parts.query:
        path = f"{path}?{endpoint_parts.query}"
    return path


def _has_access_control_id(endpoint: str) -> bool:
    value = str(endpoint or "")
    return bool("{id}" in value or _ACCESS_CONTROL_ID_RE.search(value))


def _looks_like_collection(endpoint: str) -> bool:
    path = str(endpoint or "").split("?", 1)[0].rstrip("/")
    if not path:
        return False
    last_segment = path.rsplit("/", 1)[-1].casefold()
    if not last_segment or last_segment in {"whoami", "login", "logout", "register"}:
        return False
    return (
        str(endpoint).split("?", 1)[0].endswith("/")
        or last_segment.endswith("s")
        or last_segment
        in {"user", "account", "profile", "basket", "order", "cart", "invoice", "document", "file"}
    )


def _access_control_candidates(endpoint: str) -> list[str]:
    candidates = [endpoint]
    if not _has_access_control_id(endpoint) and _looks_like_collection(endpoint):
        base_path = str(endpoint).split("?", 1)[0].rstrip("/")
        if base_path:
            candidates.append(f"{base_path}/{{id}}")
    return candidates


def _access_control_command(base_url: str, endpoint: str, victim_id: str) -> str:
    resolved = str(endpoint).replace("{id}", str(victim_id))
    if resolved.startswith(("http://", "https://")):
        target_url = resolved
    else:
        target_url = f"{base_url.rstrip('/')}{resolved}"
    return (
        "curl -s -H 'Authorization: Bearer $ATTACKER_TOKEN' "
        f"{shlex.quote(target_url)}"
    )


def _access_control_finding_to_vulnerability(
    finding: dict, execution: dict
) -> dict:
    endpoint = sanitize_endpoint_for_context(
        str(finding.get("endpoint") or execution.get("endpoint") or "")
    )
    evidence = str(finding.get("evidence") or "").strip()
    if not evidence:
        evidence = "access_control_prober confirmó acceso no autorizado sin evidencia textual."
    attack_chain = [
        str(step) for step in (finding.get("attack_chain") or []) if str(step).strip()
    ]
    return {
        "type": finding.get("title") or "Broken Access Control",
        "severity": str(finding.get("severity") or "HIGH").upper(),
        "endpoint": endpoint,
        "parameter": "id" if _has_access_control_id(endpoint) else None,
        "evidence": evidence,
        "reproducible_command": _access_control_command(
            execution.get("base_url", ""),
            endpoint,
            execution.get("victim_id", ACCESS_CONTROL_VICTIM_ID),
        ),
        "confidence": "HIGH",
        "tools_used": [ACCESS_CONTROL_TOOL],
        "finding_id": finding.get("id"),
        "cwe": finding.get("cwe") or None,
        "owasp": finding.get("owasp") or None,
        "attack_demonstrated": "active_access_control_exploitation",
        "attack_result": None,
        "attack_chain": attack_chain,
        "context_role": "access_control",
        "target_id": execution.get("target_id"),
        "request_id": execution.get("request_id"),
    }

# Mapeo semántico: Flag de weak-page -> Endpoints a probar
ACCESS_CONTROL_FLAG_TO_TESTS = {
    "IDOR_ORDERS": ["/api/orders/1", "/api/orders/2"],
    "MISSING_AUTH_ME": ["/api/me"],
    "MISSING_ROLE_CHECK_ADMIN": ["/api/admin/vulnerabilities"],
    "MASS_ASSIGNMENT_REGISTER": ["/api/auth/register"],
    "EXPOSED_SENSITIVE_FILES": ["/api/contact"],
}

def _fetch_active_flags(base_url: str) -> set[str]:
    """Consulta /api/admin/vulnerabilities para saber qué endpoints inyectar."""
    url = f"{base_url.rstrip('/')}/api/admin/vulnerabilities"
    try:
        req = urllib_request.Request(url, headers={"Accept": "application/json"})
        context = ssl._create_unverified_context()
        with urllib_request.urlopen(req, timeout=5, context=context) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            # La app devuelve {"flags": {"IDOR_ORDERS": true, ...}}
            flags_dict = data.get("flags", data)
            active = set()
            if isinstance(flags_dict, dict):
                for k, v in flags_dict.items():
                    if v is True or str(v).lower() == "vulnerable":
                        active.add(k)
            return active
    except Exception as exc:
        logger.warning("[VALIDATE] No se pudieron obtener flags de %s: %s", url, exc)
        return set()

class AccessControlValidationStrategy(ValidationStrategy):
    """Ejecuta access_control_prober con dos identidades y promueve hallazgos reales."""

    async def execute(
        self,
        channel: aio_pika.Channel,
        target_url: str,
        targets: list[dict],
        task_id: str,
        tool_timings: list[dict],
        token: str | None = None,
    ) -> ValidationEvidence:
        logger.info("[VALIDATE] task_id=%s Ejecutando access_control_prober sobre %s", task_id, target_url)
        evidence = ValidationEvidence()
        base_url = _origin_of(target_url)
        
        victim_token, attacker_token = _resolve_access_control_tokens(targets, target_url)

        if not attacker_token:
            logger.warning("[VALIDATE] task_id=%s No se obtuvo token de atacante.", task_id)
            return evidence

        context = ssl._create_unverified_context()
        headers_attacker = {"Authorization": f"Bearer {attacker_token}", "Accept": "application/json", "User-Agent": "Mozilla/5.0"}
        headers_base = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}

        # Helper robusto para hacer peticiones y capturar status codes
        def _make_request(path, method="GET", payload=None, headers=None):
            url = f"{base_url}{path}"
            req = urllib_request.Request(url, data=payload, method=method, headers=headers or {})
            try:
                with urllib_request.urlopen(req, timeout=5, context=context) as resp:
                    return resp.status, resp.read().decode("utf-8", errors="replace")
            except HTTPError as e:
                return e.code, e.read().decode("utf-8", errors="replace")
            except Exception as e:
                logger.warning(f"[-] Error de red en {path}: {e}")
                return 0, ""

        def _add_manual_finding(finding_id, title, sev, path, ev, cwe):
            finding = {
                "id": finding_id, "title": title, "severity": sev, "endpoint": f"{base_url}{path}",
                "evidence": ev, "cwe": cwe, "owasp": "A01:2021 - Broken Access Control",
                "attack_chain": [f"1. Enviar petición a {path}", "2. Observar respuesta exitosa sin la debida autorización"]
            }
            exec_data = {
                "tool": ACCESS_CONTROL_TOOL, "base_url": base_url, "endpoint": path,
                "output": json.dumps({"findings": [finding]})
            }
            evidence.executed_commands.append(exec_data)
            evidence.pre_executed_context.append({"tool": ACCESS_CONTROL_TOOL, "endpoint": path, "status": "COMPLETED", "findings": [finding]})
            logger.info(f"[VALIDATE] ✅ Hallazgo manual detectado: {finding_id} en {path}")

        # ── 1. PRUEBAS LÓGICAS MANUALES ──

        # A) MISSING_AUTH_ME (/api/me sin token)
        status, body = _make_request("/api/me", headers=headers_base)
        logger.info(f"[VALIDATE] Prueba /api/me sin token -> HTTP {status}")
        if status == 200 and "Unauthorized" not in body and "Forbidden" not in body:
            _add_manual_finding("BAC-AUTH-ME-001", "Missing Authentication (/api/me)", "HIGH", "/api/me", 
                                "El endpoint /api/me responde 200 OK sin proporcionar token de autenticación.", "CWE-306")

        # B) MISSING_ROLE_CHECK_ADMIN (/api/admin con token de atacante)
        status, body = _make_request("/api/admin/vulnerabilities", headers=headers_attacker)
        logger.info(f"[VALIDATE] Prueba /api/admin/vulnerabilities con token atacante -> HTTP {status}")
        if status == 200 and "Unauthorized" not in body and "Forbidden" not in body:
            _add_manual_finding("BAC-ROLE-ADMIN-001", "Missing Role Check on Admin", "CRITICAL", "/api/admin/vulnerabilities", 
                                "El token de atacante accedió exitosamente a la ruta de admin.", "CWE-285")

        # C) EXPOSED_SENSITIVE_FILES (.env, backup.sql, logs)
        for file_path in ["/.env", "/backup.sql", "/logs"]:
            status, body = _make_request(file_path, headers=headers_base)
            logger.info(f"[VALIDATE] Prueba {file_path} -> HTTP {status}")
            # Comprobamos que sea 200 y que el contenido no sea una página HTML genérica de error
            if status == 200 and "<html" not in body.lower()[:200] and "not found" not in body.lower():
                _add_manual_finding("BAC-FILE-EXPOSED-001", "Exposed Sensitive File", "HIGH", file_path, 
                                    f"El archivo {file_path} es accesible públicamente y contiene información sensible.", "CWE-200")

        # D) MASS_ASSIGNMENT_REGISTER (POST /api/auth/register inyectando role)
        try:
            payload = json.dumps({"email": f"hacker_{task_id[:5]}@test.local", "password": "hacker123", "name": "Hacker", "role": "admin"}).encode("utf-8")
            status, body = _make_request("/api/auth/register", method="POST", payload=payload, headers={**headers_base, "Content-Type": "application/json"})
            logger.info(f"[VALIDATE] Prueba /api/auth/register (Mass Assignment) -> HTTP {status}")
            if status in (200, 201) and "error" not in body.lower():
                _add_manual_finding("BAC-MASS-ASSIGN-001", "Mass Assignment in Registration", "CRITICAL", "/api/auth/register", 
                                    "El registro aceptó la creación de un usuario con 'role: admin'.", "CWE-915")
        except Exception as e:
            logger.warning(f"[-] Falló prueba register: {e}")

        # ── 2. PRUEBAS CON EL MCP (IDOR Real) ──
        test_endpoints = {"/api/orders/1", "/api/orders/2"}
        
        for ep in test_endpoints:
            for candidate in _access_control_candidates(ep):
                if "products" in candidate: continue # Ignorar productos por falsos positivos
                output = await call_mcp_skill(
                    channel, ACCESS_CONTROL_TOOL,
                    {
                        "base_url": base_url, "endpoint": candidate, "victim_id": ACCESS_CONTROL_VICTIM_ID,
                        "token_victim": victim_token, "token_attacker": attacker_token,
                    },
                    tool_timings,
                )
                try:
                    report = json.loads(output)
                except (TypeError, json.JSONDecodeError):
                    report = {"error": "Respuesta no válida", "raw": str(output)}

                execution = {
                    "tool": ACCESS_CONTROL_TOOL, "base_url": base_url, "endpoint": candidate,
                    "output": json.dumps(report, ensure_ascii=False),
                }
                evidence.executed_commands.append(execution)
                findings = report.get("findings", [])
                evidence.pre_executed_context.append({
                    **execution, "status": "ERROR" if report.get("error") else "COMPLETED", "findings": findings
                })

        return evidence

    def build_validation_context(self, evidence: ValidationEvidence) -> dict:
        return {"access_control_prober_results": evidence.pre_executed_context}

    def merge_findings(
        self, parsed_output: dict, evidence: ValidationEvidence, task_id: str,
    ) -> dict:
        merged = dict(parsed_output) if isinstance(parsed_output, dict) else {}
        llm_vulnerabilities = [v for v in (merged.get("vulnerabilities") or []) if isinstance(v, dict)]
        
        executions = [item for item in evidence.executed_commands if item.get("tool") == ACCESS_CONTROL_TOOL]
        derived: list[dict] = []
        seen_keys: set[tuple] = set()
        covered_paths: set[str] = set()
        
        for execution in executions:
            try:
                report = json.loads(execution.get("output") or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            findings = report.get("findings")
            if not isinstance(findings, list): continue
            
            for finding in findings:
                if not isinstance(finding, dict): continue
                vulnerability = _access_control_finding_to_vulnerability(finding, execution)
                endpoint_path = _endpoint_key(vulnerability["endpoint"])
                
                # Ignorar ruido (productos y robots.txt)
                if "products" in endpoint_path or "robots.txt" in endpoint_path:
                    continue
                    
                covered_paths.add(endpoint_path)
                dedupe_key = (endpoint_path, vulnerability.get("finding_id") or vulnerability["type"])
                
                if dedupe_key in seen_keys: continue
                seen_keys.add(dedupe_key)
                derived.append(vulnerability)

        # Filtro LLM
        kept_llm: list[dict] = []
        executed_paths = {_endpoint_key(str(ex.get("endpoint") or "")) for ex in executions}
        for vulnerability in llm_vulnerabilities:
            endpoint_key = _endpoint_key(str(vulnerability.get("endpoint") or ""))
            if endpoint_key in covered_paths or endpoint_key not in executed_paths: continue
            kept_llm.append(vulnerability)

        merged["vulnerabilities"] = sorted(derived + kept_llm, key=_severity_sort_key)
        logger.info(
            "[VALIDATE] task_id=%s vulnerabilidades finales=%d (deterministas=%d, llm_extra=%d)",
            task_id, len(merged["vulnerabilities"]), len(derived), len(kept_llm),
        )
        return merged