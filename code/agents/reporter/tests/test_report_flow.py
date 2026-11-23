import json
import unittest
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from contract_schemas import ReporterInput
from helpers import build_fallback_markdown_report, build_reporter_context, finalize_report_markdown
from main import process_report_task
from validate.output_guard import guard_validate_output


def finding(kind, endpoint, method, parameter, evidence):
    return {
        "type": kind,
        "severity": "HIGH",
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "evidence": evidence,
        "reproducible_command": "browserXssValidator --target-url https://example.test --plan",
        "confidence": "HIGH",
        "tools_used": ["browserXssValidator"],
    }


def payload():
    first = (
        "El validador introdujo una prueba sintética en el parámetro q "
        "y Chromium observó su ejecución en el DOM de la página."
    )
    findings = [
        finding("Reflected DOM Cross-Site Scripting (XSS)", "https://example.test/api/products",
                "GET", "q", first + " Prueba enviada: marker-1"),
        finding("Reflected DOM Cross-Site Scripting (XSS)", "https://example.test/api/products",
                "GET", "q", first + " Prueba enviada: marker-2"),
        finding("Stored Cross-Site Scripting (XSS)", "https://example.test/api/contact",
                "POST", "message", "Chromium observó la ejecución del dato almacenado."),
    ]
    guarded, duplicates = guard_validate_output({
        "target_url": "https://example.test",
        "vulnerabilities": findings,
        "unconfirmed_findings": [{
            "reason": "Prueba inconclusa",
            "tools_used": ["browserXssValidator"],
        }] * 4,
    })
    assert duplicates == 1
    return {
        "task_id": "simulated-task",
        "target_url": "https://example.test",
        "attack_type": "xss",
        "validate_used_fallback": True,
        "recon_data": {
            "recon_summary": {
                "target_url": "https://example.test",
                "attack_type_filter": "xss",
                "total_targets_identified": 7,
            },
            "high_priority_targets": [],
        },
        "validation_data": guarded,
    }


class ReportFlowTests(unittest.IsolatedAsyncioTestCase):
    def test_sqli_table_evidence_is_in_context_and_final_markdown(self):
        private_email = "customer@example.test"
        private_password = "plaintext-secret"
        data = payload()
        data["validation_data"]["vulnerabilities"] = [{
            "type": "SQL Injection",
            "severity": "HIGH",
            "endpoint": "https://example.test/api/users",
            "method": "GET",
            "parameter": "id",
            "evidence": "SQLMap confirmed SQL injection.",
            "confidence": "HIGH",
            "tools_used": ["sqli_map"],
            "reproducible_command": "MCP sqli_map --action extract --param id",
            "table_evidence": [{
                "database": "SQLite",
                "table": "users",
                "row_count": 1,
                "truncated": False,
                "columns": ["email", "password"],
                "preview": [[private_email, private_password]],
                "status": "retrieved",
                "values_redacted": False,
            }],
        }]
        reporter_input = ReporterInput.model_validate(data)

        context = json.loads(build_reporter_context(reporter_input))
        table_evidence = context["validation_summary"]["findings"][0]["table_evidence"]
        report = finalize_report_markdown(
            "## Resumen Ejecutivo\n\nSe confirmó SQL Injection.",
            reporter_input,
        )

        self.assertEqual(table_evidence[0]["table"], "users")
        self.assertEqual(table_evidence[0]["preview"], [[private_email, private_password]])
        self.assertIn("## Evidencia tabular SQLMap", report)
        self.assertIn("| email | password |", report)
        self.assertIn(
            f"| {private_email} | {private_password} |",
            report,
        )

    def test_sqli_report_contains_five_evidence_rows(self):
        data = payload()
        finding = data["validation_data"]["vulnerabilities"][0]
        finding["type"] = "SQL Injection"
        finding["table_evidence"] = [{
            "table": "users",
            "row_count": 5,
            "columns": ["email"],
            "preview": [[f"user{i}@example.test"] for i in range(1, 6)],
        }]
        reporter_input = ReporterInput.model_validate(data)
        context = json.loads(build_reporter_context(reporter_input))
        tables = next(
            item["table_evidence"]
            for item in context["validation_summary"]["findings"]
            if item["type"] == "SQL Injection"
        )
        report = finalize_report_markdown("## Resumen", reporter_input)

        self.assertEqual(len(tables[0]["preview"]), 5)
        self.assertIn("| user5@example.test |", report)
        self.assertIn("hasta cinco filas", report)

    async def test_reporter_receives_deduplicated_findings_and_builds_clear_fallback(self):
        data = payload()
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="")
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(data)

        self.assertTrue(fallback)
        self.assertEqual(len(data["validation_data"]["vulnerabilities"]), 2)
        self.assertIn("**Hallazgos confirmados:** 2", report)
        self.assertIn("**Pruebas sin confirmación:** 4", report)
        self.assertIn("browserxssvalidator", report)
        self.assertNotIn("crypto_inspector", report)
        self.assertNotIn("access_control_prober", report)
        self.assertIn("A05:2025", report)
        self.assertIn("CWE-79", report)
        self.assertIn("Mitigación orientativa", report)
        self.assertIn("clasificación orientativa", report.casefold())
        self.assertIn("marker-1", report)
        self.assertIn("marker-2", report)
        self.assertEqual(report.count("El validador introdujo una prueba sintética"), 1)
        self.assertIn("no es un comando reproducible", report.casefold())

    async def test_prompt_requests_evidence_based_analysis_and_partial_coverage(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="## Resumen Ejecutivo\n\nResumen de la auditoría.")
        with patch("main.get_llm", return_value=llm):
            await process_report_task(payload())
        messages = llm.ainvoke.await_args.args[0]
        prompt = messages[0].content
        self.assertIn("Distingue observaciones de hipótesis", prompt)
        self.assertIn("mitigación técnica concreta", prompt)
        self.assertIn("contexto es parcial", prompt)
        context = json.loads(messages[1].content.split("```json\n", 1)[1].rsplit("\n```", 1)[0])
        self.assertEqual(context["validation_summary"]["unconfirmed_count"], 4)

    def test_classification_is_derived_and_does_not_replace_original(self):
        data = payload()
        data["validation_data"]["vulnerabilities"][0]["cwe"] = "CWE-123"
        data["validation_data"]["vulnerabilities"][0]["owasp"] = "Referencia original"
        reporter_input = ReporterInput.model_validate(data)
        context = json.loads(build_reporter_context(reporter_input))
        findings = context["validation_summary"]["findings"]
        original = next(item for item in findings if item["cwe"] == "CWE-123")
        self.assertEqual(original["owasp"], "Referencia original")
        self.assertIsNone(original["classification_reference"])
        inferred = next(item for item in findings if item["cwe"] is None)
        self.assertEqual(inferred["classification_reference"]["cwe"], "CWE-79")
        self.assertEqual(inferred["classification_reference"]["owasp"], "A05:2025")
        report = build_fallback_markdown_report(reporter_input, "Error simulado")
        self.assertIn("CWE-123", report)
        self.assertIn("Referencia original", report)
        self.assertIn("A05:2025", report)

    def test_non_xss_has_no_inferred_classification(self):
        data = payload()
        data["validation_data"]["vulnerabilities"] = [
            finding("Otro hallazgo", "https://example.test", "GET", "q", "Evidencia.")
        ]
        context = json.loads(build_reporter_context(ReporterInput.model_validate(data)))
        self.assertIsNone(context["validation_summary"]["findings"][0]["classification_reference"])

    def test_context_reports_tools_actually_used(self):
        context = json.loads(build_reporter_context(ReporterInput.model_validate(payload())))
        validation = context["validation_summary"]
        self.assertEqual(validation["source_tools"], ["browserxssvalidator"])
        self.assertEqual(validation["unconfirmed_findings"][0]["tool"], "browserXssValidator")

    def test_context_keeps_varied_unconfirmed_data_and_marks_limits(self):
        data = payload()
        data["validation_data"]["unconfirmed_findings"] = [
            {"jwt_analysis": {"algorithm": "HS256"}, "attacks_summary": {"failed": 2}},
            {"status": "INCONCLUSIVE", "method": "POST", "reason": "Sin respuesta"},
        ]
        with patch("helpers.REPORTER_MAX_ENDPOINTS", 1):
            context = json.loads(build_reporter_context(ReporterInput.model_validate(data)))
        validation = context["validation_summary"]
        self.assertEqual(validation["unconfirmed_count"], 2)
        self.assertEqual(validation["unconfirmed_included"], 1)
        self.assertEqual(validation["unconfirmed_findings"][0]["jwt_analysis"], {"algorithm": "HS256"})
        self.assertEqual(validation["unconfirmed_findings"][0]["attacks_summary"], {"failed": 2})
        with patch("helpers.REPORTER_MAX_ENDPOINTS", 0):
            context = json.loads(build_reporter_context(ReporterInput.model_validate(data)))
        self.assertEqual(context["validation_summary"]["unconfirmed_included"], 2)

    def test_final_report_completes_missing_evidence_and_command(self):
        data = payload()
        data["validation_data"]["vulnerabilities"] = [data["validation_data"]["vulnerabilities"][0]]
        reporter_input = ReporterInput.model_validate(data)
        item = reporter_input.validation_data.vulnerabilities[0]
        report = finalize_report_markdown(
            f"## Resumen Ejecutivo\n\n{item.type} en {item.endpoint}, parámetro {item.parameter}.",
            reporter_input,
        )
        self.assertIn("marker-1", report)
        self.assertIn(item.reproducible_command, report)
        self.assertIn("no es un comando reproducible", report)

    def test_context_marks_truncated_evidence(self):
        data = payload()
        data["validation_data"]["vulnerabilities"][0]["evidence"] = "A" * 1300
        with patch("helpers.REPORTER_MAX_EVIDENCE_CHARS", 20):
            reporter_input = ReporterInput.model_validate(data)
            context = json.loads(build_reporter_context(reporter_input))
            finding_context = next(
                item for item in context["validation_summary"]["findings"]
                if item["endpoint"] == data["validation_data"]["vulnerabilities"][0]["endpoint"]
            )
            report = build_fallback_markdown_report(reporter_input, "Error")
        self.assertTrue(finding_context["evidence_truncated"])
        self.assertIn("evidencia se muestra truncada", report)

    def test_generated_report_gets_reference_if_model_omits_it(self):
        reporter_input = ReporterInput.model_validate(payload())
        report = finalize_report_markdown("## Resumen Ejecutivo\n\nResumen.", reporter_input)
        self.assertIn("A05:2025", report)
        self.assertIn("CWE-79", report)

    def test_generated_report_warns_about_incomplete_browser_command(self):
        reporter_input = ReporterInput.model_validate(payload())
        command = reporter_input.validation_data.vulnerabilities[0].reproducible_command
        report = finalize_report_markdown(f"## Resumen Ejecutivo\n\n```bash\n{command}\n```", reporter_input)
        self.assertIn("no es un comando reproducible", report)


if __name__ == "__main__":
    unittest.main()
