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
