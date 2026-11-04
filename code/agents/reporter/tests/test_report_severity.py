import json
import unittest
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from contract_schemas import ReporterInput
from helpers import (
    _severity_of,
    build_fallback_markdown_report,
    build_report_metrics,
    build_reporter_context,
    finalize_report_markdown,
)
from main import process_report_task
from test_report_language import make_payload


def finding(severity):
    return {
        "type": f"Hallazgo {severity}",
        "severity": severity,
        "endpoint": f"https://example.test/{severity.lower()}",
        "evidence": f"Evidencia {severity}",
        "reproducible_command": "test-command",
        "confidence": "HIGH",
        "tools_used": ["test-tool"],
    }


class ReporterSeverityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.payload = make_payload([
            finding("INFO"), finding("LOW"), finding("CRITICAL"),
            finding("MEDIUM"), finding("HIGH"),
        ])
        self.reporter_input = ReporterInput.model_validate(self.payload)

    def test_metrics_and_context_use_three_categories_and_keep_information_separate(self):
        original = self.reporter_input.model_dump()
        metrics = build_report_metrics(self.reporter_input)
        self.assertEqual(metrics["total_findings"], 4)
        self.assertEqual(metrics["severity_summary"], {"HIGH": 2, "MEDIUM": 1, "LOW": 1})
        self.assertEqual(metrics["informational_count"], 1)
        self.assertEqual(
            metrics["by_tool"]["test-tool"],
            {"total": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
        )
        context = json.loads(build_reporter_context(self.reporter_input))["validation_summary"]
        self.assertEqual(context["findings_order"], ["HIGH", "MEDIUM", "LOW"])
        self.assertEqual(
            [item["severity"] for item in context["findings"]],
            ["HIGH", "HIGH", "MEDIUM", "LOW"],
        )
        self.assertEqual(context["informational_count"], 1)
        self.assertEqual(context["informational_findings"][0]["type"], "Hallazgo INFO")
        self.assertEqual(context["informational_findings"][0]["severity"], None)
        self.assertEqual(self.reporter_input.model_dump(), original)

    def test_fallback_keeps_info_separate_and_counts_critical_as_high(self):
        report = build_fallback_markdown_report(self.reporter_input, "Error de prueba")
        self.assertIn("**Hallazgos confirmados:** 4", report)
        self.assertIn("HIGH: 2, MEDIUM: 1, LOW: 1", report)
        self.assertIn("**Hallazgos informativos:** 1", report)
        self.assertIn("[HIGH] Hallazgo CRITICAL", report)
        self.assertIn("## Hallazgos informativos", report)
        self.assertIn("[Informativo] Hallazgo INFO", report)
        self.assertNotIn("[INFO]", report)
        self.assertNotIn("[CRITICAL]", report)

    async def test_report_flow_preserves_informational_and_severity_order(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="## Resumen Ejecutivo\n\nResumen de la auditoría.")
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(self.payload)
        self.assertFalse(fallback)
        self.assertIn("[HIGH] Hallazgo CRITICAL", report)
        self.assertIn("[Informativo] Hallazgo INFO", report)
        self.assertLess(report.index("[HIGH]"), report.index("[MEDIUM]"))
        self.assertLess(report.index("[MEDIUM]"), report.index("[LOW]"))
        prompt = llm.ainvoke.await_args.args[0][0].content
        self.assertIn("HIGH → MEDIUM → LOW", prompt)
        self.assertNotIn("CRITICAL →", prompt)

    def test_only_info_produces_no_confirmed_vulnerabilities(self):
        info = finding("INFO")
        info["tools_used"] = ["access_control_prober"]
        reporter_input = ReporterInput.model_validate(make_payload([info]))
        report = build_fallback_markdown_report(reporter_input, "Error de prueba")
        self.assertIn("**Hallazgos confirmados:** 0", report)
        self.assertIn("No se confirmaron vulnerabilidades", report)
        self.assertIn("[Informativo] Hallazgo INFO", report)
        self.assertNotIn("Confirmación activa", report)
        context = json.loads(build_reporter_context(reporter_input))["validation_summary"]
        self.assertEqual(context["source_tools"], ["access_control_prober"])
        self.assertFalse(context["informational_findings"][0]["active_confirmation"])

    def test_empty_input_and_invalid_severity(self):
        reporter_input = ReporterInput.model_validate(make_payload([]))
        metrics = build_report_metrics(reporter_input)
        self.assertEqual(metrics["severity_summary"], {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
        report = finalize_report_markdown("# Informe\n\n## Conclusiones\n\nSin hallazgos.", reporter_input)
        self.assertIn("**Hallazgos confirmados:** 0", report)
        with self.assertRaises(ValueError):
            _severity_of(type("Finding", (), {"severity": "UNEXPECTED"})())

    async def test_llm_failure_preserves_both_kinds_of_findings(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="")
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(self.payload)
        self.assertTrue(fallback)
        self.assertIn("[HIGH] Hallazgo CRITICAL", report)
        self.assertIn("[Informativo] Hallazgo INFO", report)


if __name__ == "__main__":
    unittest.main()
