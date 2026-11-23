import json
import unittest
from unittest.mock import AsyncMock, patch

from langchain_core.messages import AIMessage

from contract_schemas import ReporterInput
from helpers import build_reporter_context, report_has_non_spanish_narrative
from main import process_report_task


def make_payload(vulnerabilities=None):
    target = "https://example.test"
    return {
        "task_id": "test-task",
        "target_url": target,
        "attack_type": "xss",
        "recon_data": {
            "recon_summary": {
                "target_url": target,
                "attack_type_filter": "xss",
                "total_targets_identified": 0,
            },
            "high_priority_targets": [],
        },
        "validation_data": {
            "target_url": target,
            "vulnerabilities": vulnerabilities or [],
        },
    }


SPANISH_REPORT = (
    "# Informe de auditoría\n\n"
    "## Resumen Ejecutivo\n\n"
    "No se confirmaron vulnerabilidades durante esta auditoría.\n\n"
    "## Conclusiones y próximos pasos\n\n"
    "Revise los resultados antes de realizar nuevas pruebas autorizadas."
)
ENGLISH_REPORT = (
    "# Security audit report\n\n"
    "## Executive Summary\n\n"
    "The application was tested and the security assessment found no confirmed vulnerabilities.\n\n"
    "## Recommendations\n\n"
    "The security team should review the results and monitor the application."
)


class ReportLanguageTests(unittest.TestCase):
    def test_detects_english_paragraph_in_spanish_report(self):
        reporter_input = ReporterInput.model_validate(make_payload())
        text = SPANISH_REPORT + (
            "\n\nThe application exposes sensitive information and the team should fix the issue."
        )
        self.assertTrue(report_has_non_spanish_narrative(text, reporter_input))

    def test_detects_short_english_sentence_and_heading(self):
        reporter_input = ReporterInput.model_validate(make_payload())
        self.assertTrue(report_has_non_spanish_narrative(
            "## Resumen Ejecutivo\n\nThe vulnerability allows unauthorized access.",
            reporter_input,
        ))
        self.assertTrue(report_has_non_spanish_narrative(
            "## Overview\n\nNo se confirmaron vulnerabilidades.",
            reporter_input,
        ))
        self.assertTrue(report_has_non_spanish_narrative(
            "## 1. Executive Summary\n\nNo se confirmaron vulnerabilidades.",
            reporter_input,
        ))
        self.assertTrue(report_has_non_spanish_narrative(
            "## Resumen Ejecutivo\n\nThe application was vulnerable.",
            reporter_input,
        ))

    def test_ignores_original_technical_evidence_and_code(self):
        finding = {
            "type": "Stored Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "endpoint": "https://example.test/search",
            "evidence": "The browser observed execution of the synthetic proof in the page.",
            "reproducible_command": "echo 'the application is vulnerable to this attack'",
            "confidence": "HIGH",
            "tools_used": ["browserXssValidator"],
            "attack_chain": ["The attacker sends a request to the endpoint."],
        }
        reporter_input = ReporterInput.model_validate(make_payload([finding]))
        text = (
            "## Resumen Ejecutivo\n\n"
            "Se confirmó un hallazgo en la aplicación auditada.\n\n"
            "### Stored Cross-Site Scripting (XSS)\n\n"
            "Evidencia original: The browser observed execution of the synthetic proof in the page.\n\n"
            "The attacker sends a request to the endpoint.\n\n"
            "```bash\necho 'the application is vulnerable to this attack'\n```"
        )
        self.assertFalse(report_has_non_spanish_narrative(text, reporter_input))

    def test_detects_chinese_headings_and_prose_but_preserves_original_data(self):
        data = make_payload([{
            "type": "XSS", "severity": "HIGH",
            "endpoint": "https://example.test/search",
            "evidence": "原始证据", "reproducible_command": "echo 原始证据",
            "confidence": "HIGH", "attack_chain": ["原始攻击步骤"],
        }])
        data["validation_data"]["unconfirmed_findings"] = [
            {"details": {"reason": "原始工具结果"}}
        ]
        reporter_input = ReporterInput.model_validate(data)
        self.assertTrue(report_has_non_spanish_narrative("## 审计报告\n\n发现安全漏洞。", reporter_input))
        self.assertTrue(report_has_non_spanish_narrative("```markdown\n## 审计报告\n```", reporter_input))
        self.assertTrue(report_has_non_spanish_narrative(SPANISH_REPORT + "\n\n建议立即修复。", reporter_input))
        self.assertFalse(report_has_non_spanish_narrative(
            SPANISH_REPORT + "\n\nEvidencia original: 原始证据\n\n"
            "原始攻击步骤\n\n原始工具结果\n\n```bash\necho 中文\n```",
            reporter_input,
        ))

    def test_context_includes_observed_method_and_verification_steps(self):
        finding = {
            "type": "XSS",
            "severity": "HIGH",
            "endpoint": "https://example.test/search",
            "method": "GET",
            "evidence": "Evidencia observada.",
            "verification_steps": "Verificación registrada.",
            "reproducible_command": "test-command",
            "confidence": "HIGH",
        }
        context = json.loads(build_reporter_context(
            ReporterInput.model_validate(make_payload([finding]))
        ))
        result = context["validation_summary"]["findings"][0]
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["verification_steps"], "Verificación registrada.")


class ReporterLanguageFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_chinese_report_is_retried_and_falls_back_if_still_chinese(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="## 审计报告\n\n建议立即修复。")
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertTrue(fallback)
        self.assertEqual(llm.ainvoke.await_count, 2)
        self.assertIn("Informe de respaldo", report)
        self.assertNotIn("审计报告", report)

    async def test_chinese_report_can_be_corrected(self):
        llm = AsyncMock()
        llm.ainvoke.side_effect = [
            AIMessage(content="## 审计报告\n\n建议立即修复。"),
            AIMessage(content=SPANISH_REPORT),
        ]
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertFalse(fallback)
        self.assertEqual(report, SPANISH_REPORT)
        self.assertEqual(llm.ainvoke.await_count, 2)

    async def test_invalid_contract_does_not_claim_there_were_no_findings(self):
        data = make_payload()
        data["validation_data"]["vulnerabilities"] = [{"type": "incomplete"}]
        report, fallback = await process_report_task(data)
        self.assertTrue(fallback)
        self.assertIn("No es posible determinar los hallazgos", report)
        self.assertNotIn("No se confirmaron vulnerabilidades", report)

    async def test_spanish_report_succeeds_without_retry(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content=SPANISH_REPORT)
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertFalse(fallback)
        self.assertEqual(report, SPANISH_REPORT)
        self.assertEqual(llm.ainvoke.await_count, 1)
        self.assertIn("español", llm.ainvoke.await_args.args[0][0].content.casefold())

    async def test_english_report_is_retried_in_spanish(self):
        llm = AsyncMock()
        llm.ainvoke.side_effect = [
            AIMessage(content=ENGLISH_REPORT),
            AIMessage(content=SPANISH_REPORT),
        ]
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertEqual(report, SPANISH_REPORT)
        self.assertFalse(fallback)
        self.assertEqual(llm.ainvoke.await_count, 2)

    async def test_repeated_english_report_returns_explicit_spanish_fallback(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content=ENGLISH_REPORT)
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertTrue(fallback)
        self.assertEqual(llm.ainvoke.await_count, 2)
        self.assertIn("Informe de respaldo", report)
        self.assertIn("español", report)
        self.assertNotIn("Executive Summary", report)

    async def test_empty_response_uses_fallback_instead_of_success(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content="")
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload())
        self.assertTrue(fallback)
        self.assertIn("Informe de respaldo", report)

    async def test_fallback_preserves_findings_and_original_technical_data(self):
        finding = {
            "type": "Stored Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "endpoint": "https://example.test/search",
            "evidence": "The browser observed execution of the synthetic proof.",
            "reproducible_command": "echo original-command",
            "confidence": "HIGH",
            "attack_chain": ["The attacker sends a request to the endpoint."],
        }
        llm = AsyncMock()
        llm.ainvoke.return_value = AIMessage(content=ENGLISH_REPORT)
        with patch("main.get_llm", return_value=llm):
            report, fallback = await process_report_task(make_payload([finding]))
        self.assertTrue(fallback)
        for value in (
            finding["type"], finding["severity"], finding["endpoint"],
            finding["evidence"], finding["reproducible_command"], finding["attack_chain"][0],
        ):
            self.assertIn(value, report)


if __name__ == "__main__":
    unittest.main()
