import json
import unittest

from attack_types import is_xss_attack
from dalfox_output import (
    build_dalfox_validator_context,
    merge_verified_dalfox_findings,
    parse_dalfox_output,
)
from validate_prompts import get_system_prompt


class DalfoxOutputTests(unittest.TestCase):
    def test_parses_dalfox_verified_and_reflected_poc_lines(self):
        raw_output = """
[INFO] Using dictionary: /tmp/dalfox.txt
[POC][V][GET][inHTML-HTML] https://example.test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
[POC][R][GET][inHTML-HTML] https://example.test/search?q=%3Csvg%20onload=alert(1)%3E
"""
        result = parse_dalfox_output(raw_output)

        self.assertEqual(result.status, "FINDINGS")
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].verification, "verified")
        self.assertEqual(result.findings[0].parameter, "q")
        self.assertIn("<script>", result.findings[0].payload)
        self.assertEqual(result.findings[0].context, "inHTML-HTML")
        self.assertEqual(result.findings[1].verification, "reflected")

    def test_strips_terminal_colors_and_deduplicates_repeated_pocs(self):
        result = parse_dalfox_output(
            "\x1b[32m[POC][V][GET][inHTML-HTML] "
            "https://example.test/?search=%3Csvg%3E\x1b[0m\n"
            "[POC][V][GET][inHTML-HTML] "
            "https://example.test/?search=%3Csvg%3E"
        )

        self.assertEqual(len(result.findings), 1)

    def test_classifies_empty_skipped_errors_and_no_findings(self):
        self.assertEqual(parse_dalfox_output("nothing detected").status, "NO_FINDINGS")
        self.assertEqual(parse_dalfox_output("SKIPPED: no query params").status, "SKIPPED")
        self.assertEqual(parse_dalfox_output("[ERROR] target unreachable").status, "ERROR")
        self.assertEqual(parse_dalfox_output("[ERR] target unreachable").status, "ERROR")
        self.assertEqual(parse_dalfox_output("Código de salida: 2").status, "ERROR")
        self.assertEqual(parse_dalfox_output("").status, "ERROR")

    def test_validator_context_is_reduced_and_redacts_query_values(self):
        raw_output = (
            "debug secret-token\n"
            "[POC][V][GET][inHTML-HTML] "
            "https://example.test/search?token=abc123&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E\n"
            "[INFO] unneeded Dalfox diagnostic"
        )
        result = parse_dalfox_output(raw_output)
        context = build_dalfox_validator_context(
            result,
            target_id="target-1",
            request_id="request-1",
            endpoint="https://example.test/search?token=abc123&q=hello",
            method="GET",
        )
        serialized = json.dumps(context)

        self.assertEqual(
            set(context),
            {"tool", "status", "target_id", "request_id", "endpoint", "method", "findings"},
        )
        self.assertIn("parameter", context["findings"][0])
        self.assertIn("verification", context["findings"][0])
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("abc123", serialized)
        self.assertNotIn("debug", serialized)
        self.assertNotIn("raw_output", context)
        self.assertNotIn("headers", context)
        self.assertNotIn("body", context)

    def test_only_verified_pocs_are_promoted_when_llm_omits_finding(self):
        raw_output = (
            "[POC][V][GET][inHTML-HTML] "
            "https://example.test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E\n"
            "[POC][R][GET][inHTML-HTML] "
            "https://example.test/search?q=%3Csvg%3E"
        )
        result = parse_dalfox_output(raw_output)
        normalized = {
            "status": result.status,
            "findings": [
                {
                    "endpoint": finding.endpoint,
                    "parameter": finding.parameter,
                    "verification": finding.verification,
                    "evidence": f"Dalfox reported a {finding.verification} POC",
                }
                for finding in result.findings
            ],
        }
        merged = merge_verified_dalfox_findings(
            {"vulnerabilities": []},
            [
                {
                    "tool": "dalfox",
                    "endpoint": "https://example.test/search?q=%5BREDACTED%5D",
                    "command": "dalfox scan https://example.test/search?q=test",
                    "output": json.dumps(normalized),
                }
            ],
        )

        self.assertEqual(len(merged["vulnerabilities"]), 1)
        finding = merged["vulnerabilities"][0]
        self.assertEqual(finding["type"], "Cross-Site Scripting (XSS)")
        self.assertEqual(finding["parameter"], "q")
        self.assertEqual(finding["tools_used"], ["dalfox"])

    def test_xss_is_registered_in_the_validation_flow_and_prompt(self):
        self.assertTrue(is_xss_attack("xss"))
        self.assertIn("CRITERIOS ESPECÍFICOS PARA XSS", get_system_prompt("xss"))
        self.assertIn(
            "realiza un flujo de escritura y posterior lectura",
            get_system_prompt("xss"),
        )


if __name__ == "__main__":
    unittest.main()
