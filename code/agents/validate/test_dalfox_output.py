import json
import unittest

from attack_types import is_xss_attack
from dalfox_output import (
    build_dalfox_validator_context,
    merge_verified_dalfox_findings,
    parse_dalfox_output,
    sanitize_dalfox_output_for_snapshot,
)
from validate_prompts import get_system_prompt


class DalfoxOutputTests(unittest.TestCase):
    def test_parses_machine_readable_dalfox_json_and_classifies_finding_tiers(self):
        result = parse_dalfox_output(
            json.dumps(
                {
                    "findings": [
                        {
                            "type": "V",
                            "data": "https://example.test/search?q=%3Csvg%3E",
                            "method": "GET",
                            "param": "q",
                            "payload": "<svg>",
                            "inject_type": "inHTML",
                            "evidence": "Verified payload execution",
                            "confidence_reason": "DOM verification succeeded",
                        },
                        {
                            "type": "R",
                            "data": "https://example.test/search?q=%3Csvg%3E",
                            "method": "GET",
                            "param": "q",
                            "inject_type": "inHTML",
                        },
                        {
                            "type": "A",
                            "data": "https://example.test/search?q=%3Csvg%3E",
                            "method": "GET",
                            "param": "q",
                        },
                    ]
                }
            )
        )

        self.assertEqual(result.status, "FINDINGS")
        self.assertEqual(
            [finding.verification for finding in result.findings],
            ["verified", "reflected", "ast_detected"],
        )
        self.assertEqual(result.findings[0].parameter, "q")
        self.assertIn("DOM verification succeeded", result.findings[0].evidence)

    def test_parses_single_object_and_json_lines_dalfox_output(self):
        records = [
            {
                "type": "V",
                "data": "https://example.test/search?q=first",
                "param": "q",
                "method": "GET",
            },
            {
                "type": "R",
                "data": "https://example.test/search?q=second",
                "param": "q",
                "method": "GET",
            },
        ]

        single = parse_dalfox_output(json.dumps(records[0]))
        json_lines = parse_dalfox_output(
            "\n".join(json.dumps(record) for record in records)
        )

        self.assertEqual(single.status, "FINDINGS")
        self.assertEqual(single.findings[0].verification, "verified")
        self.assertEqual(
            [finding.verification for finding in json_lines.findings],
            ["verified", "reflected"],
        )

    def test_snapshot_sanitizer_preserves_poc_but_redacts_credentials(self):
        raw_output = json.dumps(
            {
                "findings": [
                    {
                        "type": "V",
                        "data": (
                            "http://wackopicko/search.php?"
                            "query=%3Csvg%3E&token=private"
                        ),
                        "payload": "<svg onload=alert(1)>",
                        "Cookie": "session=private",
                    }
                ]
            }
        )

        snapshot, truncated = sanitize_dalfox_output_for_snapshot(raw_output)

        self.assertFalse(truncated)
        self.assertIn("query=%3Csvg%3E", snapshot)
        self.assertIn("<svg onload=alert(1)>", snapshot)
        self.assertIn("[REDACTED]", snapshot)
        self.assertNotIn("private", snapshot)

    def test_keeps_findings_from_different_http_methods(self):
        output = json.dumps(
            {
                "findings": [
                    {
                        "type": "V",
                        "data": "https://example.test/guestbook",
                        "method": "GET",
                        "param": "comment",
                    },
                    {
                        "type": "V",
                        "data": "https://example.test/guestbook",
                        "method": "POST",
                        "param": "comment",
                    },
                ]
            }
        )

        result = parse_dalfox_output(output)

        self.assertEqual([finding.method for finding in result.findings], ["GET", "POST"])

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

    def test_verified_finding_has_method_and_safe_verification_steps(self):
        normalized = {
            "status": "FINDINGS",
            "findings": [
                {
                    "endpoint": "http://wackopicko/guestbook.php",
                    "method": "POST",
                    "parameter": "comment",
                    "verification": "verified",
                    "context": "inHTML",
                    "evidence": "Dalfox confirmed an executable position",
                }
            ],
        }

        merged = merge_verified_dalfox_findings(
            {"vulnerabilities": []},
            [
                {
                    "tool": "dalfox",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "method": "POST",
                    "command": '/app/dalfox scan --input-type raw-http "/tmp/dalfox-req.txt"',
                    "output": json.dumps(normalized),
                }
            ],
        )

        finding = merged["vulnerabilities"][0]
        self.assertEqual(finding["method"], "POST")
        self.assertIn("parámetro `comment`", finding["verification_steps"])
        self.assertIn("no lo demuestra", finding["verification_steps"])
        self.assertIn("<svg onload=alert(1)>", finding["verification_steps"])
        self.assertIn("vuelve a cargar la vista", finding["verification_steps"])

    def test_merging_preserves_same_endpoint_findings_with_different_methods(self):
        normalized = {
            "status": "FINDINGS",
            "findings": [
                {
                    "endpoint": "http://wackopicko/guestbook.php",
                    "method": method,
                    "parameter": "comment",
                    "verification": "verified",
                }
                for method in ("GET", "POST")
            ],
        }

        merged = merge_verified_dalfox_findings(
            {"vulnerabilities": []},
            [
                {
                    "tool": "dalfox",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "output": json.dumps(normalized),
                }
            ],
        )

        self.assertEqual(
            [finding["method"] for finding in merged["vulnerabilities"]],
            ["GET", "POST"],
        )

    def test_existing_finding_is_enriched_with_dalfox_verification_details(self):
        normalized = {
            "status": "FINDINGS",
            "findings": [
                {
                    "endpoint": "http://wackopicko/guestbook.php",
                    "method": "POST",
                    "parameter": "comment",
                    "verification": "verified",
                    "context": "inHTML",
                    "evidence": "Dalfox marked this proof verified",
                }
            ],
        }

        merged = merge_verified_dalfox_findings(
            {
                "vulnerabilities": [
                    {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "endpoint": "http://wackopicko/guestbook.php",
                        "parameter": "comment",
                        "evidence": "Original model evidence",
                        "confidence": "HIGH",
                        "tools_used": ["dalfox"],
                    }
                ]
            },
            [
                {
                    "tool": "dalfox",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "output": json.dumps(normalized),
                }
            ],
        )

        self.assertEqual(len(merged["vulnerabilities"]), 1)
        finding = merged["vulnerabilities"][0]
        self.assertEqual(finding["method"], "POST")
        self.assertIn("Dalfox marked this proof verified", finding["evidence"])
        self.assertIn("entorno de pruebas autorizado", finding["verification_steps"])
        self.assertIn("origen del sitio", finding["verification_steps"])

    def test_xss_is_registered_in_the_validation_flow_and_prompt(self):
        self.assertTrue(is_xss_attack("xss"))
        self.assertIn("CRITERIOS ESPECÍFICOS PARA XSS", get_system_prompt("xss"))
        self.assertIn(
            "realiza un flujo de escritura y posterior lectura",
            get_system_prompt("xss"),
        )


if __name__ == "__main__":
    unittest.main()
