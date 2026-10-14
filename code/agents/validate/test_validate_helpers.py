import unittest

from helpers import (
    build_validate_output_from_dict,
    extract_sqli_agent_findings,
    extract_sqli_map_findings,
    extract_sqlmap_findings,
    get_sqli_test_parameters,
    merge_sqli_agent_findings,
    merge_sqli_map_findings,
    merge_sqlmap_findings,
    sanitize_endpoint_for_context,
)


class ValidateSqliHelperTests(unittest.TestCase):
    def test_extracts_query_form_and_nested_json_parameter_names(self):
        query_and_form = get_sqli_test_parameters(
            "http://juice-shop:3000/login?next=%2Fhome&id=1",
            {
                "headers": {
                    "content-type": "application/x-www-form-urlencoded"
                },
                "body": "username=alice&password=test",
            },
        )
        self.assertEqual(
            query_and_form,
            [
                ("next", "query"),
                ("id", "query"),
                ("username", "form_body"),
                ("password", "form_body"),
            ],
        )

        json_parameters = get_sqli_test_parameters(
            "http://juice-shop:3000/api",
            {
                "headers": {"content-type": "application/json"},
                "body": '{"user":{"email":"a@example.test","password":"secret"}}',
            },
        )
        self.assertEqual(
            json_parameters,
            [("user.email", "json_body"), ("user.password", "json_body")],
        )

    def test_sanitizes_credentials_and_query_values(self):
        safe_url = sanitize_endpoint_for_context(
            "https://user:pass@example.test/items?id=123&token=secret"
        )
        self.assertEqual(
            safe_url,
            "https://example.test/items?id=%5BREDACTED%5D&token=%5BREDACTED%5D",
        )


class SqlmapFindingTests(unittest.TestCase):
    def test_keeps_sqlmap_confirmed_findings_when_model_returns_empty_output(self):
        executions = [
            {
                "tool": "sqlmap",
                "target_id": "target-1",
                "request_id": "",
                "endpoint": "https://example.test/items?id=1",
                "command": "sqlmap -r /tmp/request-1.txt",
                "output": (
                    "[INFO] GET parameter 'id' appears to be "
                    "'AND boolean-based blind' injectable\n"
                    "sqlmap identified the following injection point(s):\n"
                    "Parameter: id (GET)\n"
                    "    Type: boolean-based blind\n"
                    "    Title: AND boolean-based blind\n"
                    "    Payload: id=1 AND 1=1"
                ),
            },
            {
                "tool": "sqlmap",
                "target_id": "target-2",
                "request_id": "",
                "endpoint": "https://example.test/search?q=hello",
                "command": "sqlmap -r /tmp/request-2.txt",
                "output": (
                    "back-end DBMS: MySQL\n"
                    "[INFO] GET parameter 'q' does not appear to be injectable"
                ),
            },
        ]

        detected = extract_sqlmap_findings(executions)
        self.assertEqual(len(detected), 1)
        self.assertEqual(detected[0]["parameter"], "id")

        merged = merge_sqlmap_findings({"vulnerabilities": []}, executions)
        result = build_validate_output_from_dict(
            merged,
            "https://example.test",
            "2026-10-11T10:00:00+00:00",
            executions,
        )

        self.assertEqual(len(result.vulnerabilities), 1)
        finding = result.vulnerabilities[0]
        self.assertEqual(finding.type, "SQL Injection")
        self.assertEqual(finding.endpoint, "https://example.test/items?id=1")
        self.assertEqual(finding.parameter, "id")
        self.assertEqual(finding.reproducible_command, "sqlmap -r /tmp/request-1.txt")
        self.assertIn("sqlmap identified", finding.evidence)
        self.assertEqual(finding.tools_used, ["sqlmap"])


class SqliAgentFindingTests(unittest.TestCase):
    def test_keeps_only_positive_sql_agent_checks(self):
        executions = [
            {
                "tool": "sqli_agent",
                "target_id": "target-1",
                "request_id": "request-1",
                "endpoint": "https://example.test/items?id=%5BREDACTED%5D",
                "parameter": "id",
                "command": "MCP sqli_agent --param id --location query",
                "output": (
                    '{"error_based":{"technique":"error_based","injectable":false},'
                    '"boolean_based":{"technique":"boolean_based","injectable":true,'
                    '"baseline_length":100,"true_length":100,"false_length":20},'
                    '"time_based":{"technique":"time_based","injectable":false}}'
                ),
            },
            {
                "tool": "sqli_agent",
                "endpoint": "https://example.test/search?q=%5BREDACTED%5D",
                "parameter": "q",
                "output": '{"error":"HTTP request failed (ConnectionError)"}',
            },
        ]

        findings = extract_sqli_agent_findings(executions)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "id")
        self.assertEqual(findings[0]["confidence"], "MEDIUM")
        self.assertIn("boolean_based", findings[0]["evidence"])

        merged = merge_sqli_agent_findings({"vulnerabilities": []}, executions)
        result = build_validate_output_from_dict(
            merged,
            "https://example.test",
            "2026-10-14T10:00:00+00:00",
            executions,
        )
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].tools_used, ["sqli_agent"])
        self.assertEqual(
            result.vulnerabilities[0].reproducible_command,
            "MCP sqli_agent --param id --location query",
        )

    def test_login_bypass_evidence_records_true_and_false_statuses(self):
        executions = [
            {
                "tool": "sqli_agent",
                "endpoint": "http://juice-shop:3000/rest/user/login",
                "parameter": "email",
                "command": "MCP sqli_agent --param email --location json_body",
                "output": (
                    '{"boolean_based":{"technique":"boolean_based","injectable":true,'
                    '"login_or_bypass":{"technique":"login_or_boolean",'
                    '"injectable":true,"true_status_code":200,'
                    '"false_status_code":401}}}'
                ),
            }
        ]

        finding = extract_sqli_agent_findings(executions)[0]
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertIn("HTTP 200 vs 401", finding["evidence"])


class SqliMapFindingTests(unittest.TestCase):
    def test_keeps_only_positive_sqlmap_detection_reports(self):
        executions = [
            {
                "tool": "sqli_map",
                "target_id": "target-1",
                "request_id": "request-1",
                "endpoint": "http://juice-shop:3000/rest/user/login",
                "parameter": "email",
                "command": "MCP sqli_map --param \"email\" --action detect",
                "output": (
                    '{"action":"detect","result":{"injectable":true,'
                    '"database":"SQLite","techniques":["boolean-based blind"],'
                    '"summary":["Parameter: email (POST)"]}}'
                ),
            },
            {
                "tool": "sqli_map",
                "endpoint": "http://juice-shop:3000/rest/user/login",
                "parameter": "password",
                "output": (
                    '{"action":"detect","result":{"injectable":false,'
                    '"database":"unknown","techniques":[]}}'
                ),
            },
            {
                "tool": "sqli_map",
                "parameter": "token",
                "output": '{"error":"SQLMap detection container failed","status":"ERROR"}',
            },
        ]

        findings = extract_sqli_map_findings(executions)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "email")
        self.assertIn("boolean-based blind", findings[0]["evidence"])

        merged = merge_sqli_map_findings({"vulnerabilities": []}, executions)
        result = build_validate_output_from_dict(
            merged,
            "http://juice-shop:3000",
            "2026-10-14T10:00:00+00:00",
            executions,
        )
        self.assertEqual(len(result.vulnerabilities), 1)
        finding = result.vulnerabilities[0]
        self.assertEqual(finding.tools_used, ["sqli_map"])
        self.assertEqual(finding.parameter, "email")
        self.assertIn("Parameter: email (POST)", finding.evidence)
        self.assertEqual(
            finding.reproducible_command,
            'MCP sqli_map --param "email" --action detect',
        )


if __name__ == "__main__":
    unittest.main()
