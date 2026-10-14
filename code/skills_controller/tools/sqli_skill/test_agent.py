from types import SimpleNamespace
import unittest
from unittest.mock import patch

import tools.sqli_skill.sqli_manual as sqli_manual


class SqliRequestConstructionTests(unittest.TestCase):
    def test_query_parameter_is_encoded_and_other_values_are_preserved(self):
        url, body = sqli_manual._build_request(
            "https://example.test/items?id=4&mode=full",
            "id",
            "1 AND 1=1--",
        )

        self.assertIsNone(body)
        self.assertIn("id=1+AND+1%3D1--", url)
        self.assertIn("mode=full", url)

    def test_nested_json_field_preserves_other_captured_fields(self):
        url, body = sqli_manual._build_request(
            "https://example.test/api",
            "filter.item_id",
            "'",
            {"filter": {"item_id": 3, "active": True}, "limit": 10},
            "json_body",
        )

        self.assertEqual(url, "https://example.test/api")
        self.assertEqual(
            body,
            {"filter": {"item_id": "'", "active": True}, "limit": 10},
        )

    def test_form_field_preserves_other_captured_fields(self):
        url, body = sqli_manual._build_request(
            "https://example.test/search",
            "q",
            "'",
            "title=Book&category=tools",
            "form_body",
        )

        self.assertEqual(url, "https://example.test/search")
        self.assertEqual(body, {"title": "Book", "category": "tools", "q": "'"})

    @patch("tools.sqli_skill.sqli_manual.detect_error_based")
    @patch("tools.sqli_skill.sqli_manual.detect_boolean_based")
    @patch("tools.sqli_skill.sqli_manual.detect_time_based")
    @patch("tools.sqli_skill.sqli_manual.detect_union_columns")
    def test_bounded_assessment_runs_only_error_boolean_and_time_checks(
        self, union_check, time_check, boolean_check, error_check
    ):
        error_check.return_value = {
            "technique": "error_based",
            "injectable": False,
        }
        boolean_check.return_value = {
            "technique": "boolean_based",
            "injectable": False,
        }
        time_check.return_value = {
            "technique": "time_based",
            "injectable": False,
        }

        report = sqli_manual.run_detection_assessment(
            "https://example.test/items?id=1", "id"
        )

        self.assertFalse(report["injectable"])
        error_check.assert_called_once()
        boolean_check.assert_called_once()
        time_check.assert_called_once()
        union_check.assert_not_called()

    @patch("tools.sqli_skill.sqli_manual._send_payload")
    def test_email_login_uses_or_tautology_and_false_control(self, send_payload):
        send_payload.side_effect = [
            SimpleNamespace(content=b"baseline", status_code=401),
            SimpleNamespace(content=b"true", status_code=401),
            SimpleNamespace(content=b"false", status_code=401),
            SimpleNamespace(content=b'{"token":"issued"}', status_code=200),
            SimpleNamespace(content=b'{"error":"unauthorized"}', status_code=401),
        ]
        captured_body = {"email": "user@example.test", "password": "captured"}

        result = sqli_manual.detect_boolean_based(
            "http://juice-shop:3000/rest/user/login",
            "email",
            "POST",
            body=captured_body,
            location="json_body",
        )

        self.assertTrue(result["login_or_bypass"]["injectable"])
        self.assertEqual(send_payload.call_args_list[3].args[2], "' OR 1=1--")
        self.assertEqual(send_payload.call_args_list[4].args[2], "' OR 1=2--")
        self.assertEqual(
            send_payload.call_args_list[3].args[5]["password"],
            "sqli-agent-invalid-password",
        )
        self.assertEqual(captured_body["password"], "captured")

    @patch("tools.sqli_skill.sqli_manual._send_payload")
    def test_or_login_payload_is_not_sent_to_non_login_routes(self, send_payload):
        send_payload.return_value = SimpleNamespace(
            content=b"same response", status_code=200
        )

        result = sqli_manual.detect_boolean_based(
            "http://juice-shop:3000/api/Users/",
            "email",
            "POST",
            body={"email": "user@example.test"},
            location="json_body",
        )

        self.assertFalse(result["login_or_bypass"]["injectable"])
        self.assertEqual(send_payload.call_count, 3)


if __name__ == "__main__":
    unittest.main()
