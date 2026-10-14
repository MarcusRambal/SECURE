import unittest
from unittest.mock import patch
from types import SimpleNamespace

from sqli_map import _extract_db_type, _extract_techniques, run_detection_scan


class SqlmapReportParsingTests(unittest.TestCase):
    def test_prefers_the_reported_dbms_over_warning_examples(self):
        output = (
            "[WARNING] try forcing the back-end DBMS (e.g. '--dbms=mysql')\n"
            "back-end DBMS: SQLite\n"
        )
        self.assertEqual(_extract_db_type(output), "SQLite")

    def test_extracts_only_confirmed_techniques_from_injection_report(self):
        output = (
            "[WARNING] boolean-based, error-based, and time-based tests were attempted\n"
            "sqlmap identified the following injection point(s):\n"
            "Parameter: email (POST)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
            "    Payload: email=test AND 1=1\n"
            "back-end DBMS: SQLite\n"
        )
        self.assertEqual(_extract_techniques(output), ["boolean-based"])

    @patch("sqli_map.subprocess.run")
    def test_does_not_mark_negative_injectable_message_as_positive(self, run):
        run.return_value = SimpleNamespace(
            stdout="[INFO] POST parameter 'email' does not appear to be injectable",
            stderr="",
            returncode=0,
        )
        result = run_detection_scan(
            "sqlmap", None, param="email", request_file="/tmp/request.txt"
        )
        self.assertFalse(result["injectable"])

    @patch("sqli_map.subprocess.run")
    def test_marks_explicit_sqlmap_injection_report_as_positive(self, run):
        run.return_value = SimpleNamespace(
            stdout=(
                "sqlmap identified the following injection point(s):\n"
                "Parameter: email (POST)\n"
                "    Type: boolean-based blind\n"
                "back-end DBMS: SQLite\n"
            ),
            stderr="",
            returncode=0,
        )
        result = run_detection_scan(
            "sqlmap", None, param="email", request_file="/tmp/request.txt"
        )
        self.assertTrue(result["injectable"])
        self.assertEqual(result["database"], "SQLite")
        self.assertEqual(result["techniques"], ["boolean-based"])


if __name__ == "__main__":
    unittest.main()
