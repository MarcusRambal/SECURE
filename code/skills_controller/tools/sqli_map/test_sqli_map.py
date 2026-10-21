import unittest
from unittest.mock import patch
from types import SimpleNamespace

from sqli_map import _extract_db_type, _extract_techniques, run_detection_scan
from sqli_map import enumerate_databases, enumerate_tables, run_validation_scan


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

    @patch("sqli_map.subprocess.run")
    def test_lists_databases_from_captured_request(self, run):
        run.return_value = SimpleNamespace(
            stdout=(
                "available databases [2]:\n"
                "[*] main\n"
                "[*] app\n"
                "\n"
            ),
            stderr="",
            returncode=0,
        )

        databases = enumerate_databases(
            "sqlmap",
            None,
            param="email",
            request_file="/tmp/request.txt",
        )

        self.assertEqual(databases, ["main", "app"])
        command = run.call_args.args[0]
        self.assertIn("-r", command)
        self.assertIn("/tmp/request.txt", command)
        self.assertIn("-p", command)
        self.assertIn("email", command)
        self.assertIn("--dbs", command)
        self.assertIn("--ignore-code=401", command)
        self.assertIn("--level=3", command)
        self.assertIn("--risk=2", command)

    @patch("sqli_map.subprocess.run")
    def test_lists_inline_sqlite_database_name(self, run):
        run.return_value = SimpleNamespace(
            stdout="available databases [1]: [*] main\n",
            stderr="",
            returncode=0,
        )

        self.assertEqual(
            enumerate_databases(
                "sqlmap", "https://example.test", param="email"
            ),
            ["main"],
        )

    @patch("sqli_map.subprocess.run")
    def test_lists_tables_from_captured_request(self, run):
        run.return_value = SimpleNamespace(
            stdout=(
                "+-------+\n"
                "| Table |\n"
                "+-------+\n"
                "| users |\n"
                "| orders|\n"
                "+-------+\n"
            ),
            stderr="",
            returncode=0,
        )

        tables = enumerate_tables(
            "sqlmap",
            None,
            "main",
            param="email",
            request_file="/tmp/request.txt",
        )

        self.assertEqual(tables, ["users", "orders"])
        command = run.call_args.args[0]
        self.assertIn("-r", command)
        self.assertIn("-D", command)
        self.assertIn("main", command)
        self.assertIn("--tables", command)
        self.assertIn("--ignore-code=401", command)
        self.assertIn("--level=3", command)
        self.assertIn("--risk=2", command)

    @patch("sqli_map.subprocess.run")
    def test_empty_table_output_is_reported_as_a_failure(self, run):
        run.return_value = SimpleNamespace(
            stdout="No tables found\n",
            stderr="",
            returncode=0,
        )

        with self.assertRaisesRegex(RuntimeError, "returned no table names"):
            enumerate_tables(
                "sqlmap", "https://example.test", None, param="email"
            )

    def test_validation_lists_schema_only_after_positive_detection(self):
        with (
            patch(
                "sqli_map.run_detection_scan",
                return_value={
                    "exit_code": 0,
                    "injectable": True,
                    "database": "SQLite",
                },
            ) as detect,
            patch(
                "sqli_map.enumerate_databases",
                return_value=["main"],
            ) as databases,
            patch(
                "sqli_map.enumerate_tables",
                return_value=["users"],
            ) as tables,
            patch("sqli_map.dump_table") as dump,
        ):
            report = run_validation_scan(
                "sqlmap",
                None,
                "email",
                request_file="/tmp/request.txt",
            )

        self.assertTrue(report["result"]["injectable"])
        self.assertEqual(report["profile"]["databases"], [])
        self.assertEqual(
            report["profile"]["tables"],
            [{
                "database": "SQLite_masterdb",
                "tables": ["users"],
                "tables_truncated": False,
            }],
        )
        self.assertEqual(detect.call_args.kwargs["request_file"], "/tmp/request.txt")
        databases.assert_not_called()
        tables.assert_called_once()
        self.assertIsNone(tables.call_args.args[2])
        dump.assert_not_called()

    def test_validation_does_not_list_schema_without_positive_detection(self):
        with (
            patch(
                "sqli_map.run_detection_scan",
                return_value={
                    "exit_code": 0,
                    "injectable": False,
                    "database": "unknown",
                },
            ),
            patch("sqli_map.enumerate_databases") as databases,
            patch("sqli_map.enumerate_tables") as tables,
        ):
            report = run_validation_scan(
                "sqlmap", "https://example.test", "id"
            )

        self.assertFalse(report["result"]["injectable"])
        self.assertEqual(report["profile"]["reason"], "not_confirmed")
        databases.assert_not_called()
        tables.assert_not_called()


if __name__ == "__main__":
    unittest.main()
