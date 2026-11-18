import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, patch

from handlers.sqli_map_handler import (
    REPORT_MARKER,
    SQLMAP_CONTAINER_TIMEOUT_SECONDS,
    _dump_state_entry,
    execute_sqli_map,
)


class SqliMapHandlerTests(unittest.IsolatedAsyncioTestCase):
    @patch("handlers.sqli_map_handler.save_skill_report")
    @patch(
        "handlers.sqli_map_handler.docker_runner.execute_tool",
        new_callable=AsyncMock,
    )
    async def test_container_failure_keeps_sanitized_diagnostics(
        self, execute_tool, save_report
    ):
        execute_tool.return_value = {
            "status": "ERROR",
            "output": (
                "[ERROR] SQLMap could not connect to "
                "http://juice-shop:3000/api?token=private\n"
                "Authorization: Bearer private-token"
            ),
        }
        save_report.return_value = "report.json"

        output = await execute_sqli_map({
            "action": "detect",
            "target_url": "http://juice-shop:3000/api",
            "param": "id",
        })

        report = json.loads(output)
        self.assertEqual(report["status"], "ERROR")
        self.assertIn("SQLMap could not connect", report["diagnostics"][0])
        self.assertIn("token=%5BREDACTED%5D", report["diagnostics"][0])
        self.assertNotIn("private", json.dumps(report))

    @patch("handlers.sqli_map_handler.save_skill_report")
    @patch(
        "handlers.sqli_map_handler.docker_runner.execute_tool",
        new_callable=AsyncMock,
    )
    async def test_validate_routes_request_to_schema_listing(
        self, execute_tool, save_report
    ):
        execute_tool.return_value = {
            "status": "SUCCESS",
            "output": REPORT_MARKER + json.dumps({
                "action": "validate",
                "result": {"injectable": True, "database": "SQLite"},
                "profile": {
                    "status": "completed",
                    "databases": ["main"],
                    "tables": [{"database": "main", "tables": ["users"]}],
                },
            }),
        }
        save_report.return_value = "report.json"

        output = await execute_sqli_map({
            "action": "validate",
            "target_url": "http://juice-shop:3000/rest/user/login",
            "request": {
                "method": "POST",
                "url": "http://localhost:3001/rest/user/login",
                "headers": {
                    "Host": "localhost:3001",
                    "Content-Type": "application/json",
                },
                "body": {"email": "test@example.test", "password": "secret"},
            },
            "param": "email",
        })

        command = execute_tool.call_args.kwargs["command"]
        self.assertEqual(
            execute_tool.call_args.kwargs["timeout"],
            SQLMAP_CONTAINER_TIMEOUT_SECONDS,
        )
        request_file = execute_tool.call_args.kwargs["input_files"][
            "/tmp/sqli-map-request.txt"
        ]
        self.assertIn("--action validate", command)
        self.assertIn("--param email", command)
        self.assertIn("--request-file", command)
        self.assertIn("Host: juice-shop:3000\r\n", request_file)
        report = json.loads(output)
        self.assertEqual(report["profile"]["databases"], ["main"])
        self.assertEqual(report["profile"]["tables"][0]["tables"], ["users"])

    @patch("handlers.sqli_map_handler.save_skill_report")
    @patch(
        "handlers.sqli_map_handler.docker_runner.execute_tool",
        new_callable=AsyncMock,
    )
    async def test_repeat_extract_reuses_real_table_evidence(
        self, execute_tool, save_report
    ):
        raw_value = "alice@example.test"
        execute_tool.side_effect = [
            {
                "status": "SUCCESS",
                "output": REPORT_MARKER + json.dumps({
                    "action": "extract",
                    "status": "completed",
                    "result": {"injectable": True, "database": "SQLite"},
                    "profile": {"status": "completed"},
                    "dumps": [{
                        "database": "SQLite",
                        "table": "users",
                        "row_count": 1,
                        "truncated": False,
                        "rows": [{
                            "email": raw_value,
                            "password": "plaintext-secret",
                            "id": "7",
                        }],
                    }],
                }),
            },
            {
                "status": "SUCCESS",
                "output": REPORT_MARKER + json.dumps({
                    "action": "extract",
                    "status": "detection_only",
                    "result": {"injectable": True, "database": "SQLite"},
                    "profile": {"status": "skipped"},
                    "dumps": [],
                }),
            },
        ]
        save_report.return_value = "report.json"

        with TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / ".dump_state.json"
            with patch("handlers.sqli_map_handler.DUMP_STATE_FILE", state_file):
                first = json.loads(await execute_sqli_map({
                    "action": "extract",
                    "target_url": "http://juice-shop:3000/api/users?id=7",
                    "param": "id",
                }))
                second = json.loads(await execute_sqli_map({
                    "action": "extract",
                    "target_url": "http://juice-shop:3000/api/users?id=7",
                    "param": "id",
                }))
                saved_state = state_file.read_text(encoding="utf-8")

        self.assertIn(raw_value, json.dumps(first))
        self.assertIn("plaintext-secret", json.dumps(first))
        self.assertIn(raw_value, saved_state)
        self.assertEqual(first["evidence"]["source"], "current")
        self.assertEqual(first["evidence"]["tables"][0]["table"], "users")
        self.assertEqual(first["evidence"]["tables"][0]["row_count"], 1)
        self.assertEqual(
            first["evidence"]["tables"][0]["columns"],
            ["email", "id", "password"],
        )
        self.assertEqual(
            first["evidence"]["tables"][0]["preview"],
            [[raw_value, "7", "plaintext-secret"]],
        )
        self.assertFalse(first["evidence"]["tables"][0]["values_redacted"])
        self.assertNotIn("rows", first["dumps"][0])

        self.assertIn("--skip-dump", execute_tool.call_args_list[1].kwargs["command"])
        self.assertEqual(second["evidence"]["source"], "cached")
        self.assertEqual(second["evidence"]["tables"], first["evidence"]["tables"])

    def test_legacy_dump_state_is_refreshed_without_rewriting_it_on_read(self):
        with TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / ".dump_state.json"
            legacy_state = json.dumps(["known-target-hash"])
            state_file.write_text(legacy_state, encoding="utf-8")

            with patch("handlers.sqli_map_handler.DUMP_STATE_FILE", state_file):
                self.assertIsNone(_dump_state_entry("known-target-hash"))

            self.assertEqual(state_file.read_text(encoding="utf-8"), legacy_state)

    def test_masked_versioned_dump_state_is_refreshed_without_rewriting(self):
        with TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / ".dump_state.json"
            state = {
                "version": 1,
                "targets": {
                    "known-target-hash": {
                        "tables": [{
                            "table": "users",
                            "row_count": 1,
                            "columns": ["email"],
                            "preview": [["[REDACTED]"]],
                            "values_redacted": True,
                        }],
                    },
                },
            }
            original_state = json.dumps(state)
            state_file.write_text(original_state, encoding="utf-8")

            with patch("handlers.sqli_map_handler.DUMP_STATE_FILE", state_file):
                self.assertIsNone(_dump_state_entry("known-target-hash"))

            self.assertEqual(state_file.read_text(encoding="utf-8"), original_state)


if __name__ == "__main__":
    unittest.main()
