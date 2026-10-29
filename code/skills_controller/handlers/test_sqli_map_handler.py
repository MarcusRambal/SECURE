import json
import unittest
from unittest.mock import AsyncMock, patch

from handlers.sqli_map_handler import (
    REPORT_MARKER,
    SQLMAP_CONTAINER_TIMEOUT_SECONDS,
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


if __name__ == "__main__":
    unittest.main()
