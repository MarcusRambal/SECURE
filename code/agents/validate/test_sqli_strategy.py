import json
import unittest
from unittest.mock import AsyncMock, patch

from attack_validators import SqliValidationStrategy


class SqliValidationStrategyTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_sqlmap_profile_is_not_reported_as_completed(self):
        strategy = SqliValidationStrategy()
        target = {
            "target_id": "target-1",
            "request_id": "request-1",
            "url": "https://example.test/search?id=1",
            "method": "GET",
            "request": {
                "method": "GET",
                "url": "https://example.test/search?id=1",
                "headers": {},
                "body": None,
            },
        }
        reports = [
            json.dumps({"findings": []}),
            json.dumps(
                {
                    "action": "validate",
                    "result": {"injectable": True, "database": "SQLite"},
                    "profile": {
                        "status": "partial",
                        "errors": [
                            {
                                "action": "tables",
                                "message": "SQLMap table enumeration timed out",
                            }
                        ],
                    },
                }
            ),
        ]

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(side_effect=reports),
        ):
            evidence = await strategy.execute(
                None, "https://example.test", [target], "task-1", []
            )

        self.assertEqual(
            [entry["status"] for entry in evidence.pre_executed_context],
            ["COMPLETED", "PARTIAL"],
        )


if __name__ == "__main__":
    unittest.main()
