import json
import unittest
from unittest.mock import AsyncMock, patch

from attack_validators import (
    XssValidationStrategy,
    get_validation_strategy,
)


class DalfoxStrategyTests(unittest.IsolatedAsyncioTestCase):
    def test_xss_selects_the_dalfox_validation_strategy(self):
        self.assertIsInstance(get_validation_strategy("xss"), XssValidationStrategy)

    async def test_strategy_calls_dalfox_and_filters_raw_cli_output(self):
        raw_output = (
            "[INFO] private diagnostic noise\n"
            "[POC][V][GET][inHTML-HTML] "
            "https://example.test/search?token=private&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        )
        strategy = get_validation_strategy("xss")
        target = {
            "target_id": "target-1",
            "request_id": "request-1",
            "url": "https://example.test/search?token=private&q=hello",
            "method": "GET",
            "request": {
                "method": "GET",
                "url": "https://example.test/search?token=private&q=hello",
                "headers": {"cookie": "session=private"},
                "body": None,
            },
        }

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(return_value=raw_output),
        ) as call_skill:
            evidence = await strategy.execute(
                None, "https://example.test", [target], "task-1", []
            )

        call_skill.assert_awaited_once()
        self.assertEqual(call_skill.await_args.args[1], "dalfox")
        self.assertEqual(call_skill.await_args.args[2]["request"], target["request"])

        context = strategy.build_validation_context(evidence)
        serialized_context = json.dumps(context)
        self.assertEqual(len(context["dalfox_results"]), 1)
        self.assertEqual(context["dalfox_results"][0]["status"], "FINDINGS")
        self.assertEqual(
            context["dalfox_results"][0]["findings"][0]["verification"],
            "verified",
        )
        self.assertNotIn("private diagnostic noise", serialized_context)
        self.assertNotIn("session=private", serialized_context)
        self.assertNotIn('"output"', serialized_context)

        merged = strategy.merge_findings(
            {"vulnerabilities": []}, evidence, "task-1"
        )
        self.assertEqual(len(merged["vulnerabilities"]), 1)
        self.assertEqual(
            merged["vulnerabilities"][0]["type"],
            "Cross-Site Scripting (XSS)",
        )


if __name__ == "__main__":
    unittest.main()
