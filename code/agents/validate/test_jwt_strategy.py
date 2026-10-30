import json
import unittest
from unittest.mock import AsyncMock, patch

from attack_validators import (
    JwtValidationStrategy,
    ValidationEvidence,
    get_validation_strategy,
)
from main import process_validate_task


class JwtValidationStrategyTests(unittest.IsolatedAsyncioTestCase):
    def test_jwt_selects_the_deterministic_strategy(self):
        self.assertIsInstance(get_validation_strategy("jwt"), JwtValidationStrategy)

    async def test_missing_token_returns_an_unconfirmed_result(self):
        strategy = get_validation_strategy("jwt")
        evidence = await strategy.execute(None, "https://example.test", [], "task-1", [])

        result = strategy.build_deterministic_output(
            evidence,
            "https://example.test",
            "2026-01-01T00:00:00+00:00",
        )

        self.assertEqual(result.vulnerabilities, [])
        self.assertIn("No se recibió token", result.unconfirmed_findings[0]["reason"])

    async def test_jwt_tool_output_becomes_structured_findings(self):
        report = {
            "findings": [
                {
                    "title": "Weak JWT secret",
                    "severity": "high",
                    "description": "A weak signing secret was accepted.",
                    "evidence": "Validation confirmed the secret.",
                    "cwe": "CWE-321",
                    "remediation": "Use a strong secret.",
                }
            ],
            "summary": {"risk_level": "HIGH"},
            "jwt_analysis": {"algorithm": "HS256"},
        }
        strategy = get_validation_strategy("jwt")
        timings = []

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(return_value=json.dumps(report)),
        ) as call_skill:
            evidence = await strategy.execute(
                None,
                "https://example.test",
                [],
                "task-1",
                timings,
                token="jwt-token",
            )

        call_skill.assert_awaited_once()
        self.assertEqual(call_skill.await_args.args[1], "jwt_tool")
        self.assertEqual(call_skill.await_args.args[2]["token"], "jwt-token")
        result = strategy.build_deterministic_output(
            evidence,
            "https://example.test",
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].severity, "HIGH")
        self.assertEqual(result.vulnerabilities[0].tools_used, ["jwt_tool"])
        self.assertEqual(result.unconfirmed_findings[0]["attacks_summary"], report["summary"])

    async def test_jwt_tool_error_with_findings_is_marked_unconfirmed(self):
        report = {
            "error": "no_test_endpoint_found",
            "findings": [
                {
                    "title": "JWT has no 'exp' claim",
                    "severity": "HIGH",
                    "description": "The token does not expire.",
                }
            ],
        }
        strategy = get_validation_strategy("jwt")

        with patch(
            "attack_validators.call_mcp_skill",
            new=AsyncMock(return_value=json.dumps(report)),
        ):
            evidence = await strategy.execute(
                None,
                "https://example.test",
                [],
                "task-1",
                [],
                token="jwt-token",
            )

        result = strategy.build_deterministic_output(
            evidence,
            "https://example.test",
            "2026-01-01T00:00:00+00:00",
        )

        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertIn(
            "no_test_endpoint_found",
            result.unconfirmed_findings[0]["reason"],
        )

    async def test_jwt_tool_error_returns_partial_recovery_mode(self):
        strategy = get_validation_strategy("jwt")

        with patch(
            "main.get_validation_strategy",
            return_value=strategy,
        ), patch.object(
            strategy,
            "execute",
            new=AsyncMock(
                return_value=ValidationEvidence(
                    execution_error="jwt_tool error: no_test_endpoint_found",
                ),
            ),
        ):
            _, recovery_mode, _ = await process_validate_task(
                None,
                "https://example.test",
                "jwt",
                [],
                token="jwt-token",
                task_id="task-1",
            )

        self.assertEqual(recovery_mode, "fallback")


if __name__ == "__main__":
    unittest.main()
