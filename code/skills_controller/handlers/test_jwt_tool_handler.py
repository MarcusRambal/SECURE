import json
import unittest
from unittest.mock import patch

from handlers.jwt_tool_handler import b64e, run_jwt_attack


class JwtToolHandlerTests(unittest.TestCase):
    def test_failed_discovery_still_reports_static_jwt_findings(self):
        token = ".".join(
            [
                b64e(json.dumps({"alg": "HS256"}).encode()).decode(),
                b64e(json.dumps({"sub": "user-1", "role": "user"}).encode()).decode(),
                "signature",
            ]
        )

        with patch(
            "handlers.jwt_tool_handler.discover_test_endpoint",
            return_value=None,
        ):
            result = run_jwt_attack("https://example.test", token)

        self.assertEqual(result["error"], "no_test_endpoint_found")
        self.assertTrue(result["findings"])
        self.assertTrue(
            any(finding["source"] == "jwt_analysis" for finding in result["findings"])
        )


if __name__ == "__main__":
    unittest.main()
