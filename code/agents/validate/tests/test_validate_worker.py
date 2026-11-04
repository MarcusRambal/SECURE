import unittest

from worker import simplify_recon_targets


class ValidateWorkerTargetTransferTests(unittest.TestCase):
    def test_preserves_validation_plan_from_recon(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "request": {"method": "GET", "path": "/api/search"},
        }

        targets = simplify_recon_targets(
            [
                {
                    "target_id": "target-1",
                    "request_id": "request-1",
                    "endpoint": "https://example.test/api/search?q=test",
                    "method": "GET",
                    "recommended_tool": "browserXssValidator",
                    "request": {"method": "GET"},
                    "validation_plan": plan,
                }
            ]
        )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["validation_plan"], plan)


if __name__ == "__main__":
    unittest.main()
