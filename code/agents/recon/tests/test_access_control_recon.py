import unittest

from helpers import (
    build_recon_output_from_dict,
    ensure_access_control_target_coverage,
)


class AccessControlReconTests(unittest.TestCase):
    def setUp(self):
        self.target_url = "http://juice-shop:3000"
        self.deep_crawler_data = {
            "entry_points": [
                {
                    "id": "entry_0001",
                    "method": "GET",
                    "url": "http://juice-shop:3000/rest/basket/7",
                    "path": "/rest/basket/7",
                    "headers": {"accept": "application/json"},
                    "body": None,
                    "response": {"status": 200},
                },
                {
                    "id": "entry_0002",
                    "method": "GET",
                    "url": "http://juice-shop:3000/api/Users/",
                    "path": "/api/Users/",
                    "headers": {"accept": "application/json"},
                    "body": None,
                    "response": {"status": 200},
                },
            ]
        }

    def test_observed_id_targets_are_merged_when_llm_returns_generic_targets(self):
        llm_output = {
            "recon_summary": {
                "target_url": self.target_url,
                "attack_type_filter": "web",
                "total_targets_identified": 1,
            },
            "high_priority_targets": [
                {
                    "target_id": "entry_0001",
                    "endpoint": "http://juice-shop:3000/#/login",
                    "method": "GET",
                    "recommended_tool": "hydra",
                }
            ],
        }

        covered = ensure_access_control_target_coverage(
            llm_output,
            self.deep_crawler_data,
            self.target_url,
            discovered_urls=["http://juice-shop:3000/rest/basket/7"],
        )

        endpoints = [target["endpoint"] for target in covered["high_priority_targets"]]
        self.assertIn("http://juice-shop:3000/rest/basket/7", endpoints)
        self.assertIn("http://juice-shop:3000/api/Users/", endpoints)
        self.assertNotIn("http://juice-shop:3000/#/login", endpoints)
        self.assertEqual(
            covered["recon_summary"]["attack_type_filter"], "access_control"
        )
        self.assertTrue(
            all(
                target["recommended_tool"] == "access_control_prober"
                for target in covered["high_priority_targets"]
            )
        )

    def test_recon_output_forces_access_control_prober(self):
        output = build_recon_output_from_dict(
            {
                "recon_summary": {
                    "target_url": self.target_url,
                    "attack_type_filter": "web",
                },
                "high_priority_targets": [
                    {
                        "target_id": "target_001",
                        "endpoint": "http://juice-shop:3000/rest/basket/7",
                        "method": "GET",
                        "recommended_tool": "hydra",
                    }
                ],
            },
            self.target_url,
            "access_control",
            self.deep_crawler_data,
        )

        self.assertEqual(output.recon_summary.attack_type_filter, "access_control")
        self.assertEqual(
            output.high_priority_targets[0].recommended_tool,
            "access_control_prober",
        )


if __name__ == "__main__":
    unittest.main()
