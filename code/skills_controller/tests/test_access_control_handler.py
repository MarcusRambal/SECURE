import unittest

from tools.access_control_prober_handler import prepare_args
from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY


class AccessControlProberHandlerTests(unittest.TestCase):
    def test_registry_exposes_runtime_configuration(self):
        config = MCP_SKILLS_REGISTRY["access_control_prober"]
        self.assertEqual(config["mcp_schema"]["name"], "access_control_prober")
        self.assertIn("inputSchema", config["mcp_schema"])
        self.assertEqual(config["image"], "local-access-control-prober:latest")
        self.assertEqual(config["command_template"], "{args}")
        self.assertIn("prepare_args", config)

    def test_handler_builds_cli_flags(self):
        updated, input_files = prepare_args(
            {
                "base_url": "http://juice-shop:3000/",
                "endpoint": "http://juice-shop:3000/rest/basket/{id}",
                "victim_id": "1",
                "token_victim": "victim-token",
                "token_attacker": "attacker-token",
            }
        )

        self.assertEqual(input_files, {})
        self.assertNotIn("skip_execution", updated)
        self.assertIn("--base-url http://juice-shop:3000", updated["args"])
        self.assertIn("--endpoint", updated["args"])
        self.assertIn("/rest/basket/{id}", updated["args"])
        self.assertIn("--victim-id 1", updated["args"])
        self.assertIn("--token-victim victim-token", updated["args"])
        self.assertIn("--token-attacker attacker-token", updated["args"])

    def test_handler_skips_without_required_arguments(self):
        updated, _ = prepare_args({"base_url": "http://juice-shop:3000"})
        self.assertTrue(updated.get("skip_execution"))
        self.assertIn("reason", updated)


if __name__ == "__main__":
    unittest.main()
