import unittest
from skills_controller.tools.mcp_tools_registry import MCP_SKILLS_REGISTRY
from skills_controller.tools.crypto_inspector_handler import prepare_args as prepare_crypto_args

class TestMCPHandlers(unittest.TestCase):

    def test_crypto_inspector_handler(self):
        sample_input = {
            "target_url": "http://juice-shop-target:3000/rest/admin/application-configuration"
        }
        
        # Probar el adaptador prepare_args
        updated_args, input_files = prepare_crypto_args(sample_input)
        
        self.assertIsInstance(updated_args, dict)
        self.assertIsInstance(input_files, list)
        self.assertIn("target_url", updated_args)

    def test_registry_integration(self):
        self.assertIn("crypto_inspector", MCP_SKILLS_REGISTRY)
        schema = MCP_SKILLS_REGISTRY["crypto_inspector"]
        self.assertEqual(schema["name"], "crypto_inspector")

if __name__ == "__main__":
    unittest.main()