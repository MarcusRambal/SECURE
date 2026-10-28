import unittest
from tools.mcp_tools_registry import MCP_SKILLS_REGISTRY
from tools.crypto_inspector_handler import prepare_args as prepare_crypto_args

class TestMCPHandlers(unittest.TestCase):

    def test_registry_integration(self):
        self.assertIn("crypto_inspector", MCP_SKILLS_REGISTRY)
        schema = MCP_SKILLS_REGISTRY["crypto_inspector"]
        self.assertEqual(schema["mcp_schema"]["name"], "crypto_inspector")

    def test_crypto_inspector_handler(self):
        sample_input = {
        "target_url": "http://juice-shop-target:3000/rest/admin/application-configuration"
        }

        updated_args, input_files = prepare_crypto_args(sample_input)

        self.assertIsInstance(updated_args, dict)
        self.assertIsInstance(input_files, dict)
        self.assertIn("target_url", updated_args)

        # NUEVO: verificar que el comando se generó bien
        self.assertNotIn("skip_execution", updated_args)
        self.assertIn("--url", updated_args["args"])
        self.assertIn("juice-shop-target:3000", updated_args["args"])
        self.assertTrue(updated_args["args"].startswith("--url"))


    def test_crypto_inspector_handler_rejects_empty(self):
        """Sin target_url ni jwt_token, debe saltar ejecución."""
        updated_args, _ = prepare_crypto_args({})
        self.assertTrue(updated_args.get("skip_execution"))
        self.assertIn("reason", updated_args)


    def test_crypto_inspector_handler_skips_static_asset(self):
        """Un .js/.css debe descartarse."""
        updated_args, _ = prepare_crypto_args({"target_url": "http://host/app.js"})
        self.assertTrue(updated_args.get("skip_execution"))


    def test_crypto_inspector_handler_accepts_jwt(self):
        """jwt_token debe generar --jwt, no --url."""
        updated_args, _ = prepare_crypto_args({"jwt_token": "eyJhbGc.eyJzdWI.sig"})
        self.assertIn("--jwt", updated_args["args"])
        self.assertNotIn("--url", updated_args["args"])

    

if __name__ == "__main__":
    unittest.main()