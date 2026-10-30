import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import unittest
from tools.crypto_inspector import inspect_crypto_payload

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

class TestCryptoInspectorAnalysis(unittest.TestCase):

    def _load(self, name):
        with open(os.path.join(FIXTURES_DIR, name)) as f:
            return f.read()

    def test_csaf_sha1_is_low_and_not_exploitable(self):
        report = inspect_crypto_payload(
            self._load("app_config.json"),
            endpoint_hint="http://juice-shop-target:3000/rest/admin/application-configuration",
            http_status=200,
        )
        csaf = [x for x in report["findings"] if "csafHashValue" in x.get("path", "")]
        self.assertTrue(csaf, "No se detectó csafHashValue")
        self.assertEqual(csaf[0]["severity"], "LOW")
        self.assertFalse(csaf[0]["exploitable"])
        self.assertEqual(csaf[0]["context"]["role"], "static_checksum")

    def test_md5_password_is_critical_and_cracked(self):
        report = inspect_crypto_payload(
            self._load("memories.json"),
            endpoint_hint="http://juice-shop-target:3000/rest/memories",
            http_status=200,
        )
        criticals = [x for x in report["findings"] if x["severity"] == "CRITICAL"]
        self.assertGreaterEqual(len(criticals), 1)
        self.assertTrue(any(x.get("attack_result") == "admin123" for x in criticals))

    def test_admin_endpoint_exposure_is_high(self):
        report = inspect_crypto_payload(
            '{"config": {"port": 3000}}',
            endpoint_hint="http://juice-shop-target:3000/rest/admin/application-configuration",
            http_status=200,
        )
        exp = [x for x in report["findings"] if "Exposure" in x.get("title", "")]
        self.assertTrue(exp, "No se detectó exposición de endpoint admin")
        self.assertEqual(exp[0]["severity"], "HIGH")

if __name__ == "__main__":
    unittest.main()