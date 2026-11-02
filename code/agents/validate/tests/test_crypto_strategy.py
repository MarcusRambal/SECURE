import json
import unittest

from attack_validators import CryptoValidationStrategy, ValidationEvidence
from helpers import build_validate_output_from_dict

ENDPOINT = "http://juice-shop:3000/rest/memories/"
COMMAND = f"MCP crypto_inspector --target {ENDPOINT}"


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    *,
    role: str = "information_disclosure",
    attack_demonstrated: str = "none",
    attack_result=None,
    path: str | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    attack_chain: list[str] | None = None,
):
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "path": path,
        "evidence": f"Evidencia de {title}",
        "cwe": cwe,
        "owasp": owasp,
        "attack_demonstrated": attack_demonstrated,
        "attack_result": attack_result,
        "attack_chain": attack_chain or [],
        "context": {"role": role},
    }


class CryptoMergeFindingsTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "tool": "crypto_inspector",
            "findings": [
                _finding(
                    "CRYPTO-HASH-001",
                    "Exposed MD5 Hash",
                    "CRITICAL",
                    role="authentication_material",
                    attack_demonstrated="dictionary_attack",
                    attack_result="admin123",
                    path="data[0].User.password",
                    cwe="CWE-327",
                    owasp="A02:2021 - Cryptographic Failures",
                    attack_chain=["1. Extraer hash", "2. Romper hash", "3. Login"],
                ),
                _finding(
                    "CRYPTO-HASH-002",
                    "Exposed SHA256 Hash",
                    "HIGH",
                    role="authentication_material",
                    path="data[1].User.password",
                    cwe="CWE-916",
                ),
                _finding(
                    "CRYPTO-KEY-001",
                    "Cryptographic Configuration Key",
                    "HIGH",
                    role="static_checksum",
                    path="config.csafHashValue",
                    cwe="CWE-328",
                ),
                {
                    "id": "CRYPTO-EXPOSURE",
                    "title": "Unauthenticated Admin Endpoint Exposure",
                    "severity": "HIGH",
                    "evidence": "HTTP 200 sin credenciales",
                    "cwe": "CWE-306",
                    "owasp": "A01:2021 - Broken Access Control",
                    "context": {"role": "information_disclosure"},
                },
            ],
        }
        self.executions = [
            {"tool": "crypto_inspector", "endpoint": ENDPOINT, "command": COMMAND, "output": json.dumps(self.report)}
        ]

    def _merge(self, llm_vulnerabilities=None):
        strategy = CryptoValidationStrategy()
        evidence = ValidationEvidence(executed_commands=self.executions)
        return strategy.merge_findings(
            {"vulnerabilities": llm_vulnerabilities or []}, evidence, "test-task"
        )

    def test_dictionary_attack_becomes_critical_with_recovered_password(self):
        merged = self._merge()
        critical = [v for v in merged["vulnerabilities"] if v["severity"] == "CRITICAL"]

        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["attack_result"], "admin123")
        self.assertIn("Contraseña recuperada: admin123", critical[0]["evidence"])
        self.assertEqual(critical[0]["cwe"], "CWE-327")
        self.assertEqual(critical[0]["attack_chain"], ["1. Extraer hash", "2. Romper hash", "3. Login"])

    def test_findings_are_sorted_critical_first(self):
        severities = [v["severity"] for v in self._merge()["vulnerabilities"]]
        self.assertEqual(severities, sorted(severities, key=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index))

    def test_static_checksum_is_downgraded_to_low(self):
        merged = self._merge()
        checksum = [v for v in merged["vulnerabilities"] if v["context_role"] == "static_checksum"]
        self.assertEqual(len(checksum), 1)
        self.assertEqual(checksum[0]["severity"], "LOW")

    def test_cwe_and_owasp_are_taken_verbatim_from_tool(self):
        merged = self._merge()
        exposure = [v for v in merged["vulnerabilities"] if v["finding_id"] == "CRYPTO-EXPOSURE"]
        self.assertEqual(exposure[0]["cwe"], "CWE-306")
        self.assertEqual(exposure[0]["owasp"], "A01:2021 - Broken Access Control")

    def test_llm_duplicate_on_same_endpoint_is_discarded(self):
        merged = self._merge(
            [
                {
                    "type": "Cryptographic Failure",
                    "severity": "HIGH",
                    "endpoint": "http://juice-shop-target:3000/rest/memories/",
                    "evidence": "duplicado del LLM",
                }
            ]
        )
        types = [v["type"] for v in merged["vulnerabilities"]]
        self.assertNotIn("Cryptographic Failure", types)
        self.assertEqual(len(types), len(self.report["findings"]))

    def test_new_fields_survive_the_pydantic_contract(self):
        output = build_validate_output_from_dict(
            self._merge(),
            "http://juice-shop:3000",
            "2026-10-28T00:00:00+00:00",
            self.executions,
        )
        critical = [v for v in output.vulnerabilities if v.severity == "CRITICAL"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].attack_result, "admin123")
        self.assertEqual(critical[0].cwe, "CWE-327")
        self.assertEqual(critical[0].context_role, "authentication_material")
        self.assertTrue(critical[0].attack_chain)


if __name__ == "__main__":
    unittest.main()
