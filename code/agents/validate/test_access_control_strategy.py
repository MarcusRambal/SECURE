import json
import unittest

from attack_validators import (
    AccessControlValidationStrategy,
    ValidationEvidence,
    _access_control_candidates,
    _normalize_access_control_endpoint,
)
from helpers import build_validate_output_from_dict

BASE_URL = "http://juice-shop:3000"
ENDPOINT = "http://juice-shop:3000/rest/basket/1"
COMMAND = (
    "curl -s -H 'Authorization: Bearer $ATTACKER_TOKEN' "
    "http://juice-shop:3000/rest/basket/1"
)


def _finding(finding_id: str, title: str, severity: str) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "endpoint": ENDPOINT,
        "evidence": f"Evidencia de {title}",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "attack_chain": ["1. Autenticarse como atacante", "2. Leer el recurso de la víctima"],
    }


class AccessControlMergeFindingsTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "tool": "access_control_prober",
            "findings": [
                _finding("BAC-IDOR-001", "IDOR (Insecure Direct Object Reference)", "CRITICAL"),
                _finding("BAC-VERT-001", "Vertical Privilege Escalation", "CRITICAL"),
            ],
        }
        self.executions = [
            {
                "tool": "access_control_prober",
                "endpoint": ENDPOINT,
                "command": COMMAND,
                "base_url": BASE_URL,
                "victim_id": "1",
                "target_id": "target_001",
                "request_id": "entry_0001",
                "output": json.dumps(self.report),
            }
        ]

    def test_tool_findings_are_promoted_with_active_confirmation(self):
        strategy = AccessControlValidationStrategy()
        evidence = ValidationEvidence(executed_commands=self.executions)
        merged = strategy.merge_findings({"vulnerabilities": []}, evidence, "task")

        self.assertEqual(len(merged["vulnerabilities"]), 2)
        first = merged["vulnerabilities"][0]
        self.assertEqual(first["severity"], "CRITICAL")
        self.assertEqual(first["tools_used"], ["access_control_prober"])
        self.assertEqual(first["finding_id"], "BAC-IDOR-001")
        self.assertEqual(first["cwe"], "CWE-639")
        self.assertIn("$ATTACKER_TOKEN", first["reproducible_command"])
        self.assertEqual(first["attack_chain"][0], "1. Autenticarse como atacante")

    def test_llm_cannot_downgrade_tool_finding(self):
        strategy = AccessControlValidationStrategy()
        evidence = ValidationEvidence(executed_commands=self.executions)
        merged = strategy.merge_findings(
            {
                "vulnerabilities": [
                    {
                        "type": "IDOR (Insecure Direct Object Reference)",
                        "severity": "LOW",
                        "endpoint": ENDPOINT,
                        "evidence": "resumen",
                        "reproducible_command": "echo x",
                        "confidence": "LOW",
                        "tools_used": ["access_control_prober"],
                    }
                ]
            },
            evidence,
            "task",
        )

        idor = [
            item for item in merged["vulnerabilities"] if item["finding_id"] == "BAC-IDOR-001"
        ][0]
        self.assertEqual(idor["severity"], "CRITICAL")

    def test_output_contract_preserves_access_control_fields(self):
        strategy = AccessControlValidationStrategy()
        evidence = ValidationEvidence(executed_commands=self.executions)
        merged = strategy.merge_findings({"vulnerabilities": []}, evidence, "task")

        output = build_validate_output_from_dict(
            merged, BASE_URL, "2026-01-01T00:00:00+00:00", self.executions
        )
        finding = output.vulnerabilities[0]
        self.assertEqual(finding.tools_used, ["access_control_prober"])
        self.assertEqual(finding.finding_id, "BAC-IDOR-001")
        self.assertEqual(finding.attack_chain[0], "1. Autenticarse como atacante")
        self.assertIn("$ATTACKER_TOKEN", finding.reproducible_command)


class AccessControlEndpointTests(unittest.TestCase):
    def test_absolute_endpoint_is_reduced_to_path(self):
        self.assertEqual(
            _normalize_access_control_endpoint(BASE_URL, ENDPOINT), "/rest/basket/1"
        )

    def test_collection_endpoint_gets_id_candidate(self):
        self.assertEqual(
            _access_control_candidates("/api/Users"),
            ["/api/Users", "/api/Users/{id}"],
        )

    def test_config_endpoint_does_not_get_id_candidate(self):
        self.assertEqual(
            _access_control_candidates("/rest/admin/application-configuration"),
            ["/rest/admin/application-configuration"],
        )


if __name__ == "__main__":
    unittest.main()
