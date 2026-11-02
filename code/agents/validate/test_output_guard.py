import unittest

from output_guard import guard_validate_output


class ValidateOutputGuardTests(unittest.TestCase):
    def test_merges_xss_aliases_and_payload_urls_for_the_same_parameter(self):
        output = {
            "target_url": "http://wackopicko",
            "vulnerabilities": [
                {
                    "type": "XSS",
                    "severity": "HIGH",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "parameter": None,
                    "evidence": "Dalfox reported a verified POC inHTML",
                    "reproducible_command": "Comando no verificado",
                    "confidence": "MEDIUM",
                    "tools_used": ["dalfox"],
                },
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php?name=%3Cscript%3E",
                    "parameter": "name",
                    "evidence": "Dalfox reported a verified XSS proof of concept",
                    "reproducible_command": "dalfox scan http://wackopicko/guestbook.php",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
            ],
        }

        guarded, removed = guard_validate_output(output)

        self.assertEqual(removed, 1)
        self.assertEqual(len(guarded["vulnerabilities"]), 1)
        finding = guarded["vulnerabilities"][0]
        self.assertEqual(finding["type"], "Cross-Site Scripting (XSS)")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["parameter"], "name")
        self.assertEqual(finding["tools_used"], ["dalfox"])
        self.assertIn("verified POC inHTML", finding["evidence"])
        self.assertIn("verified XSS proof of concept", finding["evidence"])
        self.assertEqual(
            finding["reproducible_command"],
            "dalfox scan http://wackopicko/guestbook.php",
        )

    def test_consolidates_parameters_for_the_same_endpoint_and_preserves_them(self):
        output = {
            "vulnerabilities": [
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php?name=%3Cscript%3E",
                    "parameter": "name",
                    "evidence": "verified POC for name",
                    "verification_steps": "Verify the name input.",
                    "reproducible_command": "dalfox name",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
                {
                    "type": "XSS",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php?message=%3Cscript%3E",
                    "parameter": "message",
                    "evidence": "verified POC for message",
                    "verification_steps": "Verify the message input.",
                    "reproducible_command": "dalfox message",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
                {
                    "type": "XSS",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/pictures/search.php?query=%3Csvg%3E",
                    "parameter": "query",
                    "method": "GET",
                    "evidence": "verified POC for query",
                    "verification_steps": "Verify the query input.",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
            ]
        }

        guarded, removed = guard_validate_output(output)

        self.assertEqual(removed, 1)
        self.assertEqual(len(guarded["vulnerabilities"]), 2)
        guestbook = guarded["vulnerabilities"][0]
        self.assertEqual(
            guestbook["parameter"], "name, message"
        )
        self.assertIn("Verify the name input.", guestbook["verification_steps"])
        self.assertIn("Verify the message input.", guestbook["verification_steps"])
        self.assertEqual(
            guarded["vulnerabilities"][1]["endpoint"],
            "http://wackopicko/pictures/search.php?query=%3Csvg%3E",
        )

    def test_preserves_distinct_xss_subtypes_at_the_same_endpoint(self):
        output = {
            "vulnerabilities": [
                {
                    "type": "Reflected XSS",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "parameter": "name",
                    "evidence": "Reflected payload",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
                {
                    "type": "Stored Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "parameter": "name",
                    "evidence": "Stored payload",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
            ]
        }

        guarded, removed = guard_validate_output(output)

        self.assertEqual(removed, 0)
        self.assertEqual(len(guarded["vulnerabilities"]), 2)

    def test_consolidates_methods_for_the_same_endpoint_and_preserves_them(self):
        output = {
            "vulnerabilities": [
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "parameter": "comment",
                    "method": "GET",
                    "evidence": "GET verified",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
                {
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "endpoint": "http://wackopicko/guestbook.php",
                    "parameter": "comment",
                    "method": "POST",
                    "evidence": "POST verified",
                    "confidence": "HIGH",
                    "tools_used": ["dalfox"],
                },
            ]
        }

        guarded, removed = guard_validate_output(output)

        self.assertEqual(removed, 1)
        self.assertEqual(len(guarded["vulnerabilities"]), 1)
        self.assertEqual(guarded["vulnerabilities"][0]["method"], "GET, POST")

    def test_rejects_malformed_confirmed_findings_explicitly(self):
        with self.assertRaisesRegex(ValueError, "must have an endpoint"):
            guard_validate_output(
                {"vulnerabilities": [{"type": "XSS", "severity": "HIGH"}]}
            )


if __name__ == "__main__":
    unittest.main()
