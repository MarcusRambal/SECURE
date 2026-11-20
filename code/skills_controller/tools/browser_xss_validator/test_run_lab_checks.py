import unittest

from run_lab_checks import build_plan, classify, test_cases


class BrowserXssLabCheckTests(unittest.TestCase):
    def test_matrix_has_expected_independent_flag_combinations(self):
        self.assertEqual(
            [(name, reflected, stored) for name, reflected, stored in test_cases()],
            [
                ("ambas-vulnerables", True, True),
                ("solo-almacenado-vulnerable", False, True),
                ("solo-reflejado-vulnerable", True, False),
                ("ambas-seguras", False, False),
            ],
        )

    def test_stored_plan_overrides_both_write_and_verification_requests(self):
        plan = build_plan(
            "http://weak-page:3009", "stored", reflected=False, stored=True
        )

        self.assertEqual(
            plan["request_headers"]["x-vulnerability-override"],
            "XSS_REFLECTED_SEARCH=false,XSS_STORED_CONTACT=true",
        )
        self.assertEqual(
            plan["verification_request"]["headers"]["x-vulnerability-override"],
            "XSS_REFLECTED_SEARCH=false,XSS_STORED_CONTACT=true",
        )
        self.assertEqual(
            plan["request_headers"]["x-weak-page-xss-validation"],
            "stored-contact",
        )

    def test_classifies_only_expected_tool_results_as_conclusive(self):
        base = {
            "tool": "browserXssValidator",
            "target": "http://weak-page:3009",
            "mode": "stored_dom",
            "cleanup": "success",
        }

        self.assertEqual(
            classify({**base, "outcome": "VULNERABLE"}, 0, "stored",
                     "http://weak-page:3009"),
            "VULNERABLE",
        )
        self.assertEqual(
            classify({**base, "outcome": "NO_XSS"}, 0, "stored",
                     "http://weak-page:3009"),
            "NO_XSS",
        )
        self.assertEqual(
            classify({**base, "outcome": "VULNERABLE", "cleanup": "failed"},
                     0, "stored", "http://weak-page:3009"),
            "INCONCLUSO",
        )
        self.assertEqual(
            classify({**base, "outcome": "INCONCLUSIVE"}, 0, "stored",
                     "http://weak-page:3009"),
            "INCONCLUSO",
        )


if __name__ == "__main__":
    unittest.main()
