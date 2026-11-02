import unittest

from browser_xss_validator import _validate_plan


class BrowserXssValidatorPlanTests(unittest.TestCase):
    def test_accepts_generic_reflected_plan(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "parameter": "q",
            "input_selector": "input[name=q]",
            "request": {"method": "GET", "path": "/api/search"},
        }

        self.assertEqual(
            _validate_plan("https://example.test", plan),
            ("https://example.test/api/search", "GET"),
        )

    def test_rejects_origin_relative_path_that_resolves_off_target(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "parameter": "q",
            "input_selector": "input[name=q]",
            "request": {"method": "GET", "path": "//other.test/search"},
        }

        with self.assertRaises(ValueError):
            _validate_plan("https://example.test", plan)

    def test_accepts_stored_plan_with_origin_relative_cleanup(self):
        plan = {
            "mode": "stored_dom",
            "source_url": "https://example.test/contact",
            "parameter": "message",
            "marker_prefix": "synthetic-probe-",
            "form_selector": "form",
            "form_fields": ["message"],
            "request": {"method": "POST", "path": "/api/contact"},
            "verification_url_template": "/messages/{id}?marker={marker}",
            "verification_request": {
                "method": "GET",
                "path_template": "/api/contact/{id}",
            },
            "cleanup": {
                "method": "DELETE",
                "path_template": "/api/contact/{id}",
                "body": {"marker": "{marker}"},
            },
        }

        self.assertEqual(
            _validate_plan("https://example.test", plan),
            ("https://example.test/api/contact", "POST"),
        )


if __name__ == "__main__":
    unittest.main()
