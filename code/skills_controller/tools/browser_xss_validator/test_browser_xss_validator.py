import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

from browser_xss_validator import _validate_plan, run_validation


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

    def test_confirmed_result_reports_the_exact_value_sent(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "parameter": "q",
            "input_selector": "input[name=q]",
            "request": {"method": "GET", "path": "/api/search"},
        }
        response = SimpleNamespace(status=200, text=lambda: "marker in response")
        page = MagicMock()
        page.evaluate.return_value = True
        page.expect_response.return_value.__enter__.return_value.value = response
        browser = MagicMock()
        browser.new_context.return_value.new_page.return_value = page
        playwright = MagicMock()
        playwright.chromium.launch.return_value = browser
        sync_api = ModuleType("playwright.sync_api")
        sync_api.sync_playwright = MagicMock()
        sync_api.sync_playwright.return_value.__enter__.return_value = playwright
        playwright_module = ModuleType("playwright")

        with (
            patch.dict("sys.modules", {
                "playwright": playwright_module,
                "playwright.sync_api": sync_api,
            }),
            patch("browser_xss_validator.secrets.token_hex", return_value="abc123"),
        ):
            result = run_validation("https://example.test", plan)

        value_sent = page.locator.return_value.first.fill.call_args.args[0]
        self.assertEqual(result["outcome"], "VULNERABLE")
        self.assertEqual(result["proof_value"], value_sent)
        self.assertIn("xss-probe-abc123", value_sent)

    def test_unconfirmed_result_does_not_report_a_proof_as_executed(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "parameter": "q",
            "input_selector": "input[name=q]",
            "request": {"method": "GET", "path": "/api/search"},
        }
        response = SimpleNamespace(status=200, text=lambda: "no marker")
        page = MagicMock()
        page.evaluate.return_value = False
        page.expect_response.return_value.__enter__.return_value.value = response
        browser = MagicMock()
        browser.new_context.return_value.new_page.return_value = page
        playwright = MagicMock()
        playwright.chromium.launch.return_value = browser
        sync_api = ModuleType("playwright.sync_api")
        sync_api.sync_playwright = MagicMock()
        sync_api.sync_playwright.return_value.__enter__.return_value = playwright

        with patch.dict("sys.modules", {
            "playwright": ModuleType("playwright"),
            "playwright.sync_api": sync_api,
        }):
            result = run_validation("https://example.test", plan)

        self.assertEqual(result["outcome"], "NO_XSS")
        self.assertNotIn("proof_value", result)


if __name__ == "__main__":
    unittest.main()
