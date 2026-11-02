import shlex
import json
import unittest

from handlers.browser_xss_handler import handle_browser_xss_args
from handlers.dalfox_handler import handle_dalfox_args

class DalfoxHandlerTests(unittest.TestCase):
    def test_get_target_uses_scan_mode(self):
        args, input_files = handle_dalfox_args(
            {"target_url": "https://example.test/search?q=hello"}
        )

        self.assertEqual(
            shlex.split(args["target_arg"]),
            ["scan", "https://example.test/search?q=hello"],
        )
        self.assertEqual(
            shlex.split(args["extra_flags"]),
            ["--format", "json", "--no-color"],
        )
        self.assertEqual(input_files, {})

    def test_post_target_uses_raw_http_input_and_preserves_request(self):
        request = {
            "url": "https://example.test/comments",
            "method": "POST",
            "headers": {
                "host": "example.test",
                "content-type": "application/x-www-form-urlencoded",
            },
            "body": "comment=hello",
        }
        args, input_files = handle_dalfox_args({"request": request})

        self.assertEqual(
            args["target_arg"],
            "scan --input-type raw-http /tmp/dalfox-req.txt",
        )
        self.assertEqual(
            shlex.split(args["extra_flags"]),
            ["--format", "json", "--no-color"],
        )
        self.assertIn("comment=hello", input_files["/tmp/dalfox-req.txt"])

    def test_get_cookie_is_kept_in_raw_request_not_logged_command(self):
        args, input_files = handle_dalfox_args(
            {
                "target_url": "https://example.test/search?q=hello",
                "request": {
                    "method": "GET",
                    "url": "https://example.test/search?q=hello",
                    "headers": {"Cookie": "session=private"},
                },
            }
        )

        self.assertEqual(
            args["target_arg"],
            "scan --input-type raw-http /tmp/dalfox-req.txt",
        )
        self.assertNotIn("private", args["target_arg"])
        self.assertIn(
            "Cookie: session=private",
            input_files["/tmp/dalfox-req.txt"],
        )

    def test_synthetic_weak_page_write_is_not_replayed_by_dalfox(self):
        args, input_files = handle_dalfox_args(
            {
                "request": {
                    "url": "http://weak-page:3009/api/contact",
                    "method": "POST",
                    "headers": {
                        "content-type": "application/json",
                        "x-weak-page-crawler": "synthetic-probe",
                    },
                    "body": {"message": "Synthetic probe"},
                }
            }
        )

        self.assertTrue(args["skip_execution"])
        self.assertIn("evitar persistir", args["reason"])
        self.assertEqual(input_files, {})


class BrowserXssHandlerTests(unittest.TestCase):
    def test_accepts_a_same_origin_declarative_plan(self):
        plan = {
            "mode": "reflected_dom",
            "source_url": "https://example.test/search",
            "parameter": "q",
            "input_selector": "input[name=q]",
            "request": {"method": "GET", "path": "/api/search"},
        }
        args, files = handle_browser_xss_args(
            {
                "target_url": "https://example.test",
                "plan": plan,
            }
        )

        self.assertEqual(shlex.split(args["target_arg"])[:2], ["--target-url", "https://example.test"])
        self.assertEqual(json.loads(shlex.split(args["target_arg"])[3]), plan)
        self.assertEqual(files, {})

    def test_rejects_cross_origin_and_stored_plan_without_cleanup(self):
        cross_origin, _ = handle_browser_xss_args(
            {
                "target_url": "https://example.test",
                "plan": {
                    "mode": "reflected_dom",
                    "source_url": "https://other.test/",
                    "parameter": "q",
                    "input_selector": "input[name=q]",
                    "request": {"method": "GET", "path": "/search"},
                },
            }
        )
        stored_without_cleanup, _ = handle_browser_xss_args(
            {
                "target_url": "https://example.test",
                "plan": {
                    "mode": "stored_dom",
                    "source_url": "https://example.test/contact",
                    "parameter": "message",
                    "form_selector": "form",
                    "form_fields": ["message"],
                    "request": {"method": "POST", "path": "/contact"},
                    "verification_url_template": "/view/{id}?marker={marker}",
                },
            }
        )

        self.assertTrue(cross_origin["skip_execution"])
        self.assertTrue(stored_without_cleanup["skip_execution"])


if __name__ == "__main__":
    unittest.main()
