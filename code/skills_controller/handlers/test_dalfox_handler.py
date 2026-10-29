import shlex
import unittest

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


if __name__ == "__main__":
    unittest.main()
