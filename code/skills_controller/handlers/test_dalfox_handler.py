import unittest

from handlers.dalfox_handler import handle_dalfox_args

class DalfoxHandlerTests(unittest.TestCase):
    def test_get_target_uses_scan_mode(self):
        args, input_files = handle_dalfox_args(
            {"target_url": "https://example.test/search?q=hello"}
        )

        self.assertEqual(args["target_arg"], 'scan "https://example.test/search?q=hello"')
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
            'scan --input-type raw-http "/tmp/dalfox-req.txt"',
        )
        self.assertIn("comment=hello", input_files["/tmp/dalfox-req.txt"])


if __name__ == "__main__":
    unittest.main()
