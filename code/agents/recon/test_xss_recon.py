import unittest

from helpers import build_recon_output_from_dict, build_xss_recon_context


class XssReconTests(unittest.TestCase):
    def test_xss_context_and_target_preserve_observed_post_request(self):
        crawler_data = {
            "navigation": {
                "endpoints": [
                    {
                        "template": "https://example.test/comments",
                        "sample_urls": ["https://example.test/comments"],
                        "methods": ["POST"],
                    }
                ]
            }
        }
        deep_crawler_data = {
            "entry_points": [
                {
                    "id": "request-1",
                    "method": "POST",
                    "url": "https://example.test/comments",
                    "path": "/comments",
                    "headers": {
                        "content-type": "application/x-www-form-urlencoded",
                        "cookie": "session=private",
                    },
                    "body": "comment=hello",
                    "response": {"status": 201},
                }
            ]
        }
        context = build_xss_recon_context(
            crawler_data,
            deep_crawler_data,
            ["https://example.test/comments"],
            [{"name": "dalfox"}],
        )
        output = build_recon_output_from_dict(
            {
                "high_priority_targets": [
                    {
                        "target_id": "target-1",
                        "request_id": "request-1",
                        "endpoint": "https://example.test/comments",
                        "method": "POST",
                        "recommended_tool": "dalfox",
                    }
                ]
            },
            "https://example.test",
            "xss",
            deep_crawler_data,
        )

        self.assertEqual(context["captured_entry_points"][0]["body"], "comment=hello")
        self.assertNotIn("cookie", context["captured_entry_points"][0]["headers"])
        target = output.high_priority_targets[0]
        self.assertEqual(target.request_id, "request-1")
        self.assertEqual(target.request["method"], "POST")
        self.assertEqual(target.request["body"], "comment=hello")
        self.assertEqual(target.recommended_tool, "dalfox")


if __name__ == "__main__":
    unittest.main()
