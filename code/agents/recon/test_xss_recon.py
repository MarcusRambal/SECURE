import unittest

from helpers import (
    build_recon_output_from_dict,
    build_xss_recon_context,
    ensure_xss_entry_point_coverage,
)


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

    def test_xss_coverage_adds_captured_query_and_form_requests(self):
        deep_crawler_data = {
            "entry_points": [
                {
                    "id": "request-get",
                    "method": "GET",
                    "url": "http://example.test/search.php?query=blah",
                    "headers": {"accept": "text/html"},
                    "body": None,
                },
                {
                    "id": "request-post",
                    "method": "POST",
                    "url": "http://example.test/submitname.php",
                    "headers": {"content-type": "application/x-www-form-urlencoded"},
                    "body": {"value": "test"},
                },
                {
                    "id": "request-no-input",
                    "method": "GET",
                    "url": "http://example.test/about.php",
                    "headers": {},
                    "body": None,
                },
            ]
        }

        covered = ensure_xss_entry_point_coverage(
            {"high_priority_targets": []},
            deep_crawler_data,
        )
        output = build_recon_output_from_dict(
            covered,
            "http://example.test",
            "xss",
            deep_crawler_data,
        )

        self.assertEqual(len(output.high_priority_targets), 2)
        self.assertEqual(
            {target.request_id for target in output.high_priority_targets},
            {"request-get", "request-post"},
        )
        self.assertTrue(
            all(target.recommended_tool == "dalfox" for target in output.high_priority_targets)
        )

    def test_xss_plan_filters_non_xss_targets_and_deduplicates_captured_requests(self):
        deep_crawler_data = {
            "entry_points": [
                {
                    "id": "search",
                    "method": "GET",
                    "url": "http://wackopicko/pictures/search.php?query=blah",
                    "headers": {},
                    "body": None,
                },
                {
                    "id": "view-1",
                    "method": "GET",
                    "url": "http://wackopicko/pictures/view.php?picid=3",
                    "headers": {},
                    "body": None,
                },
                {
                    "id": "view-2",
                    "method": "GET",
                    "url": "http://wackopicko/pictures/view.php?picid=4",
                    "headers": {},
                    "body": None,
                },
                {
                    "id": "guestbook",
                    "method": "POST",
                    "url": "http://wackopicko/guestbook.php",
                    "headers": {"content-type": "application/x-www-form-urlencoded"},
                    "body": "comment=hello",
                },
                {
                    "id": "guestbook-duplicate",
                    "method": "POST",
                    "url": "http://wackopicko/guestbook.php",
                    "headers": {"content-type": "application/x-www-form-urlencoded"},
                    "body": "comment=another-value",
                },
            ]
        }
        targets = [
            {
                "target_id": "entry_0001",
                "endpoint": "http://wackopicko/passcheck.php",
                "method": "GET",
                "recommended_tool": "sqlmap",
            },
            {
                "target_id": "target_xss_002",
                "request_id": "search",
                "endpoint": "http://wackopicko/pictures/search.php?query=blah",
                "method": "GET",
                "recommended_tool": "dalfox",
            },
            {
                "target_id": "target_xss_009",
                "request_id": "view-1",
                "endpoint": "http://wackopicko/pictures/view.php?picid=3",
                "method": "GET",
                "recommended_tool": "dalfox",
            },
        ]
        covered = ensure_xss_entry_point_coverage(
            {"high_priority_targets": targets},
            deep_crawler_data,
        )

        output = build_recon_output_from_dict(
            covered,
            "http://wackopicko",
            "xss",
            deep_crawler_data,
        )

        self.assertEqual(
            [
                (target.method, target.endpoint, target.recommended_tool)
                for target in output.high_priority_targets
            ],
            [
                (
                    "GET",
                    "http://wackopicko/pictures/search.php?query=blah",
                    "dalfox",
                ),
                (
                    "GET",
                    "http://wackopicko/pictures/view.php?picid=3",
                    "dalfox",
                ),
                ("POST", "http://wackopicko/guestbook.php", "dalfox"),
            ],
        )
        self.assertEqual(output.recon_summary.total_targets_identified, 3)


if __name__ == "__main__":
    unittest.main()
