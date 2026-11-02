import unittest

from helpers import (
    build_recon_output_from_dict,
    build_xss_recon_context,
    ensure_xss_entry_point_coverage,
    normalize_weak_page_crawler_report,
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
                    "observed_on": ["https://example.test/contact"],
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

    def test_weak_page_xss_plan_keeps_only_search_and_contact_surfaces(self):
        deep_crawler_data = {
            "target": "http://weak-page:3009",
            "entry_points": [
                {
                    "id": "search-q",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=cake&category=Tartas",
                    "headers": {},
                    "body": None,
                    "observed_on": ["http://weak-page:3009/#/catalog"],
                },
                {
                    "id": "category-only",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?category=Tartas",
                    "headers": {},
                    "body": None,
                },
                {
                    "id": "contact",
                    "method": "POST",
                    "url": "http://weak-page:3009/api/contact",
                    "headers": {"content-type": "application/json"},
                    "body": {"name": "Synthetic", "message": "Synthetic probe"},
                    "observed_on": ["http://weak-page:3009/#/contact"],
                },
                {
                    "id": "login",
                    "method": "POST",
                    "url": "http://weak-page:3009/api/auth/login",
                    "headers": {"content-type": "application/json"},
                    "body": {"email": "[REDACTED]", "password": "[REDACTED]"},
                },
            ],
        }
        context = build_xss_recon_context(
            {},
            deep_crawler_data,
            [],
            [{"name": "dalfox"}],
        )
        covered = ensure_xss_entry_point_coverage(
            {
                "high_priority_targets": [
                    {
                        "target_id": "irrelevant-category",
                        "endpoint": (
                            "http://weak-page:3009/api/products"
                            "?category=Tartas"
                        ),
                        "method": "GET",
                        "request": {
                            "method": "GET",
                            "url": (
                                "http://weak-page:3009/api/products"
                                "?category=Tartas"
                            ),
                            "body": None,
                        },
                    }
                ]
            },
            deep_crawler_data,
        )

        self.assertEqual(
            {item["id"] for item in context["captured_entry_points"]},
            {"search-q", "contact"},
        )
        self.assertEqual(
            {item["request_id"] for item in covered["high_priority_targets"]},
            {"search-q", "contact"},
        )
        self.assertIn("validation_capability", context)
        output = build_recon_output_from_dict(
            covered,
            "http://weak-page:3009",
            "xss",
            deep_crawler_data,
        )
        self.assertTrue(
            all(
                target.recommended_tool == "browserXssValidator"
                and target.validation_plan
                for target in output.high_priority_targets
            )
        )
        self.assertEqual(
            {target.validation_plan["mode"] for target in output.high_priority_targets},
            {"reflected_dom", "stored_dom"},
        )
        stored_plan = next(
            target.validation_plan
            for target in output.high_priority_targets
            if target.validation_plan["mode"] == "stored_dom"
        )
        self.assertEqual(stored_plan["form_fields"], ["message", "name"])
        self.assertEqual(stored_plan["marker_prefix"], "weakpage-xss-probe-")
        self.assertIn(
            "x-weak-page-xss-validation",
            stored_plan["request_headers"],
        )
        self.assertEqual(stored_plan["cleanup"]["method"], "DELETE")

    def test_weak_page_observed_interactions_reach_generic_browser_plans(self):
        requests = [
            {
                "id": f"req_{index:04d}",
                "method": "GET",
                "url": f"http://weak-page:3009/api/products/{index}",
                "request_headers": {},
                "request_body": None,
                "observed_on": ["http://weak-page:3009/"],
            }
            for index in range(1, 41)
        ]
        requests.extend(
            [
                {
                    "id": "req_0041",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=synthetic",
                    "request_headers": {},
                    "request_body": None,
                    "observed_on": ["http://weak-page:3009/"],
                },
                {
                    "id": "req_0046",
                    "method": "POST",
                    "url": "http://weak-page:3009/api/contact",
                    "request_headers": {"content-type": "application/json"},
                    "request_body": {
                        "captured": True,
                        "content_type": "application/json",
                        "data": {
                            "name": "Synthetic",
                            "email": "test@example.invalid",
                            "subject": "Synthetic test",
                            "message": "Synthetic message",
                        },
                    },
                    "observed_on": ["http://weak-page:3009/"],
                },
            ]
        )
        report = {
            "requests": requests,
            "frontend_routes": {
                "visited": [
                    {
                        "path": "/catalog",
                        "url": "http://weak-page:3009/",
                    },
                    {
                        "path": "/contact",
                        "url": "http://weak-page:3009/",
                    },
                ],
                "declared": [
                    {"template": "/catalog", "visited": True},
                    {"template": "/contact", "visited": True},
                ],
            },
            "interactions": [
                {
                    "route": "/catalog",
                    "action": "search_input",
                    "request_ids": ["req_0041"],
                },
                {
                    "route": "/contact",
                    "action": "synthetic_form_submission",
                    "request_ids": ["req_0046"],
                },
            ],
        }

        crawler_data, deep_crawler_data = normalize_weak_page_crawler_report(
            report,
            "http://weak-page:3009",
        )
        context = build_xss_recon_context(
            crawler_data,
            deep_crawler_data,
            [],
            [{"name": "dalfox"}, {"name": "browserXssValidator"}],
        )
        covered = ensure_xss_entry_point_coverage(
            {"high_priority_targets": []},
            deep_crawler_data,
        )
        output = build_recon_output_from_dict(
            covered,
            "http://weak-page:3009",
            "xss",
            deep_crawler_data,
        )

        self.assertEqual(
            {entry["id"] for entry in context["captured_entry_points"]},
            {"req_0041", "req_0046"},
        )
        plans = {
            target.request_id: target.validation_plan
            for target in output.high_priority_targets
        }
        self.assertEqual(set(plans), {"req_0041", "req_0046"})
        self.assertEqual(plans["req_0041"]["source_url"], "http://weak-page:3009/#/catalog")
        self.assertEqual(plans["req_0046"]["source_url"], "http://weak-page:3009/#/contact")
        self.assertTrue(all(plan for plan in plans.values()))


if __name__ == "__main__":
    unittest.main()
