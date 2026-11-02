import unittest

from helpers import (
    build_recon_output_from_dict,
    extract_urls_from_crawler,
    extract_urls_from_deep_crawler,
    normalize_weak_page_crawler_report,
)


class WeakPageReconTests(unittest.TestCase):
    def test_normalizes_weak_page_report_for_recon_consumers(self):
        report = {
            "tool": "weakPageCrawler",
            "requests": [
                {
                    "id": "req_0001",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=cake",
                    "path": "/api/products",
                    "resource_type": "xhr",
                    "request_headers": {"Accept": "application/json"},
                    "request_body": None,
                    "response": {"status": 200},
                },
                {
                    "id": "req_0002",
                    "method": "POST",
                    "url": "http://weak-page:3009/api/contact",
                    "path": "/api/contact",
                    "resource_type": "xhr",
                    "request_headers": {"Content-Type": "application/json"},
                    "request_body": {
                        "captured": True,
                        "content_type": "application/json",
                        "data": {"message": "hello"},
                    },
                    "response": {"status": 201},
                },
                {
                    "id": "req_0003",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?category=Tartas",
                    "path": "/api/products?category=Tartas",
                    "resource_type": "fetch",
                    "request_headers": {"Accept": "application/json"},
                    "request_body": None,
                    "query_values": {"category": "Tartas"},
                    "response": {"status": 200},
                },
            ],
            "observed_endpoints": [
                {
                    "method": "GET",
                    "path": "/api/products",
                    "request_ids": ["req_0001"],
                }
            ],
            "api_routes_from_source": [
                {"method": "POST", "path": "/api/contact"}
            ],
            "frontend_routes": {
                "declared": [{"template": "/catalog"}],
                "visited": [{"path": "/catalog", "url": "http://weak-page:3009/#/catalog", "forms": []}],
            },
            "interactions": [],
        }

        crawler_data, deep_crawler_data = normalize_weak_page_crawler_report(
            report, "http://weak-page:3009"
        )

        self.assertEqual(len(crawler_data["captured_requests"]), 3)
        self.assertEqual(crawler_data["navigation"]["endpoints"][0]["methods"], ["GET"])
        self.assertIn(
            "http://weak-page:3009/api/products?q=cake",
            extract_urls_from_crawler(crawler_data),
        )
        self.assertIn(
            "http://weak-page:3009/api/contact",
            extract_urls_from_deep_crawler(deep_crawler_data),
        )
        post_request = deep_crawler_data["entry_points"][1]
        self.assertEqual(post_request["headers"]["content-type"], "application/json")
        self.assertEqual(post_request["body"], {"message": "hello"})
        self.assertEqual(post_request["response"]["status"], 201)
        self.assertIsNone(deep_crawler_data["entry_points"][2]["body"])
        self.assertEqual(
            deep_crawler_data["entry_points"][2]["query_parameters"],
            {"category": "Tartas"},
        )
        recon_output = build_recon_output_from_dict(
            {
                "recon_summary": {
                    "target_url": "http://weak-page:3009",
                    "attack_type_filter": "sqli",
                    "total_targets_identified": 1,
                    "total_requests_captured": 2,
                },
                "high_priority_targets": [
                    {
                        "target_id": "target_001",
                        "request_id": "req_0002",
                        "vulnerability_target": "Captured POST request",
                        "endpoint": post_request["url"],
                        "method": "POST",
                        "recommended_tool": "sqlmap",
                    }
                ],
            },
            "http://weak-page:3009",
            "sqli",
            deep_crawler_data,
        )
        self.assertEqual(recon_output.high_priority_targets[0].request_id, "req_0002")
        self.assertEqual(
            recon_output.high_priority_targets[0].request["body"],
            {"message": "hello"},
        )
        self.assertEqual(
            crawler_data["navigation"]["states"][0]["url"],
            "http://weak-page:3009/#/catalog",
        )


if __name__ == "__main__":
    unittest.main()
