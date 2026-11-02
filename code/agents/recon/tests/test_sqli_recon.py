import unittest

from helpers import (
    build_recon_output_from_dict,
    build_sqli_fallback_output,
    build_sqli_recon_context,
    clean_scraping_report,
    ensure_sqli_entry_point_coverage,
)


class SqliReconTests(unittest.TestCase):
    def test_get_query_parameters_are_sqli_inputs_without_fabricated_body(self):
        deep_crawler_data = {
            "entry_points": [
                {
                    "id": "search",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=synthetic",
                    "headers": {"accept": "application/json"},
                    "body": None,
                },
                {
                    "id": "category",
                    "method": "GET",
                    "url": (
                        "http://weak-page:3009/api/products?category=Tartas"
                    ),
                    "headers": {"accept": "application/json"},
                    "body": None,
                },
                {
                    "id": "no-input",
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products",
                    "headers": {"accept": "application/json"},
                    "body": None,
                },
            ]
        }

        scraping_report = clean_scraping_report(
            {
                "target": "http://weak-page:3009",
                "observed_endpoints": [],
                "requests": [
                    {
                        "id": request["id"],
                        "method": request["method"],
                        "url": request["url"],
                        "path": request["url"].split("?", maxsplit=1)[0],
                        "request_line": f'{request["method"]} {request["url"]} HTTP/1.1',
                        "query_parameters": list(request.get("query_parameters", {})),
                        "query_values": request.get("query_parameters", {}),
                        "resource_type": "xhr",
                        "request_headers": request["headers"],
                        "request_body": None,
                        "response": {
                            "status": 200,
                            "status_text": "OK",
                            "headers": {},
                            "body": {
                                "captured": False,
                                "content_type": "",
                                "data": None,
                            },
                        },
                        "observed_on": [],
                    }
                    for request in deep_crawler_data["entry_points"]
                ],
            }
        )
        context = build_sqli_recon_context(
            scraping_report,
            [],
        )
        inputs = context["sqli_input_entry_points"]
        self.assertEqual([item["id"] for item in inputs], ["search", "category"])
        self.assertIsNone(inputs[0]["body"])
        self.assertEqual(inputs[0]["query_parameters"], {"q": "synthetic"})
        self.assertEqual(
            inputs[1]["query_parameters"],
            {"category": "Tartas"},
        )

        covered = ensure_sqli_entry_point_coverage(
            {"high_priority_targets": []},
            deep_crawler_data,
        )
        fallback = build_sqli_fallback_output(
            "http://weak-page:3009",
            deep_crawler_data,
        )
        for output in (covered, fallback):
            self.assertEqual(
                [target["request_id"] for target in output["high_priority_targets"]],
                ["search", "category"],
            )
        self.assertIsNone(covered["high_priority_targets"][0]["request"]["body"])

    def test_normalized_report_drops_unobserved_targets_and_covers_captured_inputs(self):
        requests = [
            {
                "id": "search",
                "method": "GET",
                "url": "http://weak-page:3009/api/products?q=cake",
                "path": "/api/products",
                "request_line": "GET /api/products?q=cake HTTP/1.1",
                "query_parameters": ["q"],
                "query_values": {"q": "cake"},
                "resource_type": "xhr",
                "request_headers": {"accept": "application/json"},
                "request_body": None,
                "response": {
                    "status": 200,
                    "status_text": "OK",
                    "headers": {},
                    "body": {
                        "captured": False,
                        "content_type": "",
                        "data": None,
                    },
                },
                "observed_on": [],
            },
            {
                "id": "login",
                "method": "POST",
                "url": "http://weak-page:3009/api/auth/login",
                "path": "/api/auth/login",
                "request_line": "POST /api/auth/login HTTP/1.1",
                "query_parameters": [],
                "query_values": {},
                "resource_type": "xhr",
                "request_headers": {"content-type": "application/json"},
                "request_body": {
                    "captured": True,
                    "content_type": "application/json",
                    "data": {"email": "user@example.test"},
                },
                "response": {
                    "status": 200,
                    "status_text": "OK",
                    "headers": {},
                    "body": {
                        "captured": False,
                        "content_type": "",
                        "data": None,
                    },
                },
                "observed_on": [],
            },
        ]
        clean_report = clean_scraping_report(
            {
                "target": "http://weak-page:3009",
                "observed_endpoints": [],
                "requests": requests,
            }
        )
        context = build_sqli_recon_context(clean_report, [])
        llm_output = {
            "recon_summary": {
                "target_url": "http://juice-shop:3000",
                "attack_type_filter": "sqli",
                "total_targets_identified": 2,
                "total_requests_captured": 2,
            },
            "high_priority_targets": [
                {
                    "target_id": "invented",
                    "request_id": "not-observed",
                    "endpoint": "http://juice-shop:3000/rest/products/search",
                    "method": "GET",
                    "recommended_tool": "sqlmap",
                },
                {
                    "target_id": "misdirected",
                    "request_id": "search",
                    "endpoint": "http://juice-shop:3000/rest/products/search",
                    "method": "GET",
                    "recommended_tool": "sqlmap",
                },
            ],
        }

        rectified = ensure_sqli_entry_point_coverage(llm_output, context)
        fallback = build_sqli_fallback_output(
            "http://weak-page:3009",
            context,
        )
        output = build_recon_output_from_dict(
            rectified,
            "http://weak-page:3009",
            "sqli",
            context,
        )

        self.assertEqual(output.recon_summary.target_url, "http://weak-page:3009")
        self.assertEqual(
            {target.request_id for target in output.high_priority_targets},
            {"search", "login"},
        )
        self.assertEqual(
            {target.endpoint for target in output.high_priority_targets},
            {request["url"] for request in requests},
        )
        self.assertTrue(
            all(
                "juice-shop" not in target.endpoint
                for target in output.high_priority_targets
            )
        )
        self.assertEqual(
            {target["request_id"] for target in fallback["high_priority_targets"]},
            {"search", "login"},
        )


if __name__ == "__main__":
    unittest.main()
