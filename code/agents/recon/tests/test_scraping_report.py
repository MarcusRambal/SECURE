import unittest

from helpers import build_sqli_recon_context, clean_scraping_report


def _request(request_id, *, body=None, observed_on=None):
    return {
        "id": request_id,
        "method": "get",
        "url": "https://example.test/items?q=tea",
        "path": "/items",
        "request_line": "GET /items?q=tea HTTP/1.1",
        "query_parameters": ["q"],
        "query_values": {"q": "tea"},
        "resource_type": "xhr",
        "request_headers": {"accept": "application/json"},
        "request_body": body,
        "response": {
            "status": 200,
            "status_text": "OK",
            "headers": {"content-type": "application/json"},
            "body": {"captured": True, "content_type": "application/json", "data": []},
        },
        "observed_on": observed_on or [],
    }


class ScrapingReportCleaningTests(unittest.TestCase):
    def test_removes_duplicate_requests_and_endpoints(self):
        cleaned = clean_scraping_report(
            {
                "target": "https://example.test",
                "observed_endpoints": [
                    {"method": "get", "path": "/items", "query_parameters": ["q"]},
                    {
                        "method": "GET",
                        "path": "/items",
                        "query_parameters": ["q", "q"],
                    },
                ],
                "requests": [
                    _request("request-1", observed_on=["https://example.test/"]),
                    _request(
                        "request-2",
                        observed_on=["https://example.test/catalog"],
                    ),
                ],
            }
        )

        self.assertEqual(len(cleaned["observed_endpoints"]), 1)
        self.assertEqual(len(cleaned["requests"]), 1)
        self.assertEqual(cleaned["requests"][0]["id"], "request-1")
        self.assertEqual(
            cleaned["requests"][0]["observed_on"],
            ["https://example.test/", "https://example.test/catalog"],
        )
        self.assertEqual(cleaned["requests"][0]["method"], "GET")

    def test_preserves_requests_with_different_bodies(self):
        cleaned = clean_scraping_report(
            {
                "target": "https://example.test",
                "observed_endpoints": [],
                "requests": [
                    _request(
                        "login-1",
                        body={"captured": True, "data": {"user": "first"}},
                    ),
                    _request(
                        "login-2",
                        body={"captured": True, "data": {"user": "second"}},
                    ),
                ],
            }
        )

        self.assertEqual(len(cleaned["requests"]), 2)

    def test_rejects_input_outside_expected_contract(self):
        with self.assertRaisesRegex(ValueError, "observed_endpoints"):
            clean_scraping_report(
                {"target": "https://example.test", "requests": []}
            )

    def test_rejects_request_with_malformed_response_body(self):
        request = _request("request-1")
        request["response"]["body"] = {"captured": "yes"}
        with self.assertRaisesRegex(ValueError, "response.body"):
            clean_scraping_report(
                {
                    "target": "https://example.test",
                    "observed_endpoints": [],
                    "requests": [request],
                }
            )

    def test_accepts_a_request_that_did_not_receive_an_http_response(self):
        request = _request("request-1")
        request["response"] = {
            "status": None,
            "status_text": "",
            "headers": {},
            "body": {"captured": False, "content_type": "", "data": None},
        }

        report = clean_scraping_report(
            {
                "target": "https://example.test",
                "observed_endpoints": [],
                "requests": [request],
            }
        )

        self.assertIsNone(report["requests"][0]["response"]["status"])

    def test_builds_sqli_context_from_clean_report_inputs(self):
        requests = [
            {
                **_request("search"),
                "url": "https://example.test/items?q=tea",
                "path": "/items",
                "query_values": {"q": "tea"},
            },
            {
                **_request(
                    "login",
                    body={
                        "captured": True,
                        "content_type": "application/json",
                        "data": {"email": "user@example.test"},
                    },
                ),
                "method": "POST",
                "url": "https://example.test/login",
                "path": "/login",
                "query_parameters": [],
                "query_values": {},
                "request_line": "POST /login HTTP/1.1",
                "request_headers": {"content-type": "application/json"},
            },
            {
                **_request("static"),
                "url": "https://example.test/",
                "path": "/",
                "query_parameters": [],
                "query_values": {},
            },
        ]
        clean_report = clean_scraping_report(
            {
                "target": "https://example.test",
                "observed_endpoints": [],
                "requests": requests,
            }
        )

        context = build_sqli_recon_context(
            clean_report,
            [{"name": "sqlmap"}],
        )

        inputs = context["sqli_input_entry_points"]
        self.assertEqual([item["id"] for item in inputs], ["search", "login"])
        self.assertEqual(inputs[0]["query_parameters"], {"q": "tea"})
        self.assertIsNone(inputs[0]["body"])
        self.assertEqual(
            inputs[1]["body"],
            {"email": "user@example.test"},
        )
        self.assertEqual(inputs[1]["headers"]["content-type"], "application/json")
        self.assertEqual(context["available_validation_tools"], [{"name": "sqlmap"}])


if __name__ == "__main__":
    unittest.main()
