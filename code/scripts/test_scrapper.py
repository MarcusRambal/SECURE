import unittest

from scrapper import (
    MAX_BODY_BYTES,
    _build_scraping_report,
    _complete_request_records,
    _response_body_for_report,
    _sanitize_body,
)


class ScrapperReportTests(unittest.TestCase):
    def test_json_body_uses_the_recon_data_field(self):
        body = _sanitize_body(
            '{"items":[{"id":1}]}',
            "application/json; charset=utf-8",
            "/api/items",
        )

        self.assertEqual(
            body,
            {
                "captured": True,
                "content_type": "application/json",
                "data": {"items": [{"id": 1}]},
            },
        )

    def test_text_response_body_uses_the_recon_data_field(self):
        body = _sanitize_body("<html>ok</html>", "text/html", "/")

        self.assertEqual(body["data"], "<html>ok</html>")
        self.assertNotIn("text", body)

    def test_oversized_body_contains_data_field(self):
        body = _sanitize_body(
            "x" * (MAX_BODY_BYTES + 1),
            "application/json",
            "/api/items",
        )

        self.assertFalse(body["captured"])
        self.assertIsNone(body["data"])

    def test_requests_without_response_keep_the_complete_report_shape(self):
        requests = [{"id": "request-1", "response": None}]

        _complete_request_records(requests)

        self.assertEqual(
            requests[0]["response"],
            {
                "status": None,
                "status_text": "",
                "headers": {},
                "body": {
                    "captured": False,
                    "content_type": "",
                    "data": None,
                },
            },
        )

    def test_response_body_discards_non_contract_metadata(self):
        body = _response_body_for_report(
            {
                "captured": False,
                "reason": "body_too_large",
                "bytes": MAX_BODY_BYTES + 1,
                "content_type": "application/json",
                "data": None,
            },
            "application/json",
        )

        self.assertEqual(
            body,
            {
                "captured": False,
                "content_type": "application/json",
                "data": None,
            },
        )

    def test_report_contains_only_the_requested_contract_fields(self):
        request = {
            "id": "req_1",
            "method": "GET",
            "url": "http://weak-page:3009/api/items?q=cake",
            "path": "/api/items?q=cake",
            "request_line": "GET /api/items?q=cake HTTP/1.1",
            "query_parameters": ["q"],
            "query_values": {"q": "cake"},
            "resource_type": "xhr",
            "request_headers": {"accept": "application/json"},
            "request_body": None,
            "response": {
                "status": 200,
                "status_text": "OK",
                "headers": {"content-type": "application/json"},
                "body": {
                    "captured": True,
                    "content_type": "application/json",
                    "data": {"items": []},
                },
            },
            "observed_on": ["http://weak-page:3009/#/catalog"],
            "failure": None,
        }
        failed_request = {**request, "id": "req_2", "response": None}

        report = _build_scraping_report(
            "http://weak-page:3009",
            [request, failed_request],
        )

        self.assertEqual(
            set(report),
            {"target", "observed_endpoints", "requests"},
        )
        self.assertEqual(
            set(report["observed_endpoints"][0]),
            {"method", "path", "query_parameters"},
        )
        self.assertEqual(len(report["requests"]), 1)
        normalized_request = report["requests"][0]
        self.assertEqual(
            set(normalized_request),
            {
                "id",
                "method",
                "url",
                "path",
                "request_line",
                "query_parameters",
                "query_values",
                "resource_type",
                "request_headers",
                "request_body",
                "response",
                "observed_on",
            },
        )
        self.assertEqual(
            set(normalized_request["response"]),
            {"status", "status_text", "headers", "body"},
        )
        self.assertEqual(
            set(normalized_request["response"]["body"]),
            {"captured", "content_type", "data"},
        )
        self.assertEqual(
            report["observed_endpoints"],
            [
                {
                    "method": "GET",
                    "path": "/api/items",
                    "query_parameters": ["q"],
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
