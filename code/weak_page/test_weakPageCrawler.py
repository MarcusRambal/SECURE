import unittest
from pathlib import Path

from weakPageCrawler import (
    _entry_point_from_request,
    _safe_headers,
    _route_template,
    _query_values,
    _observed_api_endpoints,
    _synthetic_field_value,
    _sanitize_body,
    MAX_BODY_BYTES,
    discover_api_routes,
    discover_frontend_routes,
    validate_target_url,
)


SOURCE_ROOT = Path(__file__).parent


class WeakPageCrawlerTests(unittest.TestCase):
    def test_only_accepts_the_internal_weak_page_target(self):
        self.assertEqual(
            validate_target_url("http://weak-page:3009"),
            "http://weak-page:3009",
        )
        for target in (
            "http://example.org:3009",
            "http://weak-page:3008",
            "https://weak-page:3009",
            "http://weak-page:3009/path",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target_url(target)

    def test_extracts_declared_spa_routes_from_application_source(self):
        routes = discover_frontend_routes(SOURCE_ROOT / "js" / "router.js")
        self.assertEqual(len(routes), 10)
        self.assertIn(
            {"template": "/product/{id}", "key": "productDetail", "title": "Producto"},
            routes,
        )

    def test_extracts_api_methods_and_paths_from_express_source(self):
        routes = discover_api_routes(
            SOURCE_ROOT / "backend" / "src" / "app.js",
            SOURCE_ROOT / "backend" / "routes",
        )
        self.assertIn(
            {"method": "POST", "path": "/api/auth/login", "source": "auth.routes.js"},
            routes,
        )
        self.assertIn(
            {"method": "GET", "path": "/api/health", "source": "app"},
            routes,
        )

    def test_redacts_sensitive_request_headers(self):
        headers = _safe_headers(
            {"Authorization": "Bearer private", "Accept": "application/json"}
        )
        self.assertEqual(headers["authorization"], "[REDACTED]")
        self.assertEqual(headers["accept"], "application/json")

    def test_route_template_replaces_dynamic_segments(self):
        self.assertEqual(_route_template(r"^\/product\/([^/]+)\/?$"), "/product/{id}")

    def test_observed_endpoint_catalog_contains_only_api_requests(self):
        endpoints = _observed_api_endpoints(
            [
                {
                    "method": "GET",
                    "url": "http://weak-page:3009/js/app.js",
                    "query_parameters": [],
                    "id": "req_1",
                },
                {
                    "method": "GET",
                    "url": "http://weak-page:3009/api/products?q=cake",
                    "query_parameters": ["q"],
                    "id": "req_2",
                },
            ]
        )
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/api/products")

    def test_sanitizes_credentials_in_request_and_private_response_bodies(self):
        request_body = _sanitize_body(
            '{"email":"synthetic@example.invalid","password":"not-a-real-password"}',
            "application/json",
            "/api/auth/login",
        )
        self.assertEqual(request_body["data"]["email"], "[REDACTED]")
        self.assertEqual(request_body["data"]["password"], "[REDACTED]")

        private_body = _sanitize_body(
            '{"name":"Test User","email":"user@example.invalid","phone":"+1 555 123 4567"}',
            "application/json",
            "/api/orders/1",
        )
        self.assertEqual(private_body["data"]["name"], "[REDACTED]")
        self.assertEqual(private_body["data"]["email"], "[REDACTED]")
        self.assertEqual(private_body["data"]["phone"], "[REDACTED]")

    def test_preserves_private_body_structure_while_redacting_values(self):
        body = _sanitize_body(
            '{"customer":{"name":"Synthetic User","email":"fake@example.invalid"},'
            '"items":[{"productId":"1","quantity":1}]}',
            "application/json",
            "/api/orders",
        )
        self.assertEqual(body["data"]["customer"]["name"], "[REDACTED]")
        self.assertEqual(body["data"]["customer"]["email"], "[REDACTED]")
        self.assertEqual(body["data"]["items"][0]["productId"], "1")

    def test_keeps_non_sensitive_product_response_fields(self):
        body = _sanitize_body(
            '{"name":"Tarta de chocolate","price":25}',
            "application/json",
            "/api/products/1",
        )
        self.assertEqual(body["data"]["name"], "Tarta de chocolate")

    def test_skips_bodies_over_the_capture_limit(self):
        body = _sanitize_body(
            "x" * (MAX_BODY_BYTES + 1),
            "application/json",
            "/api/products",
        )
        self.assertFalse(body["captured"])
        self.assertEqual(body["reason"], "body_too_large")

    def test_builds_deep_crawler_compatible_entry_points(self):
        entry_point = _entry_point_from_request(
            {
                "id": "req_0002",
                "request_line": "POST /api/login HTTP/1.1",
                "method": "POST",
                "url": "http://weak-page:3009/api/login",
                "path": "/api/login",
                "query_values": {},
                "resource_type": "fetch",
                "request_headers": {"content-type": "application/json"},
                "request_body": {
                    "captured": True,
                    "content_type": "application/json",
                    "data": {"username": "[REDACTED]", "password": "[REDACTED]"},
                },
                "response": {
                    "status": 401,
                    "headers": {"content-type": "application/json"},
                },
                "observed_on": ["http://weak-page:3009/#/login"],
            }
        )

        self.assertEqual(entry_point["request_line"], "POST /api/login HTTP/1.1")
        self.assertEqual(entry_point["body"]["password"], "[REDACTED]")
        self.assertEqual(entry_point["response"]["status"], 401)
        self.assertEqual(entry_point["headers"]["content-type"], "application/json")

    def test_get_entry_points_keep_query_inputs_separate_from_body(self):
        entry_point = _entry_point_from_request(
            {
                "id": "req_0040",
                "request_line": "GET /api/products?category=Tartas HTTP/1.1",
                "method": "GET",
                "url": "http://weak-page:3009/api/products?category=Tartas",
                "path": "/api/products?category=Tartas",
                "query_values": {"category": "Tartas"},
                "request_body": None,
                "response": {"status": 200, "headers": {}},
            }
        )

        self.assertIsNone(entry_point["body"])
        self.assertEqual(
            entry_point["query_parameters"],
            {"category": "Tartas"},
        )

    def test_extracts_search_and_category_values_from_get_query(self):
        self.assertEqual(
            _query_values(
                "http://weak-page:3009/api/products?q=synthetic"
                "&category=Tartas"
            ),
            {"q": "synthetic", "category": "Tartas"},
        )

    def test_synthetic_values_are_non_account_data_and_fill_common_fields(self):
        self.assertEqual(
            _synthetic_field_value({"name": "email", "type": "email"}),
            "weakpage-crawler@invalid.example",
        )
        self.assertEqual(
            _synthetic_field_value({"name": "password", "type": "password"}),
            "WeakPageCrawler-Invalid-Only",
        )
        self.assertEqual(
            _synthetic_field_value({"name": "message", "type": "textarea"}),
            "Synthetic weakPageCrawler probe message.",
        )
        self.assertIsNone(
            _synthetic_field_value({"name": "file", "type": "file"})
        )


if __name__ == "__main__":
    unittest.main()
