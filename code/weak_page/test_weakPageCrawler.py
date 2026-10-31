import unittest
from pathlib import Path

from weakPageCrawler import (
    _safe_headers,
    _route_template,
    _observed_api_endpoints,
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


if __name__ == "__main__":
    unittest.main()
