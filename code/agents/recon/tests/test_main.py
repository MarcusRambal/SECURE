import unittest
from urllib.parse import urlsplit

from main import build_recon_output


TARGET = "http://weak-page:3009"


def _request(
    request_id,
    url,
    *,
    method="GET",
    query_values=None,
    body=None,
    observed_on=None,
):
    return {
        "id": request_id,
        "method": method,
        "url": url,
        "path": urlsplit(url).path,
        "request_line": f"{method} {url} HTTP/1.1",
        "query_parameters": list((query_values or {}).keys()),
        "query_values": query_values or {},
        "resource_type": "xhr",
        "request_headers": {"content-type": "application/json"},
        "request_body": (
            {
                "captured": True,
                "content_type": "application/json",
                "data": body,
            }
            if body is not None
            else None
        ),
        "response": {
            "status": 200,
            "status_text": "OK",
            "headers": {},
            "body": {"captured": False, "content_type": "", "data": None},
        },
        "observed_on": observed_on or [],
    }


def _report(*requests, target=TARGET):
    return {
        "target": target,
        "observed_endpoints": [],
        "requests": list(requests),
    }


class ReconOutputTests(unittest.TestCase):
    def test_sqli_targets_are_built_from_observed_query_and_body_inputs(self):
        output = build_recon_output(
            TARGET,
            "sqli",
            _report(
                _request(
                    "search",
                    f"{TARGET}/api/products?q=cake",
                    query_values={"q": "cake"},
                ),
                _request(
                    "login",
                    f"{TARGET}/api/auth/login",
                    method="POST",
                    body={"email": "user@example.test"},
                ),
                _request("static", f"{TARGET}/api/products"),
            ),
        )

        self.assertEqual(
            {target.request_id for target in output.high_priority_targets},
            {"search", "login"},
        )
        self.assertTrue(
            all(target.recommended_tool == "sqlmap" for target in output.high_priority_targets)
        )
        self.assertEqual(output.recon_summary.total_requests_captured, 3)

    def test_xss_selects_query_and_body_inputs_for_any_target(self):
        target = "https://example.test"
        output = build_recon_output(
            target,
            "xss",
            _report(
                _request(
                    "search",
                    f"{target}/search?q=cake",
                    query_values={"q": "cake"},
                ),
                _request(
                    "category",
                    f"{target}/products?category=Tartas",
                    query_values={"category": "Tartas"},
                ),
                _request(
                    "contact",
                    f"{target}/comments",
                    method="POST",
                    body={"comment": "Hello"},
                ),
                _request(
                    "login",
                    f"{target}/login",
                    method="POST",
                    body={"email": "user@example.test"},
                ),
                _request("static", f"{target}/assets/app.js"),
                target=target,
            ),
        )

        targets = {target.request_id: target for target in output.high_priority_targets}
        self.assertEqual(set(targets), {"search", "category", "contact", "login"})
        self.assertTrue(
            all(target.recommended_tool == "browserXssValidator" for target in targets.values())
        )
        self.assertTrue(all(target.validation_plan is None for target in targets.values()))

    def test_xss_targets_carry_observed_pages_and_reflected_parameters(self):
        target = "https://example.test"
        report = _report(
            _request(
                "search",
                f"{target}/api/products?q=cake",
                query_values={"q": "cake"},
                observed_on=[f"{target}/#/catalog"],
            ),
            _request(
                "contact-write",
                f"{target}/api/contact",
                method="POST",
                body={"message": "hello"},
                observed_on=[f"{target}/#/contact"],
            ),
            _request(
                "contact-read",
                f"{target}/api/contact",
                observed_on=[f"{target}/#/contact-inbox"],
            ),
            target=target,
        )
        report["requests"][0]["response"]["body"] = {
            "captured": True,
            "content_type": "application/json",
            "data": {"searchInfo": {"raw": "cake"}},
        }

        output = build_recon_output(target, "xss", report)

        targets = {item.request_id: item for item in output.high_priority_targets}
        self.assertEqual(
            targets["search"].request["reflected_parameters"],
            ["q"],
        )
        self.assertEqual(
            targets["search"].request["observed_pages"],
            [f"{target}/#/catalog"],
        )
        self.assertEqual(
            targets["contact-write"].request["observed_pages"],
            [f"{target}/#/contact", f"{target}/#/contact-inbox"],
        )

    def test_access_control_and_crypto_targets_only_use_observed_urls(self):
        requests = [
            _request("basket", "https://shop.test/rest/basket/7"),
            _request("config", "https://shop.test/api/configuration"),
            _request("static", "https://shop.test/assets/app.js"),
        ]
        report = _report(*requests, target="https://shop.test")

        access_output = build_recon_output(
            "https://shop.test",
            "bac_default",
            report,
        )
        crypto_output = build_recon_output(
            "https://shop.test",
            "crypto_inspector",
            report,
        )

        self.assertEqual(
            [target.endpoint for target in access_output.high_priority_targets],
            [
                "https://shop.test/rest/basket/7",
                "https://shop.test/api/configuration",
            ],
        )
        self.assertEqual(
            [target.endpoint for target in crypto_output.high_priority_targets],
            ["https://shop.test/api/configuration"],
        )

    def test_jwt_returns_no_synthetic_targets_for_validate(self):
        output = build_recon_output(
            TARGET,
            "jwt",
            _report(_request("search", f"{TARGET}/api/products?q=cake", query_values={"q": "cake"})),
        )

        self.assertEqual(output.recon_summary.attack_type_filter, "jwt")
        self.assertEqual(output.high_priority_targets, [])

    def test_rejects_report_for_a_different_target_origin(self):
        with self.assertRaisesRegex(ValueError, "mismo origen"):
            build_recon_output(
                TARGET,
                "sqli",
                _report(
                    _request(
                        "search",
                        "http://juice-shop:3000/api/products?q=cake",
                        query_values={"q": "cake"},
                    ),
                    target="http://juice-shop:3000",
                ),
            )

    def test_duplicate_requests_are_removed_and_off_origin_requests_ignored(self):
        duplicate = _request(
            "search-a",
            f"{TARGET}/api/products?q=cake",
            query_values={"q": "cake"},
            observed_on=[f"{TARGET}/"],
        )
        same = {
            **duplicate,
            "id": "search-b",
            "observed_on": [f"{TARGET}/#/catalog"],
        }
        outside = _request(
            "external",
            "http://juice-shop:3000/rest/products/search?q=cake",
            query_values={"q": "cake"},
        )

        output = build_recon_output(
            TARGET,
            "sqli",
            _report(duplicate, same, outside),
        )

        self.assertEqual(len(output.high_priority_targets), 1)
        self.assertEqual(output.high_priority_targets[0].request_id, "search-a")
        self.assertEqual(output.recon_summary.total_requests_captured, 1)


if __name__ == "__main__":
    unittest.main()
