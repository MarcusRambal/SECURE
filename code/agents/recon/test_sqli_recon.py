import unittest

from helpers import (
    build_sqli_fallback_output,
    build_sqli_recon_context,
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

        context = build_sqli_recon_context(
            {"navigation": {"endpoints": []}},
            deep_crawler_data,
            [],
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


if __name__ == "__main__":
    unittest.main()
