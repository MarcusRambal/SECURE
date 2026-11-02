import json
import tempfile
import unittest
from pathlib import Path

from handlers.crawler_reports import _persist_json_report


class CrawlerReportPersistenceTests(unittest.TestCase):
    def test_persists_json_and_redacts_credentials(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _persist_json_report(
                {
                    "status": "SUCCESS",
                    "output": json.dumps(
                        {
                            "target_url": "https://example.test/search?token=private&q=hello",
                            "requests": [
                                {
                                    "url": "https://example.test/search?token=private&q=hello",
                                    "headers": {"Cookie": "session=private"},
                                }
                            ],
                        }
                    ),
                },
                Path(temp_dir),
                "crawler",
            )

            self.assertEqual(result["status"], "SUCCESS")
            self.assertEqual(result["saved_report"].split("/")[0:3], ["tools", "crawler", "outputs"])
            report_path = Path(temp_dir) / Path(result["saved_report"]).name
            persisted = report_path.read_text(encoding="utf-8")
            self.assertIn("[REDACTED]", persisted)
            self.assertIn("q=hello", persisted)
            self.assertNotIn("private", persisted)

    def test_malformed_tool_output_is_persisted_as_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _persist_json_report(
                {"status": "SUCCESS", "output": "not json"},
                Path(temp_dir),
                "deep_crawler",
            )

            self.assertEqual(result["status"], "FAILED")
            report = json.loads(result["output"])
            self.assertEqual(
                report["error"],
                "deep_crawler did not return valid JSON",
            )
            self.assertTrue((Path(temp_dir) / Path(result["saved_report"]).name).exists())


if __name__ == "__main__":
    unittest.main()
