import json
import tempfile
import unittest
from pathlib import Path

from handlers.report_writer import save_skill_report


class SkillReportWriterTests(unittest.TestCase):
    def test_saves_unique_json_reports_with_redacted_target_values(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            target = "https://user:secret@example.test/login?email=alice&token=abc123"
            first = save_skill_report(
                output_dir,
                "sqli_skill",
                {"target": target, "injectable": False},
                target,
                "email",
            )
            second = save_skill_report(
                output_dir,
                "sqli_skill",
                {"target": target, "injectable": True},
                target,
                "email",
            )

            self.assertNotEqual(first, second)
            self.assertEqual(first.suffix, ".json")
            stored_report = json.loads(first.read_text(encoding="utf-8"))
            serialized_report = json.dumps(stored_report)
            self.assertEqual(
                stored_report["target_url"],
                "https://example.test/login?email=%5BREDACTED%5D&token=%5BREDACTED%5D",
            )
            self.assertNotIn("secret", serialized_report)
            self.assertNotIn("alice", serialized_report)
            self.assertNotIn("abc123", serialized_report)


if __name__ == "__main__":
    unittest.main()
