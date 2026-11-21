"""Document checks only; these do not test remote integrations."""
import json
from pathlib import Path
import unittest

DOC = Path(__file__).resolve().parents[1] / "docs/qwenwork-capabilities.md"


class T11CapabilitiesTests(unittest.TestCase):
    def inventory(self):
        text = DOC.read_text()
        return text, json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])

    def test_explicit_flags_and_coverage(self):
        _, rows = self.inventory()
        self.assertEqual(set(rows), {"sessions", "skills", "connectors", "cron", "pages", "subagents", "media", "voice", "Hashmeta"})
        for name, row in rows.items():
            with self.subTest(name=name):
                self.assertIn(row["exists"], ("declared", "not declared"))
                self.assertIsInstance(row["tested"], bool)
                self.assertIsInstance(row["used"], bool)
                self.assertEqual(row["not_tested"], not row["tested"])
                self.assertTrue(row["scope"])
                self.assertTrue(row["evidence"])

    def test_observation_is_not_integration_proof(self):
        text, rows = self.inventory()
        for name in ("sessions", "subagents"):
            self.assertEqual(rows[name]["observed"], "historical report")
            heading = 'Parallel Track 2 and governance work'
            self.assertIn(heading, rows[name]["evidence"])
            self.assertNotIn("docs/progress.md:8", rows[name]["evidence"])
            progress = (DOC.parent / 'progress.md').read_text()
            report = progress.split('## ' + heading, 1)[1].split('\n## ', 1)[0]
            self.assertIn('independent worker/checker sessions', report)
            self.assertIn('Follow-up messages', report)
            self.assertFalse(rows[name]["tested"])
            self.assertFalse(rows[name]["used"])
        self.assertIn("23 is a reported count, not a recounted measurement", text)
        self.assertIn("No key inspection", text)
        self.assertIn("No network calls or working-copy creation", text)
        for name in ("pages", "Hashmeta"):
            self.assertFalse(rows[name]["used"])

    def test_observed_execution_only(self):
        _, rows = self.inventory()
        self.assertEqual([k for k, v in rows.items() if v["tested"]], ["skills"])
        self.assertEqual([k for k, v in rows.items() if v["used"]], ["skills"])
        self.assertEqual(rows["skills"]["evidence"], "functions.skill(name=audit-verify-explain-grade-5): returned skill_content")
        self.assertIn("loading only", rows["skills"]["scope"])

    def test_current_declared_trace_names(self):
        _, rows = self.inventory()
        expected = {
            "sessions": "functions.qw-builtin_qw_query",
            "skills": "functions.skill",
            "connectors": "functions.qw-builtin_qwenwork_mcp_tool_list",
            "cron": "functions.qw-builtin_qwenwork_cron_manage_job",
            "pages": "functions.qw-builtin_qwenwork_pages_publish",
            "subagents": "functions.qw-builtin_qwenwork_task_send_message",
            "media": "functions.qw-builtin_qwenwork_video_generate",
        }
        for name, tool in expected.items():
            self.assertIn(tool, rows[name]["tools"])
        for name in ("voice", "Hashmeta"):
            self.assertEqual(rows[name]["tools"], [])
            self.assertEqual(rows[name]["exists"], "not declared")

    def test_limits_visible(self):
        text, _ = self.inventory()
        for phrase in (
            "No internal QwenWork configuration was queried",
            "No login, publishing, schedule creation",
            "Part B is not proven", "not a runtime integration test",
            "No subagent creation tool is declared",
            "waiting for Chin: Hashmeta AI sign-in",
            "not evidence of absence",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
