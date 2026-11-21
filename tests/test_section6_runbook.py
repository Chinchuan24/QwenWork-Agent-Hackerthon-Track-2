"""Offline documentation guarantees; no app imports or shared fixtures."""
from pathlib import Path
import json
import re
import unittest


TEXT = (Path(__file__).resolve().parents[1] / "docs/demo-runbook.md").read_text()


class RunbookGuarantees(unittest.TestCase):
    def test_safe_reset_and_exact_local_command(self):
        self.assertIn(".venv/bin/python -m aegis.demo_repeatability", TEXT)
        self.assertIn("No production reset", TEXT)
        self.assertIn("newly allocated", TEXT)
        self.assertNotIn("/".join(("", "Users", "")), TEXT)
        self.assertNotRegex(TEXT, r"\brm\s|AEGIS_DATA_DIR=|--data-dir")

    def test_disclosure_and_timing(self):
        for phrase in ("scripted stand-in", "ready for key; not run",
                       "Aegis safe / Delta unsure", "not Delta unsafe",
                       "browser_shot_seconds", "0.440", "165 seconds"):
            self.assertIn(phrase, TEXT)
        windows = re.findall(r"\| (\d+)-(\d+) \|", TEXT)
        self.assertEqual(windows[-1], ("155", "165"))
        self.assertLessEqual(max(int(end) for _, end in windows), 170)

    def test_measured_everyday_read(self):
        root = Path(__file__).resolve().parents[1]
        receipt = json.loads((root / "docs/section-6-demo-evidence.json").read_text())
        shot = (root / "docs/demo-shot-list.md").read_text()
        for text in (TEXT, shot):
            for phrase in ("2026-11-19", "Everyday read", "record-14",
                           "clients/proposal_greenstep_tuition.md", "not a universal guarantee"):
                self.assertIn(phrase, text)
            windows = [(int(a), int(b)) for a, b in re.findall(r"\| (\d+)-(\d+) \|", text)]
            self.assertEqual(windows[0][0], 0)
            self.assertEqual(windows[-1][1], 165)
            self.assertTrue(all(a < b for a, b in windows))
            self.assertTrue(all(left[1] == right[0] for left, right in zip(windows, windows[1:])))
            self.assertLessEqual(sum(b - a for a, b in windows), 170)
        for result in receipt["results"]:
            binding = next(b for b in result["bindings"] if b["story"] == "S2" and b["step"] == 1)
            records = {r["record_ref"]: r for r in result["record_projection"]}
            record = records[binding["record_ref"]]
            self.assertEqual(binding["record_ref"], "record-14")
            self.assertEqual(record["event"], "decision")
            self.assertEqual(record["detail"]["tool"], "read_file")
            self.assertEqual(record["detail"]["args"]["doc_id"], "clients/proposal_greenstep_tuition.md")
            self.assertEqual(record["detail"]["status"], "executed")
            self.assertEqual(record["detail"]["verdict"], binding["reply"]["verdict"])
            self.assertEqual(binding["reply"]["verdict"], "allow")
            self.assertEqual((record["run_ref"], record["session_ref"]), ("run_id-3", "session_id-4"))
        self.assertIn("Zero sent does not mean all work completed", TEXT)
        self.assertIn("Actual clicks, load time and scrolling remain unmeasured", TEXT)

    def test_proof_checks(self):
        for phrase in ("record_projection", "bindings", "audit_ok", "sent",
                       "proof_ids", "run_ref", "session_ref",
                       "S1 has no emitted source-line evidence", "R07/R08"):
            self.assertIn(phrase, TEXT)

    def test_failure_and_browser_gate(self):
        for phrase in ("BLOCKED waiting core owner", "Verify", "/audit/record/{rid}",
                       "Do not use a mock screenshot", "Never approve",
                       "Do not repair or clear", "This run did not produce a disagreement",
                       "five consecutive", "ten reset clicks", "nonzero exit"):
            self.assertIn(phrase, TEXT)
        self.assertNotIn("Click Reset demo", TEXT)


if __name__ == "__main__":
    unittest.main()
