"""Document-only regression checks; run directly without app fixtures."""
import ast
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ('track2-scorecard.md', 'submission.md', 'qwenwork-capabilities.md',
        'briefing-video-script.md')


class ClaimRepairs(unittest.TestCase):
    def text(self, name):
        return (ROOT / 'docs' / name).read_text(encoding='utf-8')

    def test_scope_and_historical_baseline(self):
        text = self.text('track2-scorecard.md')
        for phrase in ('logged gateway boundary', 'off/monitor',
                       'historical baseline dated 2026-11-19',
                       'not current acceptance', 'missing acceptance'):
            self.assertIn(phrase, text)
        self.assertNotIn('Existing documents contain prohibited self-claim wording:', text)

    def test_session_reference_repaired(self):
        text = self.text('qwenwork-capabilities.md')
        rows = json.loads(text.split('```json\n')[1].split('```')[0])
        for name in ('sessions', 'subagents'):
            self.assertIn('Parallel Track 2 and governance work', rows[name]['evidence'])
            self.assertNotIn('docs/progress.md:8', rows[name]['evidence'])
            self.assertFalse(rows[name]['tested'])
        self.assertIn('historical declaration snapshot', text)

    def test_saved_briefing_not_media(self):
        text = self.text('briefing-video-script.md')
        for phrase in ('section-6-demo-evidence.json', 'saved backend briefing',
                       'not generated 60-second media', 'working browser proof links'):
            self.assertIn(phrase, text)
        self.assertNotIn('no saved post-S1-S5 briefing artifact', text)

    def test_submission_honest_and_bounded(self):
        text = self.text('submission.md')
        description = text.split('## Description\n')[1].split('## Handoff Gate')[0]
        self.assertLessEqual(len(description.split()), 300)
        for phrase in ('simulated', 'logged gateway boundary', 'not release-ready',
                       'stand-in', 'QwenWork has supported development'):
            self.assertIn(phrase, text)
        self.assertNotIn('do not establish a saved post-scenario daily briefing', text)

    def test_local_proof_links_and_private_paths(self):
        for name in DOCS:
            text = self.text(name)
            self.assertNotRegex(text, '/'.join(('', 'Users', '')) + r'|file://|/home/')
            for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
                path, _, symbol = target.partition('#')
                resolved = (ROOT / 'docs' / path).resolve()
                self.assertTrue(resolved.is_relative_to(ROOT), target)
                self.assertTrue(resolved.is_file(), target)
                source = resolved.read_text(encoding='utf-8')
                self.assertTrue(source.strip(), target)
                if symbol:
                    self.assertEqual(resolved.suffix, '.py', target)
                    names = {node.name for node in ast.walk(ast.parse(source))
                             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    self.assertIn(symbol, names, target)


if __name__ == '__main__':
    unittest.main()
