"""Read-only document checks; direct execution avoids application fixtures."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CARD = ROOT / 'docs/track2-scorecard.md'
EXPECTED = ({f'A{i}' for i in range(1, 5)} | {f'M{i}' for i in range(1, 5)}
            | {f'D{i}' for i in range(1, 4)} | {f'R{i:02}' for i in range(1, 20)}
            | {f'S{i}' for i in range(1, 6)} | {f'P{i}' for i in range(1, 5)}
            | {f'C{i}' for i in range(1, 7)})


def rows(text):
    return [line.split('|')[1:-1] for line in text.splitlines()
            if re.match(r'^\| (?:[AMDSPC]\d+|R\d{2}) \|', line)]


class ScorecardTests(unittest.TestCase):
    def text(self):
        self.assertTrue(CARD.is_file(), 'Track 2 scorecard is missing')
        return CARD.read_text(encoding='utf-8')

    def test_complete_coverage_and_explicit_limits(self):
        table = rows(self.text())
        self.assertEqual({r[0].strip() for r in table}, EXPECTED)
        self.assertEqual(len(table), len(EXPECTED))
        for row in table:
            self.assertEqual(len(row), 5, row)
            self.assertIn(row[2].strip(), ('not done', 'component verified'))
            self.assertTrue(row[4].strip(), row)
            if row[2].strip() == 'not done':
                self.assertIn('integration', row[4].lower())

    def test_every_evidence_link_and_test_name_resolves(self):
        text = self.text()
        links = re.findall(r'\[[^\]]+\]\(([^)]+)\)', text)
        self.assertTrue(links)
        for target in links:
            path, _, symbol = target.partition('#')
            resolved = (CARD.parent / path).resolve()
            self.assertTrue(resolved.is_file(), target)
            source = resolved.read_text(encoding='utf-8')
            self.assertTrue(source.strip(), target)
            if symbol:
                self.assertEqual(resolved.suffix, '.py', target)
                names = {n.name for n in ast.walk(ast.parse(source))
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                self.assertIn(symbol, names, target)
        for row in rows(text):
            self.assertRegex(row[3], r'\[[^\]]+\]\([^)]+\)')

    def test_no_forbidden_selfclaims_or_invented_scores(self):
        text = self.text()
        self.assertIsNone(re.search(r'\b(compliant|certified|approved\s+by|guarantees)\b', text, re.I))
        self.assertNotRegex(text, r'\b\d+\s*(?:/\s*\d+|out of\s+\d+|%)')
        self.assertIn('synthetic', text.lower())
        self.assertIn('not a measured gateway score', text)

    def test_current_components_do_not_imply_integration_coverage(self):
        text = self.text()
        for target in ('test_t3_office_actions.py#test_office_actions_have_validated_schemas',
                       'test_c2_attack_board.py#test_optimistic_totals_cannot_hide_individual_misses',
                       'test_c5_rule_match.py#test_missing_proof_is_not_covered'):
            self.assertIn(target, text)
        by_id = {r[0].strip(): r for r in rows(text)}
        for identifier in EXPECTED - {f'P{i}' for i in range(1, 5)}:
            self.assertEqual(by_id[identifier][2].strip(), 'not done')
        self.assertIn('IMDA version', by_id['C5'][4])
        self.assertIn('CSA final/draft', by_id['C5'][4])

    def test_link_scope_and_no_unsupported_covered_status(self):
        for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', self.text()):
            path = target.partition('#')[0]
            resolved = (CARD.parent / path).resolve()
            self.assertTrue(resolved.is_relative_to(ROOT) or
                            resolved.parent == ROOT.parent / 'docs', target)
        for row in rows(self.text()):
            self.assertNotIn(row[2].strip().lower(), ('covered', 'done', 'complete'))


if __name__ == '__main__':
    unittest.main()
