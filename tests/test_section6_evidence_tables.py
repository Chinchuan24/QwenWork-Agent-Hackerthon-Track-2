"""Documentation contract only; no product acceptance score is inferred."""
from pathlib import Path
import re

DOCUMENT = Path(__file__).resolve().parents[1] / 'docs' / 'section-6-evidence-tables.md'


def test_all_remaining_requirement_ids_are_present():
    text = DOCUMENT.read_text()
    ids = re.findall(r'^\| (T\d+|C\d+) \|', text, re.M)
    assert ids == [f'T{i}' for i in range(1, 15)] + [f'C{i}' for i in range(1, 7)]


def test_measurements_keep_scope_and_open_gates_visible():
    text = DOCUMENT.read_text()
    for phrase in ('231 passed in 0.58s', 'component', 'gateway', 'browser',
                   'stand-in', 'not rerun', 'R01-R19', 'No completion score'):
        assert phrase in text
    assert '| T7 |' in text and 'N14/N15/N16' in text
    assert 'tests/test_section6_normal_acceptance.py' in text


def test_no_machine_paths_or_promoted_acceptance():
    text = DOCUMENT.read_text()
    assert not re.search('/' + 'Users' + '/' + r'|/Applications/|[A-Z]:\\', text)
    assert not re.search(r'(?i)\b(?:all requirements complete|release ready|certified)\b', text)
    for command in re.findall(r'^\.venv/bin/python -m pytest (.+)$', text, re.M):
        assert 'tests -q' not in command
        assert 'test_t12' not in command and 'test_section6_normal_acceptance' not in command
