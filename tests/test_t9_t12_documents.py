from pathlib import Path
import json
import re

import pytest

DOCS = Path(__file__).resolve().parents[1] / 'docs'


def section(text, heading):
    return text.split('## ' + heading + '\n', 1)[1].split('\n## ', 1)[0].strip()


@pytest.mark.parametrize('name', ['briefing-video-script.md', 'demo-shot-list.md', 'submission.md'])
def test_documents_exist_and_make_no_unmeasured_success_claim(name):
    text = (DOCS / name).read_text()
    assert 'pending' in text.lower()
    assert not re.search(r'\b(compliant|certified|approved by|guarantees)\b', text, re.I)
    assert not re.search(r'15\s*(?:/|out of)\s*15|zero miss|0 misses|168 stopped', text, re.I)


def test_briefing_is_explicitly_pending_without_invented_daily_figures():
    text = (DOCS / 'briefing-video-script.md').read_text()
    spoken = section(text, 'Spoken Script')
    print(f'Briefing spoken words: {len(spoken.split())}')
    assert len(spoken.split()) <= 150
    assert not re.search(r'\d', spoken)
    assert 'pending measured briefing' in text.lower()
    assert 'not a daily briefing' in text.lower()
    assert 'No media generated' in text
    assert '55-65 seconds' in text


def test_demo_timing_and_required_moments():
    text = (DOCS / 'demo-shot-list.md').read_text()
    rows = [line.split('|')[1:-1] for line in text.splitlines()
            if re.match(r'^\| \d+-\d+ \|', line)]
    assert len(rows) == 8
    cursor = 0
    for span, beat, status, shot, words in rows:
        start, end = map(int, span.strip().split('-'))
        assert start == cursor and end > start
        cursor = end
        assert status.strip().startswith('Pending')
        assert words.strip()
    print(f'Demo planned seconds: {cursor}; narration words: {sum(len(row[4].split()) for row in rows)}')
    assert cursor <= 170
    durations = {row[1].strip(): int(row[0].split('-')[1]) - int(row[0].split('-')[0]) for row in rows}
    assert durations['Delta disagreement'] == 15
    assert 'Attack board and rule match' in text
    assert 'separate pending acceptance gate' in text
    assert 'not demonstrated in this 165-second plan' in text
    assert durations['Measured score pause'] == 10
    for beat in ['Bad worker', 'Risk stopped', 'Made-up numbers', 'Morning briefing']:
        assert beat in durations
    assert 'three clean runs' in text
    assert 'scripted' in text and 'live' in text
    assert 'Do not auto-approve' in text


def test_submission_word_limits_and_honest_engine_status():
    text = (DOCS / 'submission.md').read_text()
    print(f'Submission description words: {len(section(text, "Description").split())}')
    assert len(section(text, 'Description').split()) <= 300
    assert len(section(text, 'One-Sentence Description').split('.')) == 2
    assert 'QwenWork' in text
    assert 'waiting for key' in text
    assert 'Hashmeta AI' in text
    assert 'not legal advice' in text


def test_current_source_gate_distinguishes_builder_from_measured_briefing():
    text = (DOCS / 'briefing-video-script.md').read_text()
    assert '[briefing builder](../aegis/briefing.py)' in text
    assert '[briefing component tests](../tests/test_t8_briefing.py)' in text
    assert 'saved backend briefing' in text
    assert 'no saved post-S1-S5 briefing artifact' not in text
    receipt = json.loads((DOCS / 'section-6-demo-evidence.json').read_text())
    assert len(receipt['results']) == receipt['runs'] == 5
    for result in receipt['results']:
        assert result['briefing']['check_status'] == 'checked'
        assert result['briefing']['mode'] == 'template'
        assert result['briefing']['headline']['proof_ids']
    for gap in ['Scheduling', 'daily persistence', 'working browser proof links']:
        assert gap in text
    assert 'Source manifest: pending' in text
    for field in ['run identifiers', 'date range', 'scripted or live mode',
                  'audit records', 'T6 checks', 'incident proof links']:
        assert field in text


@pytest.mark.parametrize('name', ['briefing-video-script.md', 'demo-shot-list.md', 'submission.md'])
def test_documents_keep_media_and_release_gate_explicit(name):
    text = (DOCS / name).read_text()
    assert 'No media before a verified real briefing' in text
    assert 'waiting for Chin' in text


def test_demo_preserves_sponsor_moment_order():
    text = (DOCS / 'demo-shot-list.md').read_text()
    moments = ['Bad worker', 'Risk stopped', 'Made-up numbers', 'Morning briefing']
    positions = [text.index('| ' + moment + ' |') for moment in moments]
    assert positions == sorted(positions)
