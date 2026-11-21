"""Local content checks only; no sign-in or external services."""
from pathlib import Path
import re

CONTENT = Path(__file__).resolve().parents[1] / 'docs/website/content.md'


def text():
    assert CONTENT.is_file(), 'T13 customer content is missing'
    return CONTENT.read_text(encoding='utf-8')


def test_customer_sections():
    copy = text()
    for heading in ('Product line', 'Hero', 'The problem', 'How it works',
                    'Four demo moments', 'Sample morning briefing',
                    'Security room', 'Built with QwenWork', 'Contact',
                    'Proof slots', 'Handoff blockers'):
        assert f'## {heading}' in copy
    assert 'Aegis and Delta are two AI security guards' in copy
    steps = copy.split('## How it works\n', 1)[1].split('\n## ', 1)[0]
    assert re.findall(r'^([123])\. ', steps, re.M) == ['1', '2', '3']
    assert copy.count('Watch the demo') >= 2


def test_no_unproved_numbers_or_security_promises():
    copy = text()
    assert not re.search(r'\b(compliant|certified|approved\s+by|guarantees)\b', copy, re.I)
    customer = copy.split('## Proof slots', 1)[0]
    assert not re.search(r'\d+\s*(?:%|/\s*\d+|out of\s+\d+)', customer)
    assert not re.search(r'\b(?:SGD|S\$|USD)\s*[\d,]+', customer)
    assert 'All measurements are pending the actual scoreboard.' in copy
    assert 'Detection and harm stopped are different measures.' in copy
    assert 'live confirmation: waiting for key' in copy


def test_no_fabricated_assets_or_contact():
    copy = text()
    assert 'Illustrative wording only, not a generated daily report.' in copy
    assert 'waiting for Chin: Hashmeta AI sign-in' in copy
    assert 'Contact destination: waiting for Chin' in copy
    assert 'Keep the contact action disabled' in copy
    assert not re.search(r'https?://|mailto:|[\w.+-]+@[\w.-]+', copy)
    for slot in ('DEMO_1', 'DEMO_2', 'DEMO_3', 'DEMO_4', 'BRIEFING_VIDEO',
                 'SPONSOR_SCORE', 'TWO_GUARDS', 'ATTACK_BOARD', 'ID_CARDS',
                 'PROOF_PACK', 'RULE_MATCH', 'ALARM'):
        assert f'[{slot}]' in copy


def test_draft_boundaries_and_proof_requirements():
    copy = text()
    for phrase in ('unpublished draft', 'simulated business data',
                   'not legal advice', 'fixed rules still win',
                   'run time', 'misses', 'wrongly held', 'scripted or live',
                   'No login, publish, upload, or connector probing'):
        assert phrase in copy


def test_future_features_and_component_measurement_boundaries():
    copy = text()
    product = copy.split('## Product line\n', 1)[1].split('\n## ', 1)[0]
    assert 'Planned product:' in product
    assert 'helps you meet' in product
    hero = copy.split('## Hero\n', 1)[1].split('\n## ', 1)[0]
    assert 'is being prepared' in hero
    assert 'Future workflow, not verified integrated behaviour.' in copy
    security = copy.split('## Security room\n', 1)[1].split('\n## ', 1)[0]
    for feature in ('Two guards', 'Attack board', 'Helper ID cards',
                    'Proof pack', 'Rule match', 'Alarm'):
        assert f'**{feature} (prepared; integration unverified):**' in security
    assert 'Measured component results only; not an integrated product score.' in copy
    assert 'component name and version' in copy
    assert 'Do not combine component results into an integrated score.' in copy
    assert 'No achieved sponsor score is available for this draft.' in copy
