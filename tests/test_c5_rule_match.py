"""C5 evidence honesty, offline rendering and exact official risk names."""
from pathlib import Path
import re

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_has_exact_ten_risks():
    from aegis.rule_match import rule_match_table
    rows = [r for r in rule_match_table() if r['source'] == 'OWASP agent list']
    assert [r['number'] for r in rows] == [f'ASI{i:02}' for i in range(1, 11)]
    assert [r['heading'] for r in rows] == [
        'Agent Goal Hijack', 'Tool Misuse', 'Identity & Privilege Abuse',
        'Agentic Supply Chain Vulnerabilities', 'Unexpected Code Execution',
        'Memory & Context Poisoning', 'Insecure Inter-Agent Communication',
        'Cascading Failures', 'Human-Agent Trust Exploitation', 'Rogue Agents']


def test_missing_proof_is_not_covered():
    from aegis.rule_match import rule_match_table
    assert all(r['status'] in {'not covered', 'not verified'} for r in rule_match_table())
    assert all(not r['proof'] for r in rule_match_table())


@pytest.mark.parametrize('source', ['OWASP agent list', 'PDPA'])
def test_unreadable_source_is_not_verified(source):
    from aegis.rule_match import rule_match_table
    baseline = rule_match_table()
    rows = rule_match_table(unreadable_sources={source})
    affected = [r for r in rows if r['source'] == source]
    assert affected
    assert all(r['status'] == 'not verified' for r in affected)
    assert all(r['source_verified'] is False for r in affected)
    assert all(r['proof'] == [] for r in affected)
    assert [r for r in rows if r['source'] != source] == [
        r for r in baseline if r['source'] != source]
    assert rule_match_table() == baseline


@pytest.mark.parametrize('unreadable_sources', [(), ('OWASP agent list',), ('PDPA',),
                                              ('IMDA agent framework', 'CSA agent guide')])
def test_rule_match_export_parity(unreadable_sources, monkeypatch):
    import json
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis import proof_pack
    from aegis.rule_match import NOTICE, rule_match_table

    # Exercise C4's real projection and seal, not its authorization or audit checks.
    monkeypatch.setattr(proof_pack, '_consume_context', lambda _: {'id': 1, 'username': 'test'})
    monkeypatch.setattr(proof_pack, '_integrity', lambda: {'ok': False})
    monkeypatch.setattr(proof_pack.audit, 'record', lambda *args, **kwargs: None)
    rows = rule_match_table(unreadable_sources=unreadable_sources)
    key = Ed25519PrivateKey.generate()
    artifact = proof_pack.build_proof_pack(0, 0, context=None, signing_key=key,
                                          rule_match=rows)
    assert proof_pack.verify_seal(artifact, key.public_key())
    payload = json.loads(artifact)['payload']
    assert payload['rule_match'] == rows
    assert payload['rule_match_notice'] == NOTICE


def test_no_invented_version_or_final_status():
    from aegis.rule_match import SOURCES
    assert SOURCES['IMDA agent framework']['version'] == 'not verified'
    assert SOURCES['CSA agent guide']['publication_status'] == 'not verified'


def test_rows_have_official_provenance():
    from aegis.rule_match import rule_match_table
    for row in rule_match_table():
        assert row['url'].startswith('https://')
        assert row['read_date'] == '2026-11-18'
        assert row['heading'] and row['summary']
        assert row['status'] in {'covered', 'partly', 'not covered', 'not verified'}


def test_results_are_independent():
    from aegis.rule_match import rule_match_table
    rows = rule_match_table()
    rows[0]['status'] = 'covered'
    assert rule_match_table()[0]['status'] != 'covered'


def test_template_renders_all_gaps_and_notice():
    from aegis.rule_match import rule_match_table, NOTICE, SOURCES
    env = Environment(loader=FileSystemLoader(ROOT / 'templates'), autoescape=select_autoescape())
    html = env.get_template('rule_match.html').render(table=rule_match_table(), sources=SOURCES, notice=NOTICE)
    assert 'not legal advice' in html and 'not covered' in html and 'not verified' in html
    assert all(f'ASI{i:02}' in html for i in range(1, 11))
    assert '<script>' not in html


def test_owned_outputs_have_no_self_endorsement():
    from aegis.rule_match import rule_match_table, NOTICE
    text = NOTICE + str(rule_match_table()) + (ROOT / 'docs/rule-match.md').read_text() + (ROOT / 'templates/rule_match.html').read_text()
    assert not re.search(r'\b(?:compliant|certified|approved by|guarantees)\b', text, re.I)
