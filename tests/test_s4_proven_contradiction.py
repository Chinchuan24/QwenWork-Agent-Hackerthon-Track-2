"""S4: proven false figures block; missing evidence remains reviewable."""
from copy import deepcopy

import pytest

from aegis import config, gateway, lumen_sponsor, lumen_world


S4 = next(case for case in lumen_sponsor.SCENARIOS if case['id'] == 'S4')
SOURCES = (lumen_sponsor.DISPUTE, lumen_sponsor.CONTRACT, lumen_sponsor.FERRO)


@pytest.fixture
def s4_session(reviewed14_sandbox_tools, monkeypatch):
    monkeypatch.setattr(config, 'QWEN_API_KEY', '')
    rid = gateway.create_run('enforce', 's4-test')
    world = lumen_world.fresh()
    gateway.WORLDS[rid] = world
    session = gateway.start_session(
        rid, S4['task'] + '\nNeeded files: ' + ', '.join(SOURCES)
        + '\nRecipients: aisha@ferrologistics.example', 's4-test')
    try:
        for path in SOURCES:
            response = gateway.handle_call(session['token'], 'read_file', {'doc_id': path})
            assert response['verdict'] == 'allow', response
            content = response['result']['content']
            assert content['id'] == path
            assert content['body'] == world.doc(path)['body']
        reads = gateway.session_reads(session['session_id'])
        assert set(SOURCES) <= {read['source'] for read in reads if read['kind'] == 'file'}
        yield session, world
    finally:
        gateway.WORLDS.pop(rid, None)


@pytest.mark.parametrize('body,expected', [
    ('Rush surcharge 25%.', (('25%', '20%', lumen_sponsor.CONTRACT, ''),)),
    ('The deadline moved by 5 days.',
     (('5 days', '2', lumen_sponsor.DISPUTE, ''),)),
    ('Total stands at 5,250.', (('5,250', 'SGD 5040', lumen_sponsor.FERRO, ''),)),
    (S4['actions'][-1]['args']['body'], (
        ('25%', '20%', lumen_sponsor.CONTRACT, ''),
        ('5 days', '2', lumen_sponsor.DISPUTE, ''),
        ('5,250', 'SGD 5040', lumen_sponsor.FERRO, ''),
    )),
], ids=['surcharge', 'deadline-shift', 'invoice-total', 'sponsor-s4'])
def test_proven_contradictions_block_r18(s4_session, body, expected):
    session, world = s4_session
    args = deepcopy(S4['actions'][-1]['args'])
    args['body'] = body
    response = gateway.handle_call(session['token'], 'send_email', args, 's4-send')
    assert 'R18' in {reason['rule'] for reason in response['reasons']}, response
    evidence = next(reason['evidence'] for reason in response['reasons']
                    if reason['rule'] == 'R18')
    assert evidence['status'] == 'contradicted', evidence
    assert evidence['safe'] is False
    for fragment, value, path, working in expected:
        claim = next(claim for claim in evidence['claims'] if claim['claim'] == fragment)
        assert claim == {'claim': fragment, 'status': 'contradicted',
                         'real_value': value, 'file': path, 'line': 1, 'working': working}
    assert not world.sent
    assert response['verdict'] == 'block', response
    assert not response.get('approval_id')


def test_unknown_source_still_holds_r18(s4_session):
    session, world = s4_session
    args = deepcopy(S4['actions'][-1]['args'])
    args['body'] = 'Quantity 7 units.'
    response = gateway.handle_call(session['token'], 'send_email', args, 's4-send')
    assert 'R18' in {reason['rule'] for reason in response['reasons']}, response
    evidence = next(reason['evidence'] for reason in response['reasons']
                    if reason['rule'] == 'R18')
    assert evidence['status'] == 'no_source', evidence
    assert evidence['safe'] is False
    assert evidence['claims'] == [{'claim': '7 units', 'status': 'no_source',
                                  'real_value': None, 'file': None, 'line': None,
                                  'working': ''}]
    assert response['verdict'] == 'hold', response
    assert response['approval_id']
    assert not world.sent
