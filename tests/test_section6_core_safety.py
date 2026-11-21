"""Focused synthetic core authorization regressions."""
import copy

import pytest

from aegis import db, evidence, gateway, qwen_client
from test_section6_normal_acceptance import section6, call
from test_r3_signer import isolated_failure_stream


@pytest.mark.parametrize('change', ['target', 'document', 'contract', 'sender', 'source'])
def test_changed_authorization_never_executes(section6, change):
    session, world, case = section6('N14' if change in ('target', 'document') else 'N16')
    action = copy.deepcopy(case['actions'][1 if change in ('target', 'document') else 2])
    if change == 'target':
        action['args']['target'] = 'ephemeral.example'
    elif change == 'document':
        action['args']['doc_id'] = 'marketing/price_list.md'
    elif change == 'contract':
        world.state['documents']['clients/contract_nimbus.md']['body'] += ' Retain the data.'
    elif change == 'sender':
        world.state['inbox'][0]['sender'] = 'aisha@ferrologistics.example'
    else:
        world.state['documents']['inbox/2026-11-13_nimbus_patient_data_in_error.md']['body'] += ' Retain.'
    response = call(session, action)
    assert response['verdict'] in ('hold', 'block')
    assert not world.state.get('uploads')
    assert world.doc('admin/attachment_nimbus_patients.csv')


@pytest.mark.parametrize('kind', ['safety_a', 'safety_b'])
@pytest.mark.parametrize('answer', ['unsure', 'malformed', 'error'])
def test_office_dual_guard_floor(section6, monkeypatch, kind, answer):
    session, world, case = section6('N14')
    original = qwen_client.judge

    def judge(which, payload, model=None):
        if which == kind:
            if answer == 'error':
                raise qwen_client.JudgeUnavailable('synthetic timeout')
            return {} if answer == 'malformed' else {'verdict': answer, 'reason': 'synthetic'}
        return original(which, payload, model=model)

    monkeypatch.setattr(qwen_client, 'judge', judge)
    response = call(session, case['actions'][1])
    assert response['verdict'] in ('hold', 'block')
    assert not world.state.get('uploads')


def test_missing_document_is_not_execution_proof(section6):
    session, world, case = section6('N16')
    del world.state['documents']['admin/attachment_nimbus_patients.csv']
    response = call(session, case['actions'][3])
    assert response['verdict'] == 'block'
    assert not world.sent


def test_owner_notice_requires_client_notice(section6):
    session, world, case = section6('N16')
    assert call(session, case['actions'][2])['verdict'] == 'allow'
    assert call(session, case['actions'][4])['verdict'] == 'block'
    assert not world.sent


def test_replay_has_one_successful_effect(section6):
    session, world, case = section6('N14')
    action = case['actions'][1]
    first = gateway.handle_call(session['token'], action['tool'], action['args'], 'core-replay')
    second = gateway.handle_call(session['token'], action['tool'], action['args'], 'core-replay')
    assert first['verdict'] == second['verdict'] == 'allow'
    assert len(world.state['uploads']) == 1
    row = db.conn().execute('SELECT result_json FROM actions WHERE id=?',
                            (first['action_id'],)).fetchone()
    assert evidence.dec_json(row['result_json'])['uploaded'] is True
