import json
import secrets
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis import app, approvals, auth, db, gateway, proof_pack
from conftest import make_session
from test_new_attacks_identity import persist, call


@pytest.mark.parametrize('mode', ['off', 'monitor', 'enforce'])
def test_alarm_latches_reads_and_sends(mode, reviewed14_sandbox_tools):
    rid, helper = make_session(mode=mode)
    persist(helper, alarm=dict(helper=helper['session_id'], level='high', reasons=['private reason']))
    assert gateway.handle_call(helper['token'], 'list_inbox', {})['verdict'] == 'block'
    assert gateway._load_card(helper['session_id'])['frozen'] is True
    assert call(helper)['verdict'] == 'block'
    other = gateway.start_session(rid, 'Email Rosa at Acme a greeting.', 'other')
    persist(other)
    assert not gateway._load_card(other['session_id']).get('frozen')
    if mode == 'off':
        assert call(other)['verdict'] == 'allow'


def test_alarm_identity_mismatch(reviewed_sandbox_tools):
    rid, helper = make_session(mode='off')
    other = gateway.start_session(rid, 'Greeting', 'other')
    persist(helper, alarm=dict(helper=other['session_id'], level='high', reasons=[]))
    assert call(helper)['verdict'] == 'block'
    assert not gateway._load_card(other['session_id']).get('frozen')


def test_approval_cannot_release_alarm(reviewed_sandbox_tools):
    rid, helper = make_session('Email Rosa at Acme a greeting.', mode='off')
    persist(helper, alone=[], ask=['send_email'])
    out = call(helper)
    assert out['approval_id']
    persist(helper, alone=[], ask=['send_email'], alarm=dict(helper=helper['session_id'], level='high', reasons=[]))
    result = approvals.decide(out['approval_id'], dict(username='reviewer', role='approver'), 'approve')
    assert result['ok'] is False
    assert not gateway.get_world(rid).sent


def test_admin_routes_and_masked_proof(reviewed_sandbox_tools):
    _, helper = make_session(mode='off')
    persist(helper)
    password = secrets.token_urlsafe(24)
    name = 'freeze-' + uuid.uuid4().hex
    auth.create_user(name, password, 'admin')
    login = auth.login(name, password)
    # Trusted fixture makes this reviewer the helper's authenticated creator.
    db.conn().execute('UPDATE agent_sessions SET created_by=? WHERE id=?', (name, helper['session_id']))
    db.conn().commit()
    client = TestClient(app.app)
    path = '/admin/helpers/' + helper['session_id']
    assert client.post(path + '/freeze', data={'csrf': login['csrf']}, follow_redirects=False).status_code == 303
    client.cookies.set('aegis_session', login['token'])
    assert client.post(path + '/freeze', data={'csrf': 'bad'}).status_code == 403
    start = time.time()
    for operation, frozen in [('freeze', True), ('release', False)]:
        response = client.post(path + '/' + operation, data={'csrf': login['csrf']}, follow_redirects=False)
        assert response.status_code == 303
        assert gateway._load_card(helper['session_id'])['frozen'] is frozen
    context = proof_pack.verify_export_context(login['token'], login['csrf'], password)
    key = Ed25519PrivateKey.generate()
    raw = proof_pack.build_proof_pack(start, time.time()+1, context=context, signing_key=key)
    events = [r for r in json.loads(raw)['payload']['timeline'] if r['event'] in ('helper_frozen', 'helper_released')]
    assert [r['event'] for r in events] == ['helper_frozen', 'helper_released']
    assert events[0]['helper'].startswith('ref:')
    assert all(r['helper'] == events[0]['helper'] for r in events)
    assert helper['session_id'].encode() not in raw
    assert proof_pack.verify_seal(raw, key.public_key())
