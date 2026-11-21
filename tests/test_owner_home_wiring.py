"""HTTP regressions for the stored-evidence owner home."""
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from aegis import audit, auth, db, evidence, gateway
from aegis import app as web


@pytest.fixture
def client():
    return TestClient(web.app)


def signed_in(client, username='dana'):
    result = auth.login(username, 'demo-' + username + '-2026')
    assert result is not None
    client.cookies.set('aegis_session', result['token'])
    return auth.user_by_token(result['token'])


def test_anonymous_root_redirects_without_reading_evidence(client, monkeypatch):
    read = Mock(side_effect=AssertionError('anonymous evidence read'))
    monkeypatch.setattr(evidence, 'dec_json', read)
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/login'
    read.assert_not_called()


def test_authenticated_root_renders_real_encrypted_evidence(client):
    signed_in(client)
    rid = audit.record('decision', {'mode': 'enforce', 'verdict': 'block',
                                   'reasons': [{'reason': 'private-home-sentinel'}]})
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    assert '<h1>What your AI did today</h1>' in response.text
    assert 'A helper tried work that was not allowed. It was stopped.' in response.text
    assert f'href="/audit/record/{rid}"' in response.text
    assert 'private-home-sentinel' not in response.text
    assert 'Written from a template.' in response.text


def test_viewer_never_decrypts_or_claims_zero_activity(client, monkeypatch):
    auth.create_user('home-viewer', 'demo-home-viewer-2026', 'viewer')
    signed_in(client, 'home-viewer')
    read = Mock(side_effect=AssertionError('viewer evidence decrypt'))
    monkeypatch.setattr(evidence, 'dec_json', read)
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    assert "Today's note is not ready." in response.text
    assert '0 were stopped' not in response.text
    read.assert_not_called()


def test_singapore_day_boundary_and_old_pending_request(client, monkeypatch):
    user = signed_in(client)
    monkeypatch.setattr(web, 'current_user', lambda _: user)
    start = datetime(2026, 11, 19, tzinfo=ZoneInfo('Asia/Singapore')).timestamp()
    # Patch only the app clock, not the shared time module or session expiry.
    monkeypatch.setattr(web, 'time', Mock(time=lambda: start + 100))
    rows = [dict(id=91001, ts=start - 1, event='decision',
                 detail_json=evidence.enc_json({'mode': 'enforce', 'verdict': 'block'})),
            dict(id=91002, ts=start, event='decision',
                 detail_json=evidence.enc_json({'mode': 'enforce', 'verdict': 'block'})),
            dict(id=91003, ts=start + 86400, event='decision',
                 detail_json=evidence.enc_json({'mode': 'enforce', 'verdict': 'block'})),
            dict(id=91004, ts=start - 100, event='approval_requested',
                 detail_json=evidence.enc_json({'approval': 'old-request', 'tool': 'delete_file'}))]
    monkeypatch.setattr(web.db, 'conn', Mock(return_value=Mock(
        execute=Mock(side_effect=lambda sql, *args: [] if sql == 'SELECT * FROM approvals'
                     else Mock(fetchall=lambda: rows)))))
    monkeypatch.setattr(web.approvals, 'queue', lambda: [])
    monkeypatch.setattr(web.approvals, 'review_metrics', lambda: {})
    monkeypatch.setattr(web.gateway, 'kill_switch_on', lambda: False)
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    assert '1 were stopped.' in response.text
    assert '1 still waiting.' in response.text
    assert '/audit/record/91002' in response.text
    assert '/audit/record/91004' in response.text
    assert '/audit/record/91001' not in response.text
    assert '/audit/record/91003' not in response.text


def test_real_queue_is_projected_without_private_reasons(client, reviewed14_sandbox_tools):
    signed_in(client)
    run = gateway.create_run('enforce', 'dana')
    session = gateway.start_session(run, 'Process the large refund Cirrus Health asked for by email (INV-3008).', 'dana')
    result = gateway.handle_call(session['token'], 'issue_refund',
                                 {'invoice_id': 'INV-3008', 'source_email': 'em_cirrus_refund_large'}, uuid4().hex)
    assert result['verdict'] == 'hold', result
    approval_id = result['approval_id']
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    assert f'href="/approvals/{approval_id}"' in response.text
    assert 'before deciding.' in response.text
    assert f'action="/approvals/{approval_id}/decide"' not in response.text
    assert 'enc:v2:' not in response.text


def test_empty_history_is_explicit_not_success(client, monkeypatch):
    user = signed_in(client)
    monkeypatch.setattr(web, 'current_user', lambda _: user)
    monkeypatch.setattr(web.db, 'conn', Mock(return_value=Mock(
        execute=Mock(side_effect=lambda sql, *args: [] if sql == 'SELECT * FROM approvals'
                     else Mock(fetchall=lambda: [])))))
    monkeypatch.setattr(web.approvals, 'queue', lambda: [])
    monkeypatch.setattr(web.approvals, 'review_metrics', lambda: {})
    monkeypatch.setattr(web.gateway, 'kill_switch_on', lambda: False)
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    assert 'No events were recorded today.' in response.text
    assert 'went fine.' not in response.text
    assert 'Nothing is waiting for your decision.' in response.text
