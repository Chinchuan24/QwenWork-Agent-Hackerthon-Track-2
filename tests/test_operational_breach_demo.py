import json
import secrets

import pytest
from fastapi.testclient import TestClient
from aegis import app as web, auth, db, demo_repeatability, config, gateway


@pytest.fixture
def client():
    username = 'operational-' + secrets.token_hex(6)
    auth.create_user(username, 'private-test-password', 'admin')
    session = auth.login(username, 'private-test-password')
    with TestClient(web.app) as client:
        client.cookies.set('aegis_session', session['token'])
        client.csrf = session['csrf']
        yield client


@pytest.mark.parametrize('path', ['/breach-clock', '/admin/demo'])
def test_routes_mounted(client, path):
    assert client.get(path).status_code == 200


@pytest.mark.parametrize('path', ['/alarm', '/incident-report'])
def test_clock_links(client, path):
    assert 'href="/breach-clock"' in client.get(path).text


@pytest.mark.parametrize('action', ['reset', 'run'])
def test_demo_refuses_missing_approval(client, monkeypatch, action):
    monkeypatch.setattr(db, 'get_setting', lambda *args: 'null')
    monkeypatch.setattr(demo_repeatability, '_launch', lambda *args: pytest.fail('launched'))
    assert client.post('/admin/demo/' + action, data={'csrf': client.csrf}).status_code == 409


@pytest.mark.parametrize('action', ['reset', 'run'])
def test_demo_authorization(client, monkeypatch, action):
    monkeypatch.setattr(demo_repeatability, '_launch', lambda *args: pytest.fail('launched'))
    assert client.post('/admin/demo/' + action, data={'csrf': 'wrong'}).status_code == 403
    assert client.post('/admin/demo/' + action, data={'csrf': client.csrf},
                       headers={'X-Agent-Token': 'helper'}).status_code == 403
    client.cookies.clear()
    assert client.get('/admin/demo').status_code == 401
    assert client.post('/admin/demo/' + action).status_code == 401


def test_demo_saved_registry_and_private_output(client, reviewed14_sandbox_tools, monkeypatch):
    expected = json.loads(db.get_setting('sandbox_tool_approvals'))
    calls = []
    before = (config.DATA_DIR, dict(gateway.WORLDS), db.get_setting('sandbox_tool_approvals'))
    def launch(run, manifest):
        calls.append((run, manifest))
        return {'world_digest': 'synthetic', 'audit_ok': True, 'token': 'SECRET',
                'run_id': 'PRIVATE', 'record_projection': [{'record_ref': 'record-1'}]}, 0.01
    monkeypatch.setattr(demo_repeatability, '_launch', launch)
    for action, run in [('reset', False), ('run', True)]:
        response = client.post('/admin/demo/' + action, data={'csrf': client.csrf}, follow_redirects=False)
        assert response.status_code == 303
        page = client.get('/admin/demo')
        assert 'synthetic' in page.text
        assert 'SECRET' not in page.text and 'PRIVATE' not in page.text
    assert calls == [(False, expected), (True, expected)]
    assert before == (config.DATA_DIR, dict(gateway.WORLDS), db.get_setting('sandbox_tool_approvals'))
    username = 'other-' + secrets.token_hex(6)
    auth.create_user(username, 'private-test-password', 'admin')
    session = auth.login(username, 'private-test-password')
    client.cookies.set('aegis_session', session['token'])
    assert 'synthetic' not in client.get('/admin/demo').text


def test_demo_rejects_request_paths(client, reviewed14_sandbox_tools, monkeypatch):
    monkeypatch.setattr(demo_repeatability, '_launch', lambda *args: pytest.fail('launched'))
    assert client.post('/admin/demo/run', data={'csrf': client.csrf, 'path': '/production'}).status_code == 422


@pytest.mark.parametrize('action', ['reset', 'run'])
def test_real_child(client, reviewed14_sandbox_tools, action):
    before = config.DATA_DIR
    response = client.post('/admin/demo/' + action, data={'csrf': client.csrf}, follow_redirects=False)
    assert response.status_code == 303
    assert 'world_digest' in client.get('/admin/demo').text
    assert config.DATA_DIR == before
