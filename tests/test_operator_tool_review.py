import json
import re

import pytest
from fastapi.testclient import TestClient
from aegis import app as web


@pytest.fixture
def client():
    previous = web.db.get_setting('sandbox_tool_approvals', '')
    web.db.set_setting('sandbox_tool_approvals', '', 'isolated-test', 0)
    web.auth.create_user('review-operator', 'review-password-123', 'admin')
    login = web.auth.login('review-operator', 'review-password-123')
    client = TestClient(web.app)
    client.cookies.set('aegis_session', login['token'])
    client.csrf = login['csrf']
    yield client
    client.close()
    web.db.set_setting('sandbox_tool_approvals', previous, 'isolated-test', 0)
    web.db.conn().execute("DELETE FROM web_sessions WHERE user_id IN (SELECT id FROM users WHERE username='review-operator')")
    web.db.conn().execute("DELETE FROM users WHERE username='review-operator'")
    web.db.conn().commit()


def submission(client):
    page = client.get('/admin/tools/review')
    assert page.status_code == 200
    return {'csrf': client.csrf, 'password': 'review-password-123',
            'confirm': 'approve', 'snapshot_digest': re.search(
                r'name="snapshot_digest" value="([a-f0-9]+)"', page.text)[1]}


def test_review_is_read_only_and_explicit(client):
    data = submission(client)
    assert web.db.get_setting('sandbox_tool_approvals', '') == ''
    for field in ('csrf', 'password', 'confirm'):
        assert client.post('/admin/tools/review', data=dict(data, **{field: ''})).status_code == 403
        assert web.db.get_setting('sandbox_tool_approvals', '') == ''
    response = client.post('/admin/tools/review', data=data)
    assert response.status_code == 200
    assert 'receipt' in response.text.lower()
    baseline = json.loads(web.db.get_setting('sandbox_tool_approvals'))
    assert baseline['version'] == 1
    assert len(web.gateway.tool_schemas()) == len(baseline['approved_records'])
    assert client.post('/admin/tools/review', data=data).status_code == 409
    assert client.post('/admin/tools/review', data=submission(client)).status_code == 200
    assert json.loads(web.db.get_setting('sandbox_tool_approvals'))['version'] == 2


def test_changed_manifest_and_missing_auth(client, monkeypatch):
    data = submission(client)
    monkeypatch.setitem(web.gateway.WORKER_TOOL_DESCRIPTIONS, 'read_email', 'Changed description')
    assert client.post('/admin/tools/review', data=data).status_code == 409
    assert web.db.get_setting('sandbox_tool_approvals', '') == ''
    assert client.get('/admin/tools/review', headers={'X-Agent-Token': 'x'}).status_code == 403
    client.cookies.clear()
    assert client.get('/admin/tools/review').status_code == 403
    assert client.post('/admin/tools/review', data=data).status_code == 403


def test_demo_blocker_links_review(client):
    response = client.post('/admin/demo/run', data={'csrf': client.csrf})
    assert response.status_code == 409
    assert '/admin/tools/review' in response.text
