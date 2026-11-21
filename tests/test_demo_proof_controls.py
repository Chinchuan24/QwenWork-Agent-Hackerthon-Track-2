import json

import pytest
from fastapi.testclient import TestClient
from aegis import app as web


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(web, 'current_user', lambda request: (
        {'role': 'admin', 'csrf': 'test', 'username': 'operator'}
        if request.cookies.get('aegis_session') else None))
    monkeypatch.setattr(web.gateway, 'kill_switch_on', lambda: False)
    monkeypatch.setattr(web, 'demo_result_path', lambda request:
                        tmp_path / (request.cookies['aegis_session'] + '.json'))
    saved = {'mode': 'scripted stand-in', 'result': {
        'record_projection': [{'record_ref': 'record-7', 'event': 'decision',
                               'detail': {'verdict': 'hold'}}],
        'bindings': [{'story': 'one', 'step': 0, 'record_ref': 'record-7',
                      'reply': {'verdict': 'hold', 'reasons': []}}],
        'scenarios': [{'scenario': 'one', 'evidence': ['saved source']}],
        'guards': [{'record_ref': 'record-7', 'a': {'verdict': 'safe'},
                    'b': {'verdict': 'unsure'}}],
        'briefing': {'proof_ids': ['record-7'], 'text': 'saved briefing'}}}
    (tmp_path / 'first.json').write_text(json.dumps(saved))
    client = TestClient(web.app)
    client.cookies.set('aegis_session', 'first')
    yield client
    client.close()


@pytest.mark.parametrize('view, text', [('source', 'saved source'),
    ('guard', 'unsure'), ('briefing', 'saved briefing'), ('results', 'one'),
    ('proof/record-7', 'hold')])
def test_saved_views_and_access(client, view, text):
    url = '/admin/demo/' + view
    response = client.get(url)
    assert response.status_code == 200
    assert text in response.text
    assert client.get(url, headers={'X-Agent-Token': 'agent'}).status_code == 403
    client.cookies.set('aegis_session', 'second')
    assert client.get(url).status_code == 404
    client.cookies.clear()
    assert client.get(url).status_code == 401


def test_controls_and_unknown_proof(client):
    page = client.get('/admin/demo').text
    for view in ('source', 'guard', 'briefing', 'results', 'proof/record-7'):
        assert 'href="/admin/demo/' + view + '"' in page
    assert client.get('/admin/demo/proof/record-999').status_code == 404


def test_corrupt_storage_fails_closed(client, monkeypatch, tmp_path):
    path = tmp_path / 'broken.json'
    path.write_text('{')
    monkeypatch.setattr(web, 'demo_result_path', lambda request: path)
    assert client.get('/admin/demo/source').status_code == 503
