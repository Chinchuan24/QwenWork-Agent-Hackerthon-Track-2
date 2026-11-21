import secrets


def test_memory_expiry_forget_restart():
    from scripts.local_key_settings import SecretStore
    now = [10.0]
    store = SecretStore(clock=lambda: now[0])
    key = secrets.token_urlsafe(48)
    store.paste('deepseek', '', '', key)
    assert bool(store.snapshot())
    assert key not in str(store.metadata())
    now[0] += 28800
    assert store.snapshot() is None
    store.paste('qwen', '', '', key)
    store.forget()
    assert store.snapshot() is None
    assert SecretStore().snapshot() is None


def test_import_available():
    from scripts.local_key_settings import install


def test_routes_transport_and_release_canary(monkeypatch):
    import json
    from pathlib import Path
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from aegis import app as views, config, provider, qwen_client, db
    from scripts.local_key_settings import install
    key = secrets.token_urlsafe(48)
    user = {'username': 'settings-test', 'role': 'admin', 'csrf': 'csrf'}
    monkeypatch.setattr(views, 'current_user', lambda request: user)
    monkeypatch.setattr(views, 'csrf_ok', lambda request, user, token: token == 'csrf')
    calls = []
    class Reply:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({'choices': [{'message': {'content': 'OK'}}],
                               'usage': {'prompt_tokens': 4, 'completion_tokens': 1}}).encode()
    def fake(request, timeout):
        assert bool(request.get_header('Authorization').endswith(key))
        assert json.loads(request.data)['max_tokens'] == 8
        calls.append(1)
        return Reply()
    monkeypatch.setattr(provider, 'open_pinned', fake)
    monkeypatch.setattr(config, 'LOCAL_AI', config.LOCAL_AI)
    monkeypatch.setattr(config, 'LIVE_RETRIES', config.LIVE_RETRIES)
    monkeypatch.setattr(config, 'live_mode', config.live_mode)
    monkeypatch.setattr(config, 'provider_snapshot', None, raising=False)
    app = FastAPI()
    install(app)
    client = TestClient(app)
    assert client.post('/local-demo/settings/paste', data={'key': key}).status_code == 403
    response = client.post('/local-demo/settings/paste', data={
        'csrf': 'csrf', 'key': key, 'provider': 'deepseek'})
    assert response.status_code == 200
    assert key not in response.text
    assert 'type="password"' in response.text and 'value=""' in response.text
    response = client.post('/local-demo/settings/test', data={'csrf': 'csrf'})
    assert 'PASS:' in response.text
    assert len(calls) == 1
    assert key not in response.text
    client.post('/local-demo/settings/forget', data={'csrf': 'csrf'})
    assert app.state.local_secret_store.snapshot() is None
    user['role'] = 'viewer'
    assert client.get('/local-demo/settings').status_code == 403
    assert client.post('/local-demo/settings/forget', data={'csrf': 'csrf'}).status_code == 403
    root = Path(__file__).resolve().parents[1]
    assert not any(key.encode() in path.read_bytes() for path in root.rglob('*')
                   if path.is_file() and not path.is_symlink())
