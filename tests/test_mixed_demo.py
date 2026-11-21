"""Synthetic keys only, mock transport only; no provider network calls."""
import hashlib
import io
import json
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis.mixed_demo import MixedDemo, RESERVE


def setup(tmp_path, monkeypatch):
    code = secrets.token_urlsafe(32)
    monkeypatch.setenv('AEGIS_LIVE_ACCESS_CODES', 'sha256:' + hashlib.sha256(code.encode()).hexdigest())
    monkeypatch.setenv('AEGIS_QWEN_API_KEY', 'synthetic-test-only')
    demo = MixedDemo(tmp_path / 'budget.db', b'test-only-salt')
    return demo, code


def mock(monkeypatch, verdict='safe', usage=True, failure=False):
    requests = []
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if failure:
                raise TimeoutError('synthetic-test-only')
            response = {'choices': [{'message': {'content': json.dumps({'verdict': verdict, 'reason': 'synthetic-test-only'})}}]}
            if usage:
                response['usage'] = {'prompt_tokens': 100, 'completion_tokens': 10}
            return io.BytesIO(json.dumps(response).encode())
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())
    return requests


def test_public_and_wrong_code_never_network(tmp_path, monkeypatch):
    demo, code = setup(tmp_path, monkeypatch)
    requests = mock(monkeypatch)
    assert not demo.unlock('visitor', secrets.token_urlsafe(32))
    assert demo.evaluate('visitor', '192.0.2.1', {}, {'decision': 'allow'})['model_mode'] == 'SCRIPTED'
    assert not requests
    assert demo.unlock('visitor', code)


@pytest.mark.parametrize('provider', ['qwen', 'deepseek'])
def test_provider_allowlist_and_redaction(tmp_path, monkeypatch, provider):
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', provider)
    monkeypatch.setenv('DEEPSEEK_API_KEY', 'synthetic-test-only')
    demo, code = setup(tmp_path, monkeypatch)
    requests = mock(monkeypatch)
    demo.unlock('visitor', code)
    result = demo.evaluate('visitor', '192.0.2.1', {}, {'decision': 'block'})
    assert result['decision'] == 'block' and result['model_mode'] == 'LIVE'
    assert len(requests) == 2 and all(r.full_url.startswith(demo.base + '/') for r in requests)
    assert 'synthetic-test-only' not in json.dumps(result)


@pytest.mark.parametrize('verdict,usage,failure', [('unsure', True, False), ('invalid', True, False), ('safe', False, False), ('safe', True, True)])
def test_uncertain_and_network_failure_hold(tmp_path, monkeypatch, verdict, usage, failure):
    demo, code = setup(tmp_path, monkeypatch)
    mock(monkeypatch, verdict, usage, failure)
    demo.unlock('visitor', code)
    assert demo.evaluate('visitor', '192.0.2.1', {}, {'decision': 'allow'})['decision'] == 'hold'
    restarted = MixedDemo(demo.database, demo.salt)
    if not usage or failure:
        assert restarted.reserve('other', '192.0.2.2')[0] == 'hold'


@pytest.mark.parametrize('limit', ['SESSION_CALLS', 'IP_DAILY_CALLS', 'DAILY_CALLS', 'DAILY_TOKENS', 'MONTHLY_TOKENS'])
def test_caps_fallback(tmp_path, monkeypatch, limit):
    monkeypatch.setenv('AEGIS_LIVE_' + limit, '1')
    demo, code = setup(tmp_path, monkeypatch)
    requests = mock(monkeypatch)
    demo.unlock('visitor', code)
    result = demo.evaluate('visitor', '192.0.2.1', {}, {'decision': 'allow'})
    assert result['model_mode'] == 'SCRIPTED' and not requests


def test_concurrent_reservations_and_persistent_privacy(tmp_path, monkeypatch):
    demo, _ = setup(tmp_path, monkeypatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: demo.reserve('visitor', '192.0.2.1'), range(2)))
    assert sorted(r[0] for r in results) == ['hold', 'live']
    with sqlite3.connect(demo.database) as c:
        assert c.execute('SELECT SUM(tokens) FROM live_attempts').fetchone()[0] == RESERVE * 2
        assert all(row[0] != '192.0.2.1' for row in c.execute('SELECT ip FROM live_attempts'))
    assert MixedDemo(demo.database, demo.salt).reserve('visitor', '192.0.2.1')[0] == 'hold'


def test_missing_key_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', 'deepseek')
    monkeypatch.delenv('DEEPSEEK_API_KEY', raising=False)
    demo, code = setup(tmp_path, monkeypatch)
    requests = mock(monkeypatch)
    assert demo.unlock('visitor', code)
    result = demo.evaluate('visitor', '192.0.2.1', {}, {'decision': 'block'})
    assert result['model_mode'] == 'SCRIPTED' and result['decision'] == 'block'
    assert not requests
    with demo.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0] == 0


def test_invalid_provider_and_hash_refused(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', 'http://localhost')
    with pytest.raises(ValueError):
        MixedDemo(tmp_path / 'db', b'salt')
    monkeypatch.setenv('AEGIS_MODEL_PROVIDER', 'qwen')
    monkeypatch.setenv('AEGIS_LIVE_ACCESS_CODES', 'plaintext')
    with pytest.raises(ValueError):
        MixedDemo(tmp_path / 'db', b'salt')
