"""Public production boundary tests, independent of legacy app startup."""
import pytest
from fastapi.testclient import TestClient


def client(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_ENV', 'production')
    monkeypatch.setenv('AEGIS_DEMO_PUBLIC', '1')
    monkeypatch.setenv('AEGIS_PRODUCTION_DATA_DIR', str(tmp_path))
    monkeypatch.setenv('AEGIS_TRUSTED_HOSTS', 'testserver')
    from aegis.production import create_app
    return TestClient(create_app(), base_url='https://testserver', follow_redirects=False)


def test_public_boundary(tmp_path, monkeypatch):
    import re
    with client(tmp_path, monkeypatch) as c:
        readiness = c.get('/readyz').json()
        assert readiness['ready'] and readiness['simulated_hmac']
        assert readiness['signer'] is False
        page = c.get('/')
        assert 'SIMULATED' in page.text
        csrf = re.search('name="csrf" value="([^"]+)"', page.text)[1]
        assert c.post('/session', data={'role': 'admin', 'csrf': csrf}).status_code == 403
        assert c.post('/session', data={'role': 'approver', 'csrf': csrf}).status_code == 303
        for path in ('/', '/world', '/audit', '/roles'):
            r = c.get(path)
            assert r.status_code == 200
            assert 'SIMULATED' in r.text
            assert r.headers['strict-transport-security']
        assert c.post('/reset').status_code == 403
        assert c.post('/worker/start', data={'csrf': csrf}).status_code == 404
        assert c.post('/reset', content=b'x' * 17000).status_code == 413
        assert c.post('/reset', files={'file': ('a', b'a')}).status_code == 415
        assert c.get('/audit/export').json()['outside_effects'] == 0
        assert c.post('/action', data={'csrf': csrf, 'action': 'release'}).status_code == 403
        assert c.post('/reset', data={'csrf': csrf}).status_code == 303
        assert len(c.get('/audit/export').json()['events']) == 2


def test_cookie_injection_and_internal_probe(tmp_path, monkeypatch):
    with client(tmp_path, monkeypatch) as c:
        assert c.get('http://testserver/readyz').status_code == 200
        c.cookies.set('__Host-csrf', '\" autofocus onfocus=alert(1) x=\"')
        assert 'onfocus=alert' not in c.get('/').text


def test_lumen_guard_cases(tmp_path, monkeypatch):
    import re
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        c.post('/session', data={'role': 'approver', 'csrf': csrf})
        assert 'Twinguard oversight of Lumen Studio' in c.get('/world').text
        for case in ('greenstep', 'ferro', 'quickprint', 'audience', 'harbourbean'):
            response = c.post('/action', data={'csrf': csrf, 'action': 'scenario_' + case})
            assert response.status_code == 200
            assert response.json()['sources'] and response.json()['rules']
            if case == 'greenstep':
                assert response.json()['decision'] == 'block'
                assert 'R08' in response.json()['rules']
        events = c.get('/audit/export').json()['events']
        assert events[-2]['event'] == 'lumen_audience_block'
        assert events[-1]['event'] == 'lumen_harbourbean_allow'
        assert (tmp_path / 'db' / 'public-demo.db').exists()
        assert (tmp_path.parent / 'tmp').exists()


def test_debug_refused(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_DEBUG', '1')
    with pytest.raises(ValueError, match='debug'):
        client(tmp_path, monkeypatch)


def test_no_multiworker(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_WORKERS', '2')
    with pytest.raises(ValueError, match='single'):
        client(tmp_path, monkeypatch)


def test_restart_and_isolation(tmp_path, monkeypatch):
    import re
    with client(tmp_path, monkeypatch) as a:
        csrf = re.search('name="csrf" value="([^"]+)"', a.get('/').text)[1]
        a.post('/session', data={'role': 'viewer', 'csrf': csrf})
        key = (tmp_path / 'keys' / 'internal.key').read_bytes()
        assert a.get('/audit/export').json()['events']
    with client(tmp_path, monkeypatch) as b:
        assert (tmp_path / 'keys' / 'internal.key').read_bytes() == key
        assert b.get('/audit/export').status_code == 401
        assert b.get('/readyz').json()['ready']


def test_nightly_generation_preserves_audit(tmp_path, monkeypatch):
    import re
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        c.post('/session', data={'role': 'viewer', 'csrf': csrf})
        c.portal.call(c.app.state.reset_demo_worlds)
        events = c.get('/audit/export').json()['events']
        assert events == [{'generation': 1, 'event': 'session_started'}, {'generation': 2, 'event': 'nightly_reset'}]
        assert 'World generation 2' in c.get('/world').text


def test_missing_persisted_key_refused(tmp_path, monkeypatch):
    with client(tmp_path, monkeypatch) as c:
        assert c.get('/readyz').status_code == 200
    (tmp_path / 'keys' / 'internal.key').unlink()
    with pytest.raises(ValueError, match='original internal key'):
        with client(tmp_path, monkeypatch):
            pass


def test_ip_lockout_and_untrusted_forwarding(tmp_path, monkeypatch):
    import re
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        for _ in range(5):
            assert c.post('/session', data={'role': 'admin', 'csrf': csrf}).status_code == 403
        assert c.post('/session', data={'role': 'viewer', 'csrf': csrf}).status_code == 429
        assert c.get('http://testserver/', headers={'X-Forwarded-Proto': 'https'}).status_code == 400


def test_trusted_proxy_ip_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_TRUSTED_PROXY_CIDRS', '127.0.0.0/8')
    from aegis.production import create_app
    client(tmp_path, monkeypatch)
    with TestClient(create_app(), base_url='http://testserver', client=('127.0.0.1', 12345)) as c:
        first = {'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '192.0.2.1'}
        second = {'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '192.0.2.2'}
        for _ in range(120):
            assert c.get('/', headers=first).status_code == 200
        assert c.get('/', headers=first).status_code == 429
        assert c.get('/', headers=second).status_code == 200
        assert c.get('/', headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '192.0.2.1, 192.0.2.2'}).status_code == 400


def test_event_quota_atomic_admission(tmp_path, monkeypatch):
    import re
    import sqlite3
    monkeypatch.setenv('AEGIS_DEMO_MAX_EVENTS', '2')
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        assert c.post('/session', data={'role': 'approver', 'csrf': csrf}).status_code == 303
        assert c.post('/reset', data={'csrf': csrf}).status_code == 303
        database = sqlite3.connect(tmp_path / 'db' / 'public-demo.db')
        before = database.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
        for path, fields in (('/session', {'role': 'viewer'}), ('/reset', {}), ('/action', {'action': 'simulate_approval'})):
            assert c.post(path, data={'csrf': csrf, **fields}).status_code == 429
        assert len(c.get('/audit/export').json()['events']) == 2
        assert 'World generation 2' in c.get('/world').text
        assert database.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == before
        assert c.get('/readyz').status_code == 503
        assert c.get('/healthz').json()['live']
        c.portal.call(c.app.state.reset_demo_worlds)
        assert database.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
        database.close()
    with client(tmp_path, monkeypatch) as c:
        assert c.get('/healthz').status_code == 200
        assert c.get('/readyz').status_code == 503


def test_concurrent_last_event_slot(tmp_path, monkeypatch):
    import re
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setenv('AEGIS_DEMO_MAX_EVENTS', '2')
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        c.post('/session', data={'role': 'approver', 'csrf': csrf})
        def submit(_):
            return c.post('/action', data={'csrf': csrf, 'action': 'simulate_approval'}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(submit, range(2))) == [303, 429]
        assert len(c.get('/audit/export').json()['events']) == 2


@pytest.mark.parametrize('peer', ['172.16.11.2', '172.19.10.209', '172.16.10.210', '172.31.255.254'])
def test_fly_deployed_proxy_range(tmp_path, monkeypatch, peer):
    import tomllib
    from pathlib import Path
    config = tomllib.loads((Path(__file__).parents[1] / 'fly.toml').read_text())['env']
    client(tmp_path, monkeypatch)
    for name in ('AEGIS_TRUSTED_PROXY_CIDRS', 'AEGIS_TRUSTED_HOSTS', 'AEGIS_PROXY_PROVIDER'):
        monkeypatch.setenv(name, config[name])
    from aegis.production import create_app
    headers = {'X-Forwarded-Proto': 'https', 'Fly-Client-IP': '192.0.2.10'}
    with TestClient(create_app(), base_url='http://twinguard-demo.fly.dev', client=(peer, 12345)) as c:
        for path in ('/', '/readyz'):
            assert c.get(path, headers=headers).status_code == 200
        assert c.get('/', headers={'Fly-Client-IP': '192.0.2.10'}).status_code == 400
        assert c.get('http://evil.example/', headers=headers).status_code == 400
        assert c.get('/', headers={**headers, 'Fly-Client-IP': '192.0.2.10, 192.0.2.11'}).status_code == 400


@pytest.mark.parametrize('peer', ['172.15.255.254', '172.32.0.1', '192.0.2.10'])
def test_fly_outside_proxy_range_rejected(tmp_path, monkeypatch, peer):
    import tomllib
    from pathlib import Path
    config = tomllib.loads((Path(__file__).parents[1] / 'fly.toml').read_text())['env']
    client(tmp_path, monkeypatch)
    for name in ('AEGIS_TRUSTED_PROXY_CIDRS', 'AEGIS_TRUSTED_HOSTS', 'AEGIS_PROXY_PROVIDER'):
        monkeypatch.setenv(name, config[name])
    from aegis.production import create_app
    with TestClient(create_app(), base_url='http://twinguard-demo.fly.dev', client=(peer, 12345)) as c:
        for path in ('/', '/readyz'):
            assert c.get(path, headers={'X-Forwarded-Proto': 'https', 'Fly-Client-IP': '192.0.2.10'}).status_code == 400


def test_http_and_host_and_rate(tmp_path, monkeypatch):
    with client(tmp_path, monkeypatch) as c:
        assert c.get('http://testserver/', follow_redirects=False).status_code == 400
        assert c.get('https://evil.example/').status_code == 400
        statuses = [c.get('/healthz').status_code for _ in range(125)]
        assert 429 in statuses
