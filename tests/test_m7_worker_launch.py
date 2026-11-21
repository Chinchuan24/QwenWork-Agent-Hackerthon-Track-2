"""M7 — launching the live worker must be a state-changing POST with CSRF,
bounded in concurrency, cleaned up, and the session token must travel in the
environment, never on the command line where other processes can read it."""
import re

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import config, gateway


@pytest.fixture(scope="module")
def client():
    app_module.startup()
    from aegis import db
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    with TestClient(app_module.app) as c:
        yield c


def _login(client, u, p):
    r = client.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    return r.cookies.get("aegis_session")


def _csrf(client, cookie):
    r = client.get("/live", cookies={"aegis_session": cookie})
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


class FakeProc:
    def __init__(self, alive=True):
        self.pid = 4242
        self._alive = alive
        self.terminated = False

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self.terminated = True
        self._alive = False


def test_m7_get_not_allowed(client):
    dana = _login(client, "dana", "demo-dana-2026")
    r = client.get("/live/agent-run?scenario=demo:S1", cookies={"aegis_session": dana})
    assert r.status_code == 405


def test_m7_post_requires_csrf(client):
    dana = _login(client, "dana", "demo-dana-2026")
    r = client.post("/live/agent-run", data={"scenario": "demo:S1", "csrf": "forged"},
                    cookies={"aegis_session": dana})
    assert r.status_code == 403


def test_m7_token_via_env_not_argv(monkeypatch, client):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    captured = {}
    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env", {})
        return FakeProc()
    monkeypatch.setattr(app_module.subprocess, "Popen", fake_popen)
    app_module.WORKER_PROCS.clear()
    dana = _login(client, "dana", "demo-dana-2026")
    csrf = _csrf(client, dana)
    r = client.post("/live/agent-run", data={"scenario": "demo:S1", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 200, r.text
    assert not any("--token" in a for a in captured["argv"])
    sess_token = captured["env"].get("AEGIS_AGENT_TOKEN", "")
    assert sess_token and not any(sess_token in a for a in captured["argv"])
    assert "AEGIS_QWEN_API_KEY" not in captured["env"]
    app_module.WORKER_PROCS.clear()


def test_m7_concurrency_cap_and_cleanup(monkeypatch, client):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    procs = []
    def fake_popen(argv, **kwargs):
        p = FakeProc()
        procs.append(p)
        return p
    monkeypatch.setattr(app_module.subprocess, "Popen", fake_popen)
    app_module.WORKER_PROCS.clear()
    dana = _login(client, "dana", "demo-dana-2026")
    csrf = _csrf(client, dana)
    for _ in range(config.WORKER_MAX_CONCURRENT):
        r = client.post("/live/agent-run", data={"scenario": "demo:S1", "csrf": csrf},
                        cookies={"aegis_session": dana})
        assert r.status_code == 200
    r = client.post("/live/agent-run", data={"scenario": "demo:S1", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 429 and "workers" in r.json()["error"]
    # finished processes are pruned, freeing a slot
    procs[0]._alive = False
    r = client.post("/live/agent-run", data={"scenario": "demo:S1", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 200
    app_module.WORKER_PROCS.clear()