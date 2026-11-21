"""App security tests: every page and API against every role, forged form
submissions, script injection, headers, policy validation. Written as checks
on the server's responses — no browser needed."""
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient
from aegis.app import app, startup
from aegis import db, auth, policy, gateway


@pytest.fixture
def client():
    startup()
    with TestClient(app) as c:
        yield c


def login(client, username, password):
    r = client.post("/login", data={"username": username, "password": password},
                    follow_redirects=False)
    assert r.status_code == 303
    return r.cookies.get("aegis_session")


def csrf_of(client, cookie, path="/live"):
    r = client.get(path, cookies={"aegis_session": cookie})
    import re
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


PAGES = ["/live", "/approvals", "/audit", "/policies", "/redteam", "/compliance", "/admin"]


def test_pages_require_login(client):
    for p in PAGES:
        r = client.get(p, follow_redirects=False)
        assert r.status_code in (303, 307), p
        assert "/login" in r.headers.get("location", ""), p


def test_role_matrix(client):
    dana = login(client, "dana", "demo-dana-2026")
    ops = login(client, "ops", "demo-ops-2026")
    audi = login(client, "audi", "demo-audi-2026")
    # admin page: admin only
    assert client.get("/admin", cookies={"aegis_session": dana}).status_code == 200
    assert client.get("/admin", cookies={"aegis_session": ops}).status_code == 403
    assert client.get("/admin", cookies={"aegis_session": audi}).status_code == 403
    # audit export: admin + auditor
    assert client.get("/audit/export.json", cookies={"aegis_session": audi}).status_code == 200
    assert client.get("/audit/export.json", cookies={"aegis_session": ops}).status_code == 403
    # everyone logged in can view the main screens
    for cookie in (dana, ops, audi):
        for p in ("/live", "/approvals", "/audit", "/policies", "/redteam", "/compliance"):
            assert client.get(p, cookies={"aegis_session": cookie}).status_code == 200


def test_csrf_rejected(client):
    dana = login(client, "dana", "demo-dana-2026")
    r = client.post("/live/run", data={"scenario": "demo:S1", "mode": "enforce", "csrf": "forged"},
                    cookies={"aegis_session": dana})
    assert r.status_code == 403
    r = client.post("/admin/kill", data={"value": "on", "password": "demo-dana-2026", "csrf": "forged"},
                    cookies={"aegis_session": dana})
    assert r.status_code == 403


def test_kill_switch_requires_reauth(client):
    dana = login(client, "dana", "demo-dana-2026")
    csrf = csrf_of(client, dana, "/admin")
    r = client.post("/admin/kill", data={"value": "on", "password": "wrong", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 200 and "Re-authentication failed" in r.text
    from aegis import db as _db
    assert _db.get_setting("kill_switch", "off") == "off"


def test_default_mode_cannot_be_off(client):
    dana = login(client, "dana", "demo-dana-2026")
    csrf = csrf_of(client, dana, "/admin")
    r = client.post("/admin/default-mode", data={"value": "off", "password": "demo-dana-2026", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 403


def test_xss_escaped_everywhere(client):
    dana = login(client, "dana", "demo-dana-2026")
    payload = '<script>alert(1)</script>'
    rid = gateway.create_run("enforce", "dana")
    gateway.start_session(rid, payload + " for Acme", "dana")
    r = client.get("/live", cookies={"aegis_session": dana})
    assert "<script>alert(1)</script>" not in r.text
    # task text appears escaped on the run page
    r = client.get(f"/run/{rid}", cookies={"aegis_session": dana})
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_security_headers(client):
    r = client.get("/login")
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_bad_policy_refused_previous_stays(client):
    dana = login(client, "dana", "demo-dana-2026")
    csrf = csrf_of(client, dana, "/policies")
    before = policy.active_version()
    r = client.post("/policies/activate",
                    data={"content": "rules:\n  - id: BAD\n    explain: x\n    when: {not_a_condition: true}\n    decision: block",
                          "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 200 and "refused" in r.text
    assert policy.active_version() == before
    # non-admin cannot activate
    ops = login(client, "ops", "demo-ops-2026")
    r = client.post("/policies/activate", data={"content": "rules: []", "csrf": "x"},
                    cookies={"aegis_session": ops})
    assert r.status_code == 403


def test_agent_token_cannot_start_sessions(client):
    # session creation is a human-login form only; agent API has no such route
    _, s = None, None
    rid = gateway.create_run("enforce", "dana")
    s = gateway.start_session(rid, "Help Acme with the report.", "dana")
    r = client.post("/api/agent/session", headers={"X-Agent-Token": s["token"]})
    assert r.status_code == 200
    # the token cannot create runs or sessions through any API
    client.cookies.clear()
    r = client.post("/live/run", data={"scenario": "demo:S1", "mode": "enforce"},
                    headers={"X-Agent-Token": s["token"]}, follow_redirects=False)
    assert r.status_code in (303, 307)  # bounced to login, not executed
    r = client.post("/api/agent/call", json={"tool": "start_session"},
                    headers={"X-Agent-Token": s["token"]})
    assert r.json()["verdict"] == "block"


def test_invalid_login(client):
    r = client.post("/login", data={"username": "dana", "password": "wrong"})
    assert r.status_code == 200 and "Invalid" in r.text


def test_off_run_admin_only(client):
    # Trusted fixture setup: test role policy, not published-password gating.
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='ops'")
    db.conn().commit()
    ops = login(client, "ops", "demo-ops-2026")
    csrf = csrf_of(client, ops)
    r = client.post("/live/run", data={"scenario": "demo:S1", "mode": "off", "csrf": csrf},
                    cookies={"aegis_session": ops})
    assert r.status_code == 200
    assert "UNPROTECTED BASELINE" not in r.text  # off skipped for non-admin


def test_http_password_change_preserves_only_current_session(client):
    auth.create_user('http-session-change', 'old-http-password', 'viewer', must_change=1)
    first = auth.login('http-session-change', 'old-http-password')
    other = auth.login('http-session-change', 'old-http-password')
    client.cookies.clear()
    client.cookies.set('aegis_session', first['token'])
    response = client.post('/change-password', data={
        'current': 'old-http-password', 'new': 'new-http-password',
        'csrf': first['csrf']}, follow_redirects=False)
    assert response.status_code == 303
    assert auth.user_by_token(first['token'])['must_change'] == 0
    assert auth.user_by_token(other['token']) is None
    client.cookies.clear()
