"""M1 — auth hardening: 600k PBKDF2 rounds with transparent legacy upgrade,
hashed web-session tokens, login-attempt throttling, forced password change
for the fixed demo passwords."""
import hashlib
import re

import pytest
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import auth, db


@pytest.fixture(scope="module")
def client():
    app_module.startup()
    with TestClient(app_module.app) as c:
        yield c


def _login(client, u, p):
    r = client.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    return r.cookies.get("aegis_session") if r.status_code == 303 else None


def _csrf(client, cookie, path="/live"):
    r = client.get(path, cookies={"aegis_session": cookie})
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def test_m1_600k_rounds_and_format():
    assert auth.ITERATIONS == 600_000
    auth.create_user("m1-fresh", "fresh-password-123", "viewer")
    row = db.conn().execute("SELECT pw_hash FROM users WHERE username='m1-fresh'").fetchone()
    assert row["pw_hash"].startswith("pbkdf2:600000:")


def test_m1_legacy_hash_upgraded_on_login():
    salt = b"0123456789abcdef"
    legacy = hashlib.pbkdf2_hmac("sha256", b"legacy-password-1", salt, 200_000).hex()
    db.conn().execute("INSERT INTO users(username,pw_hash,salt,role,must_change) VALUES(?,?,?,?,0)",
                      ("m1-legacy", legacy, salt.hex(), "viewer"))
    db.conn().commit()
    assert auth.login("m1-legacy", "legacy-password-1") is not None
    row = db.conn().execute("SELECT pw_hash FROM users WHERE username='m1-legacy'").fetchone()
    assert row["pw_hash"].startswith("pbkdf2:600000:")


def test_m1_web_tokens_stored_hashed():
    res = auth.login("m1-fresh", "fresh-password-123")
    assert res is not None
    row = db.conn().execute("SELECT token FROM web_sessions ORDER BY created_at DESC LIMIT 1").fetchone()
    assert row["token"] != res["token"]
    assert row["token"] == hashlib.sha256(res["token"].encode()).hexdigest()
    assert auth.user_by_token(res["token"])["username"] == "m1-fresh"


def test_m1_login_throttled_after_repeated_failures():
    auth.create_user("m1-throttle", "correct-password-1", "viewer")
    for _ in range(5):
        assert auth.login("m1-throttle", "wrong") is None
    assert auth.login("m1-throttle", "correct-password-1") is None  # locked out
    events = [r["event"] for r in db.conn().execute("SELECT event FROM audit").fetchall()]
    assert "login_throttled" in events


def test_m1_demo_users_must_change_password():
    for u in ("dana", "ops", "audi"):
        row = db.conn().execute("SELECT must_change FROM users WHERE username=?", (u,)).fetchone()
        assert row["must_change"] == 1


def test_m1_change_password_flow(client):
    auth.create_user("m1-changer", "old-password-123", "admin", must_change=1)
    cookie = _login(client, "m1-changer", "old-password-123")
    assert cookie
    # privileged action refused until the password is changed
    csrf = _csrf(client, cookie, "/admin")
    r = client.post("/admin/default-mode",
                    data={"value": "enforce", "password": "old-password-123", "csrf": csrf},
                    cookies={"aegis_session": cookie})
    assert r.status_code == 403 and "password" in r.text.lower()
    # wrong current password refused
    r = client.post("/change-password",
                    data={"current": "wrong", "new": "new-password-456", "csrf": csrf},
                    cookies={"aegis_session": cookie})
    assert r.status_code == 200 and "refused" in r.text.lower()
    # proper change
    r = client.post("/change-password",
                    data={"current": "old-password-123", "new": "new-password-456", "csrf": csrf},
                    cookies={"aegis_session": cookie}, follow_redirects=False)
    assert r.status_code == 303
    row = db.conn().execute("SELECT must_change FROM users WHERE username='m1-changer'").fetchone()
    assert row["must_change"] == 0
    # now the privileged action works with the new password
    r = client.post("/admin/default-mode",
                    data={"value": "enforce", "password": "new-password-456", "csrf": csrf},
                    cookies={"aegis_session": cookie}, follow_redirects=False)
    assert r.status_code == 303


def test_m1_admin_action_requires_change_for_demo_admin(client):
    cookie = _login(client, "dana", "demo-dana-2026")
    csrf = _csrf(client, cookie, "/admin")
    r = client.post("/admin/default-mode",
                    data={"value": "enforce", "password": "demo-dana-2026", "csrf": csrf},
                    cookies={"aegis_session": cookie})
    assert r.status_code == 403