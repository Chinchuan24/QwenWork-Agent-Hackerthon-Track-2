"""M4 — a policy with no rules is refused (it would silently disable every
rule), and changing the policy requires a second login (re-authentication),
like the kill switch does."""
import re

import pytest
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import auth, db, policy

VALID = ("rules:\n  - id: M4-TEST\n    explain: test rule\n"
         "    when: {side_effect: true}\n    decision: hold\n")


@pytest.fixture(scope="module")
def client():
    app_module.startup()
    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_cookie(client):
    auth.create_user("m4-admin", "m4-password-123", "admin")
    r = client.post("/login", data={"username": "m4-admin", "password": "m4-password-123"},
                    follow_redirects=False)
    return r.cookies.get("aegis_session")


def _csrf(client, cookie):
    r = client.get("/policies", cookies={"aegis_session": cookie})
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _active_content():
    v = policy.active_version()
    return db.conn().execute("SELECT content FROM policy_versions WHERE version=?", (v,)).fetchone()["content"]


def test_m4_empty_rules_refused_at_validator():
    with pytest.raises(policy.PolicyError):
        policy.validate({"rules": []})


def test_m4_empty_policy_refused_via_http(client, admin_cookie):
    before = policy.active_version()
    csrf = _csrf(client, admin_cookie)
    r = client.post("/policies/activate",
                    data={"content": "rules: []", "password": "m4-password-123", "csrf": csrf},
                    cookies={"aegis_session": admin_cookie})
    assert r.status_code == 200 and "refused" in r.text.lower()
    assert policy.active_version() == before


def test_m4_policy_change_requires_reauth(client, admin_cookie):
    original = _active_content()
    before = policy.active_version()
    csrf = _csrf(client, admin_cookie)
    try:
        # wrong password -> refused, nothing changes
        r = client.post("/policies/activate",
                        data={"content": VALID, "password": "wrong", "csrf": csrf},
                        cookies={"aegis_session": admin_cookie})
        assert r.status_code == 200 and "refused" in r.text.lower()
        assert policy.active_version() == before
        # correct password -> activated
        r = client.post("/policies/activate",
                        data={"content": VALID, "password": "m4-password-123", "csrf": csrf},
                        cookies={"aegis_session": admin_cookie}, follow_redirects=False)
        assert r.status_code == 303
        assert policy.active_version() == before + 1
    finally:
        policy.activate(original, "tests", "restore after M4 test")