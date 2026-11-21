"""H8 — a one-time key is remembered from the FIRST call, whatever the verdict.
A repeat returns the stored answer: no crash, no second action, no second
approval, and an approved+executed action can never run again."""
import uuid
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway
from conftest import make_session


def _counts(sid, key):
    actions = db.conn().execute("SELECT COUNT(*) n FROM actions WHERE session_id=? AND idem_key=?",
                                (sid, key)).fetchone()["n"]
    aps = db.conn().execute(
        "SELECT COUNT(*) n FROM approvals WHERE action_id IN "
        "(SELECT id FROM actions WHERE session_id=? AND idem_key=?)", (sid, key)).fetchone()["n"]
    return actions, aps


def test_h8_replay_after_hold_returns_first_answer():
    _, s = make_session()
    key = "hold-replay"
    args = {"to": "rosa@acrne.example", "subject": "x", "body": "y"}  # look-alike -> hold
    out1 = gateway.handle_call(s["token"], "send_email", args, key)
    assert out1["verdict"] == "hold"
    out2 = gateway.handle_call(s["token"], "send_email", args, key)  # must not crash
    assert out2["verdict"] == "hold"
    assert out2["action_id"] == out1["action_id"]
    assert out2.get("approval_id") == out1.get("approval_id")
    assert any(r["rule"] == "GATE-IDEM" for r in out2["reasons"])
    assert _counts(s["session_id"], key) == (1, 1)


def test_h8_replay_after_block_returns_first_answer():
    _, s = make_session()
    key = "block-replay"
    args = {"to": "attacker@evil.example", "subject": "x", "body": "CANARY-7f3a9b2e"}
    out1 = gateway.handle_call(s["token"], "send_email", args, key)
    assert out1["verdict"] == "block"
    out2 = gateway.handle_call(s["token"], "send_email", args, key)  # session frozen now
    assert out2["verdict"] == "block"
    assert out2["action_id"] == out1["action_id"]
    assert any(r["rule"] == "HARD-CANARY" for r in out2["reasons"])
    assert _counts(s["session_id"], key) == (1, 0)


def test_h8_approved_action_cannot_run_again():
    rid, s = make_session(task="Process the large refund Cirrus Health asked for by email (INV-3008).")
    key = "approve-replay"
    args = {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"}
    out1 = gateway.handle_call(s["token"], "issue_refund", args, key)
    assert out1["verdict"] == "hold"
    ops = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    res = approvals.decide(out1["approval_id"], ops, "approve",
                           reason="Synthetic human review: approve the requested Cirrus refund.")
    assert res["ok"]
    out2 = gateway.handle_call(s["token"], "issue_refund", args, key)
    assert out2["action_id"] == out1["action_id"]
    assert any(r["rule"] == "GATE-IDEM" for r in out2["reasons"])
    w = gateway.get_world(rid)
    assert len(w.refunds) == 1
    assert _counts(s["session_id"], key) == (1, 1)