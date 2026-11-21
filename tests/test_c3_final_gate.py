"""Card revocation during Delta must stop sends at the final sink boundary."""
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway, qwen_client
from conftest import make_session
from test_c3_enforcement_review import call, save_card


SEND = dict(to="rosa@acme.example", subject="Hello", body="Hello")


def revoke_card(session, mutation):
    if mutation == "deleted":
        db.conn().execute("DELETE FROM helper_cards WHERE helper_id=?",
                          (session["session_id"],))
        db.conn().commit()
    else:
        save_card(session, frozen=True)


@pytest.mark.parametrize("mutation", ["deleted", "frozen"])
def test_initial_send_rechecks_card_after_delta(monkeypatch, mutation):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    w = gateway.get_world(rid)
    sink = Mock(wraps=w.send_email)
    monkeypatch.setattr(w, "send_email", sink)
    seen = []

    def judge(kind, payload, model=None):
        seen.append(kind)
        if kind == "safety_b":
            assert gateway._load_card(session["session_id"]).get("frozen", False) is False
            revoke_card(session, mutation)
        return {"verdict": "yes" if kind == "intent" else "safe"}

    monkeypatch.setattr(qwen_client, "judge", judge)
    out = call(session, "send_email", dict(SEND))

    assert seen == ["intent", "safety_a", "safety_b"]
    assert (sink.call_count, w.sent) == (0, []), (
        f"{mutation} card during Delta reached initial email sink: {out}"
    )
    assert out["verdict"] == "block"
    assert any(reason["rule"] == "HARD-CARD" for reason in out["reasons"])


@pytest.mark.parametrize("mutation", ["deleted", "frozen"])
def test_approved_release_rechecks_card_after_delta(monkeypatch, mutation):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    w = gateway.get_world(rid)
    sink = Mock(wraps=w.send_email)
    monkeypatch.setattr(w, "send_email", sink)

    def hold_judge(kind, payload, model=None):
        return {"verdict": "yes" if kind == "intent" else
                "unsure" if kind == "safety_b" else "safe"}

    monkeypatch.setattr(qwen_client, "judge", hold_judge)
    held = call(session, "send_email", dict(SEND))
    assert held["verdict"] == "hold"
    sink.assert_not_called()
    assert w.sent == []
    seen = []

    def release_judge(kind, payload, model=None):
        seen.append(kind)
        if kind == "safety_b":
            assert gateway._load_card(session["session_id"]).get("frozen", False) is False
            revoke_card(session, mutation)
        return {"verdict": "yes" if kind == "intent" else "safe"}

    monkeypatch.setattr(qwen_client, "judge", release_judge)
    user = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    out = approvals.decide(held["approval_id"], user, "approve",
                           reason="I reviewed the recipient and greeting and approve this send.")

    assert seen == ["intent", "safety_a", "safety_b"]
    assert (sink.call_count, w.sent) == (0, []), (
        f"{mutation} card during Delta reached approved email sink: {out}"
    )
    assert out["ok"] is False
    assert approvals.get(held["approval_id"])["status"] == "void"
    action = db.conn().execute("SELECT status, executed_at FROM actions WHERE id=?",
                               (held["action_id"],)).fetchone()
    assert action["status"] == "blocked"
    assert action["executed_at"] is None
