"""Independent factual reviews must survive failures and approval release."""
from copy import deepcopy
import json
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, config, db, gateway, qwen_client
from conftest import make_session


SEND = {"to": "rosa@acme.example", "subject": "Hello", "body": "Hello",
        "attachment_ids": []}


def test_judge_inputs_are_independent(monkeypatch):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    args = deepcopy(SEND)
    original = qwen_client.judge
    seen = []

    def judge(kind, payload, model=None):
        if kind == "intent":
            payload["args"]["body"] = "intent mutation"
            return {"verdict": "yes"}
        if kind in ("safety_a", "safety_b"):
            seen.append(deepcopy(payload))
            payload["args"]["attachment_ids"].append("mutation")
            payload["verdict"] = "safe"
            return {"verdict": "safe", "reason": "private verdict"}
        return original(kind, payload, model=model)

    monkeypatch.setattr(qwen_client, "judge", judge)
    out = gateway.handle_call(session["token"], "send_email", args, uuid.uuid4().hex)
    assert out["verdict"] == "allow"
    assert len(seen) == 2 and seen[0] == seen[1]
    assert seen[0]["args"] == SEND
    assert "verdict" not in seen[1]
    assert args == SEND
    assert gateway.get_world(rid).sent[0]["body"] == "Hello"


@pytest.mark.parametrize("broken", [RuntimeError("crash"), None, {}, {"verdict": "bogus"}])
def test_first_judge_failure_still_invokes_delta(monkeypatch, broken):
    _, session = make_session("Email Rosa at Acme a greeting.")
    original = qwen_client.judge
    seen = []

    def judge(kind, payload, model=None):
        if kind in ("safety_a", "safety_b"):
            seen.append(kind)
            if kind == "safety_a":
                if isinstance(broken, Exception):
                    raise broken
                return broken
            return {"verdict": "safe"}
        return original(kind, payload, model=model)

    monkeypatch.setattr(qwen_client, "judge", judge)
    out = gateway.handle_call(session["token"], "send_email", deepcopy(SEND), uuid.uuid4().hex)
    assert seen == ["safety_a", "safety_b"]
    assert out["verdict"] in ("hold", "block")


@pytest.mark.parametrize("release", ["safe", "unsafe", "error"])
def test_approval_reruns_delta_and_preserves_reviewable_refund(monkeypatch, release):
    rid, session = make_session("Process the large refund Cirrus Health asked for (INV-3008).")
    out = gateway.handle_call(session["token"], "issue_refund",
                              {"invoice_id": "INV-3008"}, uuid.uuid4().hex)
    assert out["verdict"] == "hold"
    original = qwen_client.judge
    seen = []

    def judge(kind, payload, model=None):
        if kind in ("safety_a", "safety_b"):
            seen.append((kind, deepcopy(payload)))
            if kind == "safety_b" and release == "error":
                raise RuntimeError("release failure")
            if kind == "safety_b" and release == "unsafe":
                return {"verdict": "unsafe"}
        return original(kind, payload, model=model)

    monkeypatch.setattr(qwen_client, "judge", judge)
    user = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    result = approvals.decide(out["approval_id"], user, "approve",
                              reason="Synthetic human review: approve the requested Cirrus refund.")
    assert [kind for kind, _ in seen] == ["safety_a", "safety_b"]
    assert seen[0][1] == seen[1][1]
    assert result["ok"] is (release == "safe")
    assert len(gateway.get_world(rid).refunds) == (1 if release == "safe" else 0)


@pytest.mark.parametrize("kind", ["safety_a", "safety_b"])
def test_live_review_includes_authorization_facts(monkeypatch, kind):
    monkeypatch.setattr(config, "live_mode", lambda: True)
    seen = []

    def live(model, system, user):
        seen.append(user)
        return json.dumps({"verdict": "unsure"})

    monkeypatch.setattr(qwen_client, "_live_call", live)
    qwen_client.judge(kind, {"task": "Refund invoice", "tool": "issue_refund", "args": {},
                            "known_recipient": False, "automatic_refund_cap": 1234})
    assert '"known_recipient": false' in seen[0]
    assert '"automatic_refund_cap": 1234' in seen[0]
