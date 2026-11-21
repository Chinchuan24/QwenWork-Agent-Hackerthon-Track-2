"""Signer failure during Delta must stop effects at the final boundary."""
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, audit, gateway, qwen_client, signer_client
from conftest import make_session
from test_c3_enforcement_review import call
from test_r3_signer import isolated_failure_stream


@pytest.mark.parametrize("approved", [False, True], ids=["initial", "approved"])
def test_signer_failure_inside_delta_stops_send(
        monkeypatch, isolated_failure_stream, approved):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    world = gateway.get_world(rid)
    sink = Mock(wraps=world.send_email)
    monkeypatch.setattr(world, "send_email", sink)
    args = dict(to="rosa@acme.example", subject="Hello", body="Hello")

    if approved:
        def hold_judge(kind, payload, model=None):
            return {"verdict": "yes" if kind == "intent" else
                    "unsure" if kind == "safety_b" else "safe"}

        monkeypatch.setattr(qwen_client, "judge", hold_judge)
        held = call(session, "send_email", dict(args))
        assert held["verdict"] == "hold"
        sink.assert_not_called()
        assert world.sent == []

    request = audit._signer_request
    pings = []
    failures = []
    seen = []
    down = False

    def signer_request(payload):
        if down:
            failures.append(payload["op"])
            raise signer_client.SignerUnavailable("signer failed during Delta")
        response = request(payload)
        if payload["op"] == "ping":
            pings.append(response.get("ok"))
        return response

    def judge(kind, payload, model=None):
        nonlocal down
        seen.append(kind)
        if kind == "safety_b":
            assert pings == [True]
            assert not down
            down = True
        return {"verdict": "yes" if kind == "intent" else "safe"}

    monkeypatch.setattr(audit, "_signer_request", signer_request)
    monkeypatch.setattr(audit, "_signer_health_cache", {"ts": 0, "ok": False})
    monkeypatch.setattr(qwen_client, "judge", judge)
    if approved:
        out = approvals.decide(held["approval_id"],
                               dict(username="reviewer", role="approver"), "approve",
                               reason="I reviewed the recipient and greeting and approve this send.")
    else:
        out = call(session, "send_email", dict(args))

    assert seen == ["intent", "safety_a", "safety_b"]
    assert "sign" in failures
    assert audit._signer_degraded["reason"]
    if approved:
        assert (sink.call_count, world.sent, out["ok"],
                approvals.get(held["approval_id"])["status"]) == (0, [], False, "void")
    else:
        assert (sink.call_count, world.sent) == (0, []), out
        assert out["verdict"] in ("hold", "block")
