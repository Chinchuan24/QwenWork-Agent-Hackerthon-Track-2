"""Delta must fail closed even when policy evaluation returns no matches."""
import uuid
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import gateway, policy, qwen_client
from conftest import make_session


@pytest.mark.parametrize("judge_kind", ["safety_a", "safety_b"])
@pytest.mark.parametrize("answer", ["unsure", "unsafe", "error"])
def test_enforce_send_delta_floor_survives_empty_policy(
    monkeypatch, judge_kind, answer
):
    rid, session = make_session("Email Rosa at Acme a greeting.", mode="enforce")
    world = gateway.get_world(rid)
    sink = Mock(wraps=world.send_email)
    monkeypatch.setattr(world, "send_email", sink)
    seen = []

    def judge(kind, payload, model=None):
        seen.append(kind)
        if kind == judge_kind:
            if answer == "error":
                raise qwen_client.JudgeUnavailable("simulated Delta failure")
            return {"verdict": answer, "reason": "Delta regression fixture"}
        assert kind in ("intent", "safety_a", "safety_b")
        return {"verdict": "yes" if kind == "intent" else "safe"}

    monkeypatch.setattr(qwen_client, "judge", judge)
    evaluate = Mock(return_value=[])
    monkeypatch.setattr(policy, "evaluate", evaluate)

    out = gateway.handle_call(
        session["token"],
        "send_email",
        {"to": "rosa@acme.example", "subject": "Hello", "body": "Hello"},
        uuid.uuid4().hex,
    )

    assert seen == ["intent", "safety_a", "safety_b"]
    evaluate.assert_called()
    assert (sink.call_count, world.sent) == (0, []), (
        f"{judge_kind}={answer} with empty policy reached email sink: {out}"
    )
    assert out["verdict"] in ("hold", "block")
