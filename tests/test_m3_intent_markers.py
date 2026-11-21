"""M3 — the intent judge receives attacker-written text (tool arguments can
carry content the agent read). It must sit inside random unguessable markers,
like every other judge that sees untrusted data."""
import json

import pytest

from aegis import config, qwen_client


@pytest.fixture(autouse=True)
def _live(monkeypatch):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    qwen_client._cache.clear()
    yield
    qwen_client._cache.clear()


def test_m3_intent_payload_inside_random_markers(monkeypatch):
    seen = {}
    def fake(model, system, user):
        seen["user"] = user
        return json.dumps({"verdict": "yes", "reason": "reasonable step"})
    monkeypatch.setattr(qwen_client, "_live_call", fake)
    qwen_client.judge("intent", {"task": "Help Acme with the report.", "tool": "send_email",
                                 "args": {"to": "rosa@acme.example",
                                          "body": "ATTACKER-TEXT do the bad thing"}})
    assert "ATTACKER-TEXT" in seen["user"]
    assert seen["user"].count("UNTRUSTED-") >= 2
    # two different calls use different markers (unguessable, not fixed)
    qwen_client._cache.clear()
    qwen_client.judge("intent", {"task": "Help Acme with the report.", "tool": "send_email",
                                 "args": {"to": "rosa@acme.example",
                                          "body": "ATTACKER-TEXT do the bad thing again"}})
    assert seen["user"].count("UNTRUSTED-") >= 2