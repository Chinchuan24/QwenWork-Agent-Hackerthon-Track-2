"""B1 — the live Qwen path, tested without a key by simulating the transport.

Every test here drives the REAL live code path (config.live_mode() true) with
_live_call / urlopen replaced by a fake transport. Nothing is hard-coded: the
assertions are about how the app parses, shields and retries real replies.
Actual endpoint/model confirmation against the account needs the key and is
tracked as 'waiting for key' in docs/progress.md.
"""
import json
import urllib.error

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import config, db, gateway, qwen_client
from conftest import make_session


@pytest.fixture(autouse=True)
def _live(monkeypatch):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    qwen_client._cache.clear()
    qwen_client._calls_window.clear()
    yield
    qwen_client._cache.clear()
    qwen_client._calls_window.clear()


@pytest.mark.parametrize("reply", [{}, {"choices": []}, {"choices": [{"message": "invalid"}]}])
def test_malformed_received_response_latches_admission(monkeypatch, reply):
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return json.dumps(reply).encode()
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", lambda *a, **k: Response())
    try:
        with pytest.raises(qwen_client.JudgeUnavailable):
            qwen_client._chat("synthetic-model", [{"role": "user", "content": "synthetic"}])
        assert db.get_setting("model_usage_unknown", "false") == "true"
        with pytest.raises(qwen_client.JudgeUnavailable):
            qwen_client._admit_attempt("live")
    finally:
        db.set_setting("model_usage_unknown", "false", "test-cleanup", 0)


LIMITS_REPLY = json.dumps({
    "verdict": "ok",
    "limits": {"clients": ["acme"], "tools": ["list_inbox", "read_email", "send_email"],
               "external_send": True, "refund": False},
    "reason": "task names Acme",
})


@pytest.mark.parametrize("bad_tokens", [-1, True, "10", None, 1.5])
def test_unreadable_usage_latches_future_admission(monkeypatch, bad_tokens):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "synthetic"}}],
                               "usage": {"prompt_tokens": bad_tokens,
                                         "completion_tokens": 1}}).encode()

    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", lambda *a, **k: Response())
    with pytest.raises(qwen_client.JudgeUnavailable, match="usage unreadable"):
        qwen_client._chat("synthetic-model", [{"role": "user", "content": "synthetic"}])
    assert db.get_setting("model_usage_unknown", "false") == "true"
    try:
        with pytest.raises(qwen_client.JudgeUnavailable):
            qwen_client._admit_attempt("live")
    finally:
        db.set_setting("model_usage_unknown", "false", "test-cleanup", 0)


def test_b1a_nested_limits_reply_is_parsed(monkeypatch):
    """The limits reply is nested JSON; the reader must not require flat JSON."""
    monkeypatch.setattr(qwen_client, "_live_call", lambda *a, **k: LIMITS_REPLY)
    out = qwen_client.judge("limits", {"task": "Help Acme Industries with the Q3 report."})
    assert out["verdict"] == "ok", out
    assert out["limits"]["clients"] == ["acme"]


def test_b1a_live_session_gets_acme_limits(monkeypatch):
    monkeypatch.setattr(qwen_client, "_live_call", lambda *a, **k: LIMITS_REPLY)
    rid = gateway.create_run("enforce", "dana")
    sess = gateway.start_session(rid, "Help Acme Industries with their Q3 report request from Rosa.", "dana")
    assert sess["limits_mode"] == "live"
    assert sess["limits"]["clients"] == ["acme"]
    assert "send_email" in sess["limits"]["tools"]


def test_b1b_unreadable_injection_reply_holds_without_crash(monkeypatch):
    """An unreadable injection verdict must fail closed: no crash, content
    withheld, session suspicious, later side effect held, audit recorded."""
    def fake(model, system, user):
        if "security classifier" in system:
            return "Sorry, I cannot produce that JSON."
        return LIMITS_REPLY
    monkeypatch.setattr(qwen_client, "_live_call", fake)
    rid = gateway.create_run("enforce", "dana")
    sess = gateway.start_session(rid, "Help Acme Industries with their Q3 report request from Rosa.", "dana")
    out = gateway.handle_call(sess["token"], "read_email", {"email_id": "em_task_note"}, None)
    assert out["verdict"] in ("allow", "hold")          # read itself never crashes
    assert "withheld" in json.dumps(out.get("result", {}))
    row = db.conn().execute("SELECT suspicious FROM agent_sessions WHERE id=?",
                            (sess["session_id"],)).fetchone()
    assert row["suspicious"] == 1
    out2 = gateway.handle_call(sess["token"], "send_email",
                               {"to": "rosa@acme.example", "subject": "x", "body": "y"}, "k1")
    assert out2["verdict"] in ("hold", "block")
    events = [r["event"] for r in db.conn().execute("SELECT event FROM audit").fetchall()]
    assert "shield_unsure" in events


def test_b1c_worker_tool_schemas_have_real_types():
    tools = {t["function"]["name"]: t["function"] for t in gateway.tool_schemas()}
    send = tools["send_email"]["parameters"]
    assert send["properties"]["attachment_ids"]["type"] == "array"
    assert send["properties"]["attachment_ids"]["items"]["type"] == "string"
    refund = tools["issue_refund"]["parameters"]
    assert refund["properties"]["amount"]["type"] == "number"
    assert "to" in send["required"] and "invoice_id" in refund["required"]


def test_b1d_leak_judge_receives_confidential_text_in_markers(monkeypatch):
    seen = {}
    def fake(model, system, user):
        seen["user"] = user
        return json.dumps({"verdict": "no", "reason": "nothing confidential"})
    monkeypatch.setattr(qwen_client, "_live_call", fake)
    qwen_client.judge("leak", {
        "outgoing": "here is the summary", "external": True, "recipient_client": "acme",
        "confidential_reads": [{"source": "doc_acme_q3", "client": "acme",
                                "body": "revenue 4.2M, northern corridor strategy"}]})
    assert "4.2M" in seen["user"] and "northern corridor" in seen["user"]
    assert seen["user"].count("UNTRUSTED-") >= 2  # random markers around the data


def test_b1e_failed_call_retried_with_pause_then_succeeds(monkeypatch):
    calls = {"n": 0}
    sleeps = []
    class Resp:
        def read(self):
            return json.dumps({"choices": [{"message": {"content": LIMITS_REPLY}}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 5}}).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def flaky(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("simulated network failure")
        return Resp()
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", flaky)
    monkeypatch.setattr(qwen_client.time, "sleep", lambda s: sleeps.append(s))
    out = qwen_client.judge("limits", {"task": "Help Acme with the report."})
    assert out["verdict"] == "ok"
    assert calls["n"] == 3
    assert len(sleeps) == 2 and all(s > 0 for s in sleeps)


def test_b1e_persistent_failure_fails_closed(monkeypatch):
    calls = {"n": 0}
    def dead(req, timeout=None):
        calls["n"] += 1
        raise urllib.error.URLError("simulated outage")
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", dead)
    monkeypatch.setattr(qwen_client.time, "sleep", lambda s: None)
    with pytest.raises(qwen_client.JudgeUnavailable):
        qwen_client.judge("intent", {"task": "t", "tool": "list_inbox", "args": {}})
    assert calls["n"] >= 2  # retried, not a single shot


def test_b1e_model_listing_confirms_names(monkeypatch):
    class Resp:
        def read(self):
            return json.dumps({"data": [{"id": "qwen-max"}, {"id": "qwen-plus"},
                                        {"id": "qwen-turbo"}]}).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", lambda req, timeout=None: Resp())
    res = qwen_client.verify_models()
    assert res["ok"] and not res["missing"]
    assert "qwen-max" in res["available"]


def test_b1e_model_listing_flags_unknown_names(monkeypatch):
    class Resp:
        def read(self):
            return json.dumps({"data": [{"id": "some-other-model"}]}).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", lambda req, timeout=None: Resp())
    res = qwen_client.verify_models()
    assert not res["ok"]
    assert set(res["missing"]) == {config.MODEL_JUDGE, config.MODEL_WORKER, config.MODEL_FAST}