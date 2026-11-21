"""H7 — the worker's model calls must go through the ONE Qwen client with the
spending cap, rate limit, a per-session budget and a payload size limit.
Tested without a key by simulating live mode and the transport."""
import json
import time

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import app as app_module
from aegis import config, db, gateway, qwen_client


@pytest.fixture(autouse=True)
def _live(monkeypatch):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    qwen_client._cache.clear()
    qwen_client._calls_window.clear()
    db.conn().execute("DELETE FROM spend")
    db.conn().execute("DELETE FROM worker_usage")
    db.conn().commit()
    yield
    qwen_client._cache.clear()
    qwen_client._calls_window.clear()


def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network call escaped the capped client")
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", boom)


def _session():
    rid = gateway.create_run("enforce", "dana")
    return gateway.start_session(rid, "Help Acme Industries with the Q3 report.", "dana")


def test_h7_worker_refused_at_spend_cap(monkeypatch):
    _no_network(monkeypatch)
    db.conn().execute("INSERT INTO spend(ts,model,tokens_in,tokens_out,est_usd,mode) "
                      "VALUES(?,?,?,?,?,?)", (time.time(), "qwen-plus", 0, 0,
                                              config.SPEND_CAP_USD + 1, "live"))
    db.conn().commit()
    s = _session()
    with pytest.raises(qwen_client.JudgeUnavailable, match="cap"):
        qwen_client.worker_chat(s["session_id"], [{"role": "user", "content": "hi"}], [])
    events = [r["event"] for r in db.conn().execute("SELECT event FROM audit").fetchall()]
    assert "worker_model_refused" in events


def test_h7_worker_refused_at_rate_limit(monkeypatch):
    _no_network(monkeypatch)
    qwen_client._calls_window.extend([time.time()] * qwen_client.RATE_PER_MIN)
    s = _session()
    with pytest.raises(qwen_client.JudgeUnavailable, match="rate"):
        qwen_client.worker_chat(s["session_id"], [{"role": "user", "content": "hi"}], [])


def test_h7_worker_per_session_budget(monkeypatch):
    monkeypatch.setattr(qwen_client, "_chat",
                        lambda *a, **k: {"role": "assistant", "content": "ok"})
    s = _session()
    for _ in range(config.WORKER_MAX_CALLS_PER_SESSION):
        qwen_client.worker_chat(s["session_id"], [{"role": "user", "content": "hi"}], [])
    with pytest.raises(qwen_client.JudgeUnavailable, match="budget"):
        qwen_client.worker_chat(s["session_id"], [{"role": "user", "content": "hi"}], [])
    events = [r["event"] for r in db.conn().execute("SELECT event FROM audit").fetchall()]
    assert "worker_model_refused" in events


def test_h7_worker_payload_size_limit(monkeypatch):
    _no_network(monkeypatch)
    s = _session()
    big = [{"role": "user", "content": "x" * (config.WORKER_MAX_PAYLOAD_BYTES + 10)}]
    with pytest.raises(qwen_client.JudgeUnavailable, match="size"):
        qwen_client.worker_chat(s["session_id"], big, [])


def test_h7_one_code_path_no_direct_calls_in_app():
    src = (app_module.ROOT / "aegis" / "app.py").read_text()
    assert "urlopen" not in src, "app.py must not make its own model calls"
    assert "worker_chat" in src


def test_h7_endpoint_uses_capped_client(monkeypatch):
    from fastapi.testclient import TestClient
    seen = {}
    def fake_chat(session_id, messages, tools):
        seen["session"] = session_id
        return {"role": "assistant", "content": "done"}
    monkeypatch.setattr(qwen_client, "worker_chat", fake_chat)
    reviews = []
    def local_judge(kind, payload, model=None):
        if kind == 'limits':
            return qwen_client._standin(kind, payload)
        assert kind in ('safety_a', 'safety_b')
        assert payload['tool'] == 'worker_model'
        reviews.append(kind)
        return {'verdict': 'safe', 'mode': 'standin'}
    monkeypatch.setattr(qwen_client, 'judge', local_judge)
    _no_network(monkeypatch)
    app_module.startup()
    with TestClient(app_module.app) as client:
        s = _session()
        r = client.post("/api/agent/model", json={"messages": [{"role": "user", "content": "hi"}]},
                        headers={"X-Agent-Token": s["token"]})
        assert r.status_code == 200
        assert r.json()["message"]["content"] == "done"
        assert seen["session"] == s["session_id"]
        assert reviews == ['safety_a', 'safety_b']
        # at the cap the endpoint refuses instead of calling out
        db.conn().execute("INSERT INTO spend(ts,model,tokens_in,tokens_out,est_usd,mode) "
                          "VALUES(?,?,?,?,?,?)", (time.time(), "qwen-plus", 0, 0,
                                                  config.SPEND_CAP_USD + 1, "live"))
        db.conn().commit()
        def real_refuse(session_id, messages, tools):
            raise qwen_client.JudgeUnavailable("spending cap reached")
        monkeypatch.setattr(qwen_client, "worker_chat", real_refuse)
        r = client.post("/api/agent/model", json={"messages": []},
                        headers={"X-Agent-Token": s["token"]})
        assert "cap" in r.json()["error"]