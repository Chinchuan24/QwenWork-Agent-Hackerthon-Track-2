"""C1/C3: card and Delta must gate worker model egress before transport."""
import json
from unittest.mock import MagicMock, Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import config, db, evidence, qwen_client
from aegis.app import app
from conftest import make_session


@pytest.fixture
def model_egress(monkeypatch):
    # Derive the real session/card locally before enabling the live route.
    _, session = make_session("Help Acme Industries with their Q3 report.")
    monkeypatch.setattr(config, "live_mode", lambda: True)
    monkeypatch.setattr(config, "QWEN_API_KEY", "local-test-not-a-credential")
    monkeypatch.setattr(qwen_client, "_calls_window", [])
    monkeypatch.setattr(qwen_client, "_spend_total", lambda: 0)
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({
        "choices": [{"message": {"role": "assistant", "content": "fixture reply"}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }).encode()
    transport = Mock(return_value=response)
    monkeypatch.setattr(qwen_client.urllib.request, "urlopen", transport)
    monkeypatch.setattr(qwen_client, "judge", Mock(return_value={"verdict": "safe"}))
    # No lifespan or login: conftest initializes the sandbox; use its real agent token.
    client = TestClient(app)
    yield session, client, transport
    client.close()


def post_model(session, client):
    return client.post(
        "/api/agent/model", headers={"X-Agent-Token": session["token"]},
        json={"messages": [{"role": "user", "content": "Summarize the Q3 report."}]},
    )


def test_valid_card_safe_reviews_reach_worker_transport(model_egress):
    session, client, transport = model_egress
    response = post_model(session, client)
    assert response.status_code == 200
    assert response.json()["message"]["content"] == "fixture reply"
    transport.assert_called_once()


@pytest.mark.parametrize("card_state", ["missing", "frozen"])
def test_missing_or_frozen_card_prevents_worker_transport(model_egress, card_state):
    session, client, transport = model_egress
    if card_state == "missing":
        db.conn().execute("DELETE FROM helper_cards WHERE helper_id=?", (session["session_id"],))
    else:
        row = db.conn().execute("SELECT content FROM helper_cards WHERE helper_id=?",
                                (session["session_id"],)).fetchone()
        card = evidence.dec_json(row["content"])
        card["frozen"] = True
        db.conn().execute("UPDATE helper_cards SET content=? WHERE helper_id=?",
                          (evidence.enc_json(card), session["session_id"]))
    db.conn().commit()

    response = post_model(session, client)

    transport.assert_not_called()
    assert "message" not in response.json()


@pytest.mark.parametrize("delta_result", ["unsafe", "error"])
def test_delta_unsafe_or_error_prevents_worker_transport(model_egress, monkeypatch, delta_result):
    session, client, transport = model_egress

    def judge(kind, payload, model=None):
        if kind == "safety_b":
            if delta_result == "error":
                raise qwen_client.JudgeUnavailable("local Delta outage")
            return {"verdict": "unsafe", "reason": "model egress denied"}
        return {"verdict": "safe", "reason": "local fixture"}

    delta = Mock(side_effect=judge)
    monkeypatch.setattr(qwen_client, "judge", delta)

    response = post_model(session, client)

    transport.assert_not_called()
    assert any(call.args[0] == "safety_b" for call in delta.call_args_list)
    assert "message" not in response.json()
