"""Malformed and expired helper cards must fail closed before email sends."""
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import db, gateway
from conftest import make_session
from test_c3_enforcement_review import call, save_card


@pytest.mark.parametrize("restriction", [
    pytest.param(dict(ask="not-a-list"), id="malformed-ask-string"),
    pytest.param(dict(expiry=1.0), id="expired-card-timestamp"),
])
def test_invalid_card_blocks_without_sending(monkeypatch, restriction):
    rid, session = make_session("Email Rosa at Acme a greeting.", mode="off")
    save_card(session, tools=["send_email"], alone=["send_email"],
              **restriction)
    w = gateway.get_world(rid)
    sink = Mock(wraps=w.send_email)
    monkeypatch.setattr(w, "send_email", sink)

    out = call(session, "send_email", dict(
        to="rosa@acme.example", subject="Hello", body="Hello"))

    total = db.conn().execute(
        "SELECT send_total FROM agent_sessions WHERE id=?",
        (session["session_id"],)).fetchone()["send_total"]
    assert (out["verdict"], sink.call_count, w.sent, total) == (
        "block", 0, [], 0)
