"""M8 — client names live in ONE place (the sandbox world), not hard-coded in
the gateway or the Qwen client. And an empty client list in the limits means
'no client data may leave', never 'skip the scope check'."""
import json
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import config, db, gateway, qwen_client, world
from conftest import make_session


def _empty_client_session(task="Help Acme Industries with their Q3 report request from Rosa."):
    rid, s = make_session(task=task)
    limits = json.loads(db.conn().execute(
        "SELECT limits_json FROM agent_sessions WHERE id=?", (s["session_id"],)).fetchone()["limits_json"])
    limits["clients"] = []           # e.g. a live judge named no client
    limits["tools"] = list(gateway.TOOL_SCHEMAS)
    limits["external_send"] = True
    limits["refund"] = True
    db.conn().execute("UPDATE agent_sessions SET limits_json=? WHERE id=?",
                      (json.dumps(limits, sort_keys=True), s["session_id"]))
    db.conn().commit()
    return rid, s


def test_m8_no_hardcoded_client_names_in_gateway_or_client():
    gw = (gateway.__file__)
    src_gw = open(gw).read()
    src_qc = open(qwen_client.__file__).read()
    for name in ("acme", "boreal", "cirrus", "meridian"):
        assert name not in src_gw.lower(), f"client name {name!r} hard-coded in gateway"
        assert name not in src_qc.lower(), f"client name {name!r} hard-coded in qwen_client"


def test_m8_empty_clients_blocks_client_attachment():
    rid, s = _empty_client_session()
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": "y",
                               "attachment_ids": ["doc_acme_q3"]}, uuid.uuid4().hex)
    assert out["verdict"] == "block"
    w = gateway.get_world(rid)
    assert not w.sent


def test_m8_empty_clients_blocks_client_text_paste():
    rid, s = _empty_client_session()
    body = world.SEED["documents"]["doc_acme_q3"]["body"]
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": body},
                              uuid.uuid4().hex)
    assert out["verdict"] in ("block", "hold")
    w = gateway.get_world(rid)
    assert not w.sent


def test_m8_empty_clients_blocks_client_refund():
    rid, s = _empty_client_session(task="Process the refund Cirrus Health asked for by email.")
    out = gateway.handle_call(s["token"], "issue_refund",
                              {"invoice_id": "INV-3007", "amount": 250,
                               "payee": "Cirrus Health"}, uuid.uuid4().hex)
    assert out["verdict"] == "block"
    assert any(r["rule"] == "R-SCOPE" for r in out["reasons"])
    w = gateway.get_world(rid)
    assert not w.refunds


def test_m8_limits_prompt_derives_clients_from_world(monkeypatch):
    monkeypatch.setattr(config, "QWEN_API_KEY", "test-key-not-real")
    qwen_client._cache.clear()
    seen = {}
    def fake(model, system, user):
        seen["system"] = system
        return json.dumps({"verdict": "ok", "limits": {"clients": ["acme"],
                            "tools": ["list_inbox"], "external_send": False, "refund": False},
                            "reason": "r"})
    monkeypatch.setattr(qwen_client, "_live_call", fake)
    qwen_client.judge("limits", {"task": "Help Acme with the report."})
    for cid in world.client_ids():
        assert cid in seen["system"]
    qwen_client._cache.clear()


def test_m8_standin_limits_use_world_clients():
    out = qwen_client.judge("limits", {"task": "Help Boreal Logistics with the restructuring plan."})
    assert out["limits"]["clients"] == ["boreal"]