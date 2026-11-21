"""M10 — writing an audit record and checking running totals must be single
steps. Parallel calls must not fork the hash chain or pass a cap."""
import threading
import uuid

import pytest

from aegis import audit, config, db, gateway
from conftest import make_session


@pytest.fixture
def fresh_audit(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(config, "ANCHOR_DIR", tmp_path)
    monkeypatch.setattr(audit, "_KEY_FILE", tmp_path / "signing.key")
    monkeypatch.setattr(audit, "_ANCHOR_FILE", tmp_path / "checkpoints.jsonl")
    monkeypatch.setattr(config, "AEGIS_ANCHOR_EXTERNAL",
                        str(tmp_path.parent / (tmp_path.name + "-ext") / "anchor.json"),
                        raising=False)
    db._local.conn = None
    db.init_db()
    yield
    db._local.conn = None


def test_m10_parallel_audit_records_do_not_fork_chain(fresh_audit):
    errors = []
    def worker(n):
        try:
            for i in range(25):
                audit.record("parallel", {"thread": n, "i": i})
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    v = audit.verify()
    assert v["ok"], v["problems"]
    assert v["records"] == 200


def test_m10_parallel_refunds_cannot_pass_cap():
    rid, s = make_session(task="Process the refund Cirrus Health asked for by email.")
    invoices = ["INV-3007", "INV-3010", "INV-3011"] * 4  # 12 threads, 250 each
    errors = []
    def worker(inv):
        try:
            gateway.handle_call(s["token"], "issue_refund",
                                {"invoice_id": inv, "amount": 250, "payee": "Cirrus Health"},
                                uuid.uuid4().hex)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(inv,)) for inv in invoices]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    w = gateway.get_world(rid)
    paid = sum(r["amount"] for r in w.refunds)
    assert paid <= config.REFUND_SESSION_CAP, f"parallel refunds paid {paid}"
    assert len(w.refunds) <= 2


def test_m10_parallel_sends_cannot_pass_cap():
    rid, s = make_session()
    errors = []
    def worker(n):
        try:
            gateway.handle_call(s["token"], "send_email",
                                {"to": "rosa@acme.example", "subject": "x",
                                 "body": f"unique message {n}"}, uuid.uuid4().hex)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    w = gateway.get_world(rid)
    assert len(w.sent) <= config.SEND_SESSION_CAP, f"parallel sends: {len(w.sent)}"