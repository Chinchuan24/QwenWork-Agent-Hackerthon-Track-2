"""Internal incident service contracts against real SQLite and audit receipts."""
import sqlite3

import pytest

from aegis import audit, db, evidence
from aegis import incident_store as store


@pytest.fixture
def admin():
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    yield dict(db.conn().execute("SELECT * FROM users WHERE username='dana'").fetchone())
    db.conn().execute("UPDATE users SET role='admin', must_change=1 WHERE username='dana'")
    db.conn().execute("UPDATE users SET must_change=1 WHERE username IN ('ops', 'audi')")
    db.conn().commit()


def test_persist_encrypted_known_facts_and_explicit_epochs(admin):
    result = store.create_incident(admin, title="private incident", facts={"count": 0, "harm": False})
    iid = result["id"]
    step = store.add_step(admin, iid, step="private assessment", awareness_at=0,
                          human_awareness=True, facts={"data": ["private category"], "count": None})
    got = store.get_incident(admin, iid)
    assert got["title"] == "private incident"
    assert got["awareness_at"] is None and got["determination_at"] is None
    assert got["facts"] == {"count": 0, "harm": False}
    assert got["steps"][0]["awareness_at"] == 0
    assert got["steps"][0]["human_awareness"] is True
    assert got["steps"][0]["facts"] == {"data": ["private category"]}
    assert step["audit_id"] > result["audit_id"]
    assert audit.verify()["ok"]
    for table in ("incidents", "incident_steps"):
        raw = db.conn().execute(f"SELECT payload FROM {table} WHERE incident_id=?", (iid,)).fetchone()[0]
        assert raw.startswith(evidence.PREFIX)
        assert "private" not in raw
    reopened = sqlite3.connect(db.conn().execute("PRAGMA database_list").fetchone()[2])
    try:
        assert reopened.execute("SELECT COUNT(*) FROM incidents WHERE incident_id=?", (iid,)).fetchone()[0] == 1
    finally:
        reopened.close()
    assert iid in [item["id"] for item in store.list_incidents(admin)]


@pytest.mark.parametrize("username", ["ops", "audi"])
def test_read_roles_cannot_write(admin, username):
    iid = store.create_incident(admin, title="restricted")["id"]
    db.conn().execute("UPDATE users SET must_change=0 WHERE username=?", (username,))
    db.conn().commit()
    user = dict(db.conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())
    assert store.get_incident(user, iid)["id"] == iid
    assert store.list_incidents(user)
    with pytest.raises(PermissionError):
        store.create_incident(user, title="no")
    with pytest.raises(PermissionError):
        store.add_step(user, iid, step="no")


@pytest.mark.parametrize("user", [None, {}, {"role": "admin"},
    {"id": True, "username": "dana", "role": "admin"},
    {"id": 1, "username": "helper", "role": "admin"}])
def test_untrusted_or_helper_identity_refused(admin, user):
    iid = store.create_incident(admin, title="restricted")["id"]
    for operation in (lambda: store.create_incident(user, title="no"),
                      lambda: store.add_step(user, iid, step="no"),
                      lambda: store.get_incident(user, iid), lambda: store.list_incidents(user)):
        with pytest.raises(PermissionError):
            operation()


def test_current_stored_role_and_password_gate(admin):
    db.conn().execute("UPDATE users SET role='viewer' WHERE id=?", (admin["id"],))
    db.conn().commit()
    try:
        with pytest.raises(PermissionError):
            store.list_incidents(admin)
    finally:
        db.conn().execute("UPDATE users SET role='admin', must_change=1 WHERE id=?", (admin["id"],))
        db.conn().commit()
    with pytest.raises(PermissionError):
        store.create_incident(admin, title="no")


@pytest.mark.parametrize("kwargs", [
    {"awareness_at": 123}, {"human_awareness": 1}, {"human_awareness": True},
    {"awareness_at": True, "human_awareness": True},
    {"awareness_at": float("nan"), "human_awareness": True},
    {"determination_at": -1, "human_determination": True},
    {"determination_at": 123}, {"human_determination": "yes"},
    {"facts": {"count": True}}, {"facts": {"count": -1}},
    {"facts": {"unknown": "no"}}, {"facts": {"data": {"secret": "no"}}},
])
def test_invalid_claims_have_no_receipt_or_write(admin, kwargs):
    before = db.conn().execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    with pytest.raises(ValueError):
        store.create_incident(admin, title="no", **kwargs)
    assert db.conn().execute("SELECT COUNT(*) FROM audit").fetchone()[0] == before


@pytest.mark.parametrize("table", ["incidents", "incident_steps"])
@pytest.mark.parametrize("operation", ["UPDATE {table} SET payload='changed'", "DELETE FROM {table}",
                                       "INSERT OR REPLACE INTO {table} SELECT * FROM {table}"])
def test_database_append_only(admin, table, operation):
    iid = store.create_incident(admin, title="immutable")["id"]
    store.add_step(admin, iid, step="immutable")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn().execute(operation.format(table=table))
    db.conn().rollback()


def test_audit_failures_propagate_without_incident_write(admin, monkeypatch):
    iid = store.create_incident(admin, title="existing")["id"]
    before = db.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    def fail(*args, **kwargs):
        raise OSError("receipt failed")
    monkeypatch.setattr(audit, "record", fail)
    with pytest.raises(OSError, match="receipt failed"):
        store.create_incident(admin, title="no")
    with pytest.raises(OSError):
        store.add_step(admin, iid, step="no")
    assert db.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == before
    assert store.get_incident(admin, iid)["steps"] == []


def test_verification_failure_never_claims_success(admin, monkeypatch):
    iid = store.create_incident(admin, title="existing")["id"]
    monkeypatch.setattr(audit, "verify", lambda: {"ok": False, "problems": ["missing checkpoint"]})
    for op in (lambda: store.create_incident(admin, title="no"),
               lambda: store.add_step(admin, iid, step="no"),
               lambda: store.get_incident(admin, iid), lambda: store.list_incidents(admin)):
        with pytest.raises(store.IncidentIntegrityError):
            op()
    assert db.conn().execute("SELECT COUNT(*) FROM incident_steps WHERE incident_id=?", (iid,)).fetchone()[0] == 0


def test_missing_incident_and_encryption_failure(admin, monkeypatch):
    with pytest.raises(KeyError):
        store.get_incident(admin, "missing")
    with pytest.raises(KeyError):
        store.add_step(admin, "missing", step="no")
    def fail(*args):
        raise evidence.EvidenceKeyError("key unavailable")
    monkeypatch.setattr(evidence, "enc_json", fail)
    with pytest.raises(evidence.EvidenceKeyError):
        store.create_incident(admin, title="enc:v2:fake ciphertext")


def test_post_receipt_verification_failure_blocks_insert(admin, monkeypatch):
    original = audit.verify
    calls = []
    def verify():
        calls.append(True)
        return original() if len(calls) == 1 else {"ok": False}
    monkeypatch.setattr(audit, "verify", verify)
    before = db.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    with pytest.raises(store.IncidentIntegrityError):
        store.create_incident(admin, title="not persisted")
    assert len(calls) == 2
    assert db.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == before


def test_tampered_receipt_binding_refused(admin, monkeypatch):
    iid = store.create_incident(admin, title="existing")["id"]
    original = evidence.dec_json
    def decode(text):
        value = original(text)
        if isinstance(value, dict) and "payload_sha256" in value:
            value["payload_sha256"] = "wrong"
        return value
    monkeypatch.setattr(evidence, "dec_json", decode)
    with pytest.raises(store.IncidentIntegrityError):
        store.get_incident(admin, iid)


@pytest.mark.parametrize("kwargs", [{"title": ""}, {"title": None},
    {"title": "x" * 10001}, {"title": "valid", "timestamp": float("inf")},
    {"title": "valid", "facts": {"harm": "yes"}},
    {"title": "valid", "facts": {"data": "x" * 10001}},
    {"title": "valid", "facts": []}])
def test_text_and_fact_bounds(admin, kwargs):
    with pytest.raises(ValueError):
        store.create_incident(admin, **kwargs)


def test_order_is_append_order_not_epoch_and_schema_is_additive(admin):
    db.conn().execute("CREATE TABLE IF NOT EXISTS incident_test_sentinel (value TEXT)")
    db.conn().execute("INSERT INTO incident_test_sentinel VALUES ('preserved')")
    db.conn().commit()
    store.init_store()
    store.init_store()
    iid = store.create_incident(admin, title="order", determination_at=20, human_determination=True)["id"]
    store.add_step(admin, iid, step="first", timestamp=20)
    store.add_step(admin, iid, step="second", timestamp=0)
    got = store.get_incident(admin, iid)
    assert [s["step"] for s in got["steps"]] == ["first", "second"]
    assert got["determination_at"] == 20 and got["human_determination"] is True
    assert db.conn().execute("SELECT value FROM incident_test_sentinel").fetchone()[0] == "preserved"


def test_INCIDENT01_add_step_refuses_caller_transaction(admin):
    iid = store.create_incident(admin, title='caller transaction')['id']
    before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    try:
        with audit.publication_lock():
            db.conn().execute("INSERT INTO settings(key,value) VALUES('INCIDENT01','pending')")
            with pytest.raises(RuntimeError, match='existing transaction'):
                store.add_step(admin, iid, step='refused')
            assert db.conn().in_transaction
            assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
    finally:
        db.conn().rollback()
    assert db.conn().execute("SELECT value FROM settings WHERE key='INCIDENT01'").fetchone() is None
    assert store.get_incident(admin, iid)['steps'] == []


def test_INCIDENT02_creation_insert_failure_rolls_back_receipt(admin):
    store.init_store()
    before = [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')]
    db.conn().execute("CREATE TRIGGER incident_creation_failure BEFORE INSERT ON incidents "
                      "BEGIN SELECT RAISE(ABORT, 'INCIDENT02 insert failure'); END")
    try:
        with pytest.raises(sqlite3.IntegrityError, match='INCIDENT02 insert failure'):
            store.create_incident(admin, title='not persisted')
        assert not db.conn().in_transaction
        assert [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')] == before
        assert audit.verify()['ok']
    finally:
        db.conn().rollback()
        db.conn().execute('DROP TRIGGER incident_creation_failure')
