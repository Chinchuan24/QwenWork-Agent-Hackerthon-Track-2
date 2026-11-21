"""Tamper-evidence: append-only at the DB level, chain verify, outside
checkpoints catch deletion of the newest records, signature tampering caught."""
import json
import sqlite3
import pytest
from aegis import audit, db, config


@pytest.fixture
def fresh_audit(tmp_path, monkeypatch):
    # isolated DB + anchors: tamper tests must not regress the shared stream
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(config, "ANCHOR_DIR", tmp_path)
    monkeypatch.setattr(audit, "_KEY_FILE", tmp_path / "signing.key")
    monkeypatch.setattr(audit, "_ANCHOR_FILE", tmp_path / "checkpoints.jsonl")
    monkeypatch.setattr(config, "AEGIS_ANCHOR_EXTERNAL",
                        str(tmp_path.parent / (tmp_path.name + "-ext") / "anchor.json"),
                        raising=False)
    db._local.conn = None
    db.init_db()
    yield tmp_path
    db._local.conn = None


def test_writer_recovers_each_unpublished_prefix(fresh_audit, monkeypatch):
    checkpoint = audit.checkpoint
    monkeypatch.setattr(audit, 'checkpoint', lambda **kwargs: False)
    audit.record('interrupted_one', {})
    audit.record('interrupted_two', {})
    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    audit.record('next_writer', {})
    result = audit.verify()
    assert result['ok'], result['problems']
    counts = [json.loads(line)['body']['count'] for line in
              audit._ANCHOR_FILE.read_text().splitlines()]
    assert counts == list(range(1, counts[-1] + 1))


@pytest.mark.parametrize('detail', ['{', 'enc:v1:invalid'])
def test_malformed_detail_returns_structured_failure(fresh_audit, detail):
    rid = audit.record('malformed', {})
    c = db.conn()
    c.execute('DROP TRIGGER audit_no_update')
    c.execute('UPDATE audit SET detail_json=? WHERE id=?', (detail, rid))
    c.commit()
    result = audit.verify()
    assert result['ok'] is False
    assert result['problems']


@pytest.mark.parametrize('anchor', ['[]', 'null', '{"body": []}'])
def test_malformed_checkpoint_shape_fails_closed(fresh_audit, anchor):
    audit.record('shape', {})
    audit._ANCHOR_FILE.write_text(anchor + '\n')
    result = audit.verify()
    assert result['ok'] is False
    assert result['problems']


def test_decision_refuses_writer_acquired_before_publication_lock(fresh_audit):
    c = db.conn()
    c.execute('BEGIN IMMEDIATE')
    try:
        with pytest.raises(RuntimeError, match='publication lock'):
            audit.record_decision('inverted', {}, trusted_ts=1)
        assert c.in_transaction
    finally:
        c.rollback()


def test_verify_ok():
    audit.record("test_event", {"x": 1})
    audit.checkpoint()
    v = audit.verify()
    assert v["ok"], v["problems"]


def test_db_refuses_update_and_delete():
    audit.record("protected", {"x": 2})
    rid = db.conn().execute("SELECT MAX(id) m FROM audit").fetchone()["m"]
    with pytest.raises(sqlite3.IntegrityError):
        db.conn().execute("UPDATE audit SET event='hacked' WHERE id=?", (rid,))
    with pytest.raises(sqlite3.IntegrityError):
        db.conn().execute("DELETE FROM audit WHERE id=?", (rid,))
    db.conn().rollback()


def test_edited_record_detected(fresh_audit):
    audit.record("will_be_edited", {"x": 3})
    audit.checkpoint()
    rid = db.conn().execute("SELECT MAX(id) m FROM audit").fetchone()["m"]
    # simulate an attacker who disables the trigger (controls the DB)
    db.conn().execute("DROP TRIGGER audit_no_update")
    db.conn().execute("UPDATE audit SET detail_json=? WHERE id=?", (json.dumps({"x": "hacked"}), rid))
    db.conn().commit()
    v = audit.verify()
    assert not v["ok"]
    assert any(str(rid) in p for p in v["problems"])
    # restore trigger and record for later tests
    db.conn().execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    db.conn().commit()


def test_deleted_newest_records_detected(fresh_audit):
    for i in range(3):
        audit.record("tail", {"i": i})
    audit.checkpoint()
    db.conn().execute("DROP TRIGGER audit_no_delete")
    db.conn().execute("DELETE FROM audit WHERE id > (SELECT MAX(id)-2 FROM audit)")
    db.conn().commit()
    v = audit.verify()
    assert not v["ok"]
    assert any("deleted" in p or "rolled back" in p for p in v["problems"])
    db.conn().execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    db.conn().commit()


def test_checkpoint_signature_tamper(fresh_audit):
    audit.record("anchor_test", {})
    audit.checkpoint()
    path = config.ANCHOR_DIR / "checkpoints.jsonl"
    lines = path.read_text().splitlines()
    a = json.loads(lines[-1])
    a["body"]["count"] = 999999
    lines[-1] = json.dumps(a)
    path.write_text("\n".join(lines) + "\n")
    v = audit.verify()
    assert not v["ok"]
    assert any("signature" in p for p in v["problems"])