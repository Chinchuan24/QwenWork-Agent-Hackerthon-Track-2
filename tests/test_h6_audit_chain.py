"""H6 — audit tampering must be caught in all three proven cases: deleting the
newest record, deleting the checkpoint file (with a truncated log), and
removing the last checkpoint line. Checkpoints are written with every record
and each one carries the signature of the one before it."""
import json

import pytest

from aegis import audit, config, db


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
    yield tmp_path
    db._local.conn = None


def _drop_delete_trigger():
    db.conn().execute("DROP TRIGGER audit_no_delete")
    db.conn().commit()


def _restore_delete_trigger():
    db.conn().execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    db.conn().commit()


def test_h6_verify_ok_with_per_record_checkpoints(fresh_audit):
    for i in range(7):
        audit.record("evt", {"i": i})
    v = audit.verify()
    assert v["ok"], v["problems"]
    assert v["checkpoints"] == 7  # one checkpoint per record


def test_h6_checkpoint_chain_links_signatures(fresh_audit):
    for i in range(3):
        audit.record("evt", {"i": i})
    lines = (fresh_audit / "checkpoints.jsonl").read_text().splitlines()
    anchors = [json.loads(l) for l in lines]
    assert anchors[0]["body"]["prev_sig"] == "genesis"
    assert anchors[1]["body"]["prev_sig"] == anchors[0]["sig"]
    assert anchors[2]["body"]["prev_sig"] == anchors[1]["sig"]


def test_h6_delete_newest_record_detected(fresh_audit):
    for i in range(6):
        audit.record("evt", {"i": i})
    _drop_delete_trigger()
    db.conn().execute("DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)")
    db.conn().commit()
    _restore_delete_trigger()
    v = audit.verify()
    assert not v["ok"]
    assert any("deleted" in p for p in v["problems"])


def test_h6_delete_checkpoint_file_with_truncated_log_detected(fresh_audit):
    for i in range(20):
        audit.record("evt", {"i": i})
    (fresh_audit / "checkpoints.jsonl").unlink()
    _drop_delete_trigger()
    db.conn().execute("DELETE FROM audit WHERE id > 10")
    db.conn().commit()
    _restore_delete_trigger()
    v = audit.verify()
    assert not v["ok"], "checkpoint file deleted + log truncated went unnoticed"
    assert any("checkpoint" in p.lower() for p in v["problems"])


def test_h6_remove_last_checkpoint_line_detected(fresh_audit):
    for i in range(10):
        audit.record("evt", {"i": i})
    path = fresh_audit / "checkpoints.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    v = audit.verify()
    assert not v["ok"]
    assert any("missing" in p.lower() for p in v["problems"])


def test_h6_remove_middle_checkpoint_line_detected(fresh_audit):
    for i in range(8):
        audit.record("evt", {"i": i})
    path = fresh_audit / "checkpoints.jsonl"
    lines = path.read_text().splitlines()
    del lines[3]
    path.write_text("\n".join(lines) + "\n")
    v = audit.verify()
    assert not v["ok"]


def test_h6_out_of_sequence_checkpoints_detected(fresh_audit):
    for i in range(6):
        audit.record("evt", {"i": i})
    path = fresh_audit / "checkpoints.jsonl"
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    v = audit.verify()
    assert not v["ok"]