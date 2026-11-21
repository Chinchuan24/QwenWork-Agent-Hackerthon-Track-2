"""Versioned encryption preserves immutable evidence and signed receipts."""
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis import audit, auth, config, db, evidence, incident_store


def key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def key_id(raw):
    return hashlib.sha256(base64.urlsafe_b64decode(raw)).hexdigest()[:32]


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    anchors = data / "anchors"
    anchors.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "DB_PATH", data / "test.db")
    monkeypatch.setattr(config, "ANCHOR_DIR", anchors)
    monkeypatch.setattr(config, "AEGIS_ANCHOR_EXTERNAL", str(tmp_path / "external.json"))
    monkeypatch.setattr(audit, "_KEY_FILE", anchors / "signing.key")
    monkeypatch.setattr(audit, "_ANCHOR_FILE", anchors / "checkpoints.jsonl")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", "")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEYRING_FILE", str(tmp_path / "keys.json"), raising=False)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    previous = getattr(db._local, "conn", None)
    db._local.conn = None
    db.init_db()
    auth.ensure_demo_users()
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    admin = dict(db.conn().execute("SELECT * FROM users WHERE username='dana'").fetchone())
    yield admin, Path(config.AEGIS_EVIDENCE_KEYRING_FILE)
    db.conn().close()
    db._local.conn = previous


def test_two_rotations_preserve_incidents_receipts_and_audit(isolated, monkeypatch):
    admin, ring = isolated
    old = config.AEGIS_EVIDENCE_KEY
    evidence.probe()
    created = incident_store.create_incident(admin, title="private incident")
    iid = created["id"]
    step = incident_store.add_step(admin, iid, step="private step")
    before = [tuple(r) for r in db.conn().execute("SELECT * FROM audit ORDER BY id")]
    payload = db.conn().execute("SELECT payload FROM incidents").fetchone()[0]
    assert payload.startswith(evidence.PREFIX + key_id(old) + ":")
    anchors = audit._ANCHOR_FILE.read_bytes()
    external = Path(config.AEGIS_ANCHOR_EXTERNAL).read_bytes()
    probe = db.get_setting("evidence_probe")
    triggers = [tuple(r) for r in db.conn().execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")]
    retained = {}
    for _ in range(2):
        retained[key_id(config.AEGIS_EVIDENCE_KEY)] = config.AEGIS_EVIDENCE_KEY
        ring.write_text(json.dumps({"keys": retained}))
        ring.chmod(0o400)
        contents = ring.read_bytes()
        newest = key()
        monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", newest)
        monkeypatch.setattr(evidence, "_key_cache", None)
        assert evidence.enc("new private write").startswith(evidence.PREFIX + key_id(newest) + ":")
        assert evidence.probe()
        got = incident_store.get_incident(admin, iid)
        assert got["title"] == "private incident"
        assert got["steps"][0]["step"] == "private step"
        assert got["audit_id"] == created["audit_id"]
        assert got["steps"][0]["audit_id"] == step["audit_id"]
        assert audit.verify()["ok"]
        assert ring.read_bytes() == contents
        ring.chmod(0o600)
    assert [tuple(r) for r in db.conn().execute("SELECT * FROM audit ORDER BY id")] == before
    assert db.conn().execute("SELECT payload FROM incidents").fetchone()[0] == payload
    assert audit._ANCHOR_FILE.read_bytes() == anchors
    assert Path(config.AEGIS_ANCHOR_EXTERNAL).read_bytes() == external
    assert db.get_setting("evidence_probe") == probe
    assert [tuple(r) for r in db.conn().execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")] == triggers
    for table in ("audit", "incidents", "incident_steps"):
        for sql in (f"DELETE FROM {table}", f"UPDATE {table} SET " + ("detail_json='x'" if table == "audit" else "payload='x'")):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                db.conn().execute(sql)
            db.conn().rollback()


@pytest.mark.parametrize("failure", ["missing", "tamper", "id", "malformed", "wrong-old-key"])
def test_versioned_failures_are_sanitized(isolated, monkeypatch, failure):
    _, ring = isolated
    text = evidence.enc("private plaintext")
    assert text.startswith(evidence.PREFIX + key_id(config.AEGIS_EVIDENCE_KEY) + ":")
    if failure == "missing":
        monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
        monkeypatch.setattr(evidence, "_key_cache", None)
    elif failure == "wrong-old-key":
        old_id = key_id(config.AEGIS_EVIDENCE_KEY)
        ring.write_text(json.dumps({"keys": {old_id: key()}}))
        monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
        monkeypatch.setattr(evidence, "_key_cache", None)
    elif failure == "tamper":
        text = text[:-2] + ("00" if text[-2:] != "00" else "01")
    elif failure == "id":
        text = text.replace(key_id(config.AEGIS_EVIDENCE_KEY), "f" * 32)
    else:
        text = evidence.PREFIX + key_id(config.AEGIS_EVIDENCE_KEY) + ":not-hex"
    with pytest.raises(evidence.EvidenceKeyError) as error:
        evidence.dec(text)
    assert str(error.value) == "stored evidence cannot be decrypted"
    assert error.value.__cause__ is None


@pytest.mark.parametrize("prefix", ["enc:v1:", "enc:v2:"])
def test_legacy_no_id_reads_unchanged(isolated, prefix):
    raw = base64.urlsafe_b64decode(config.AEGIS_EVIDENCE_KEY)
    nonce = os.urandom(12)
    blob = nonce + AESGCM(raw).encrypt(nonce, b"legacy", None)
    text = prefix + (blob.hex() if prefix == "enc:v2:" else base64.urlsafe_b64encode(blob).decode())
    assert evidence.dec(text) == "legacy"
    assert evidence.enc(text) == text
    assert evidence.dec("plain legacy") == "plain legacy"


@pytest.mark.parametrize("prefix", ["enc:v1:", "enc:v2:"])
def test_legacy_retained_keys_across_two_rotations(isolated, monkeypatch, prefix):
    _, ring = isolated
    retained, envelopes = {}, []
    for generation in range(3):
        current = config.AEGIS_EVIDENCE_KEY
        raw = base64.urlsafe_b64decode(current)
        nonce = os.urandom(12)
        plain = f"synthetic generation {generation}"
        blob = nonce + AESGCM(raw).encrypt(nonce, plain.encode(), None)
        text = prefix + (blob.hex() if prefix == "enc:v2:" else base64.urlsafe_b64encode(blob).decode())
        envelopes.append((text, plain))
        if generation:
            before = ring.read_bytes()
            for stored, expected in envelopes:
                assert evidence.dec(stored) == expected
                assert evidence.enc(stored) == stored
            assert ring.read_bytes() == before
        retained[key_id(current)] = current
        ring.write_text(json.dumps({"keys": retained}))
        monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
        monkeypatch.setattr(evidence, "_key_cache", None)


def test_startup_rejects_unreadable_history_despite_current_probe(isolated, monkeypatch):
    stored = evidence.enc("synthetic historic summary")
    db.conn().execute("INSERT INTO runs(id,mode,label,created_at,summary) VALUES(?,?,?,?,?)",
                      ("crypto-history", "enforce", "synthetic", 0, stored))
    db.conn().commit()
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    evidence.probe()
    before = db.conn().total_changes
    assert evidence.probe()
    with pytest.raises(evidence.EvidenceKeyError, match="stored evidence cannot be decrypted"):
        evidence.require_key_for_startup()
    assert db.conn().total_changes == before


@pytest.mark.parametrize("failure", ["missing", "tamper", "wrong-key", "inside", "malformed"])
@pytest.mark.parametrize("prefix", ["enc:v1:", "enc:v2:"])
def test_legacy_retained_failures_are_sanitized(isolated, monkeypatch, prefix, failure):
    _, ring = isolated
    old = config.AEGIS_EVIDENCE_KEY
    nonce = os.urandom(12)
    blob = nonce + AESGCM(base64.urlsafe_b64decode(old)).encrypt(nonce, b"synthetic", None)
    if failure == "tamper":
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    text = prefix + (blob.hex() if prefix == "enc:v2:" else base64.urlsafe_b64encode(blob).decode())
    ring.write_text(json.dumps({"keys": {key_id(old): old if failure != "wrong-key" else key()}}))
    if failure == "missing":
        ring.unlink()
    elif failure == "inside":
        ring = config.DATA_DIR / "synthetic-ring.json"
        ring.write_text(json.dumps({"keys": {key_id(old): old}}))
        monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEYRING_FILE", str(ring))
    elif failure == "malformed":
        ring.write_text("not-json")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    with pytest.raises(evidence.EvidenceKeyError) as error:
        evidence.dec(text)
    assert str(error.value) == "stored evidence cannot be decrypted"
    assert error.value.__cause__ is None


@pytest.mark.parametrize("table,column", [
    ("helper_cards", "content"), ("helper_baselines", "content"),
    ("incidents", "payload"), ("incident_steps", "payload"),
    ("approvals", "reason"), ("actions", "reasons_json"),
    ("agent_sessions", "exposures_json"), ("audit", "detail_json")])
def test_startup_inventory_read_only(isolated, monkeypatch, table, column):
    _, ring = isolated
    # In-memory minimal schemas isolate inventory checks from other owners' APIs.
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute(f"CREATE TABLE {table} ({column} TEXT)")
    stored = evidence.enc("synthetic history")
    old = config.AEGIS_EVIDENCE_KEY
    c.execute(f"INSERT INTO {table} VALUES (?)", (stored,))
    c.commit()
    ring.write_text(json.dumps({"keys": {key_id(old): old}}))
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    marker = evidence.enc("aegis-evidence-probe")
    monkeypatch.setattr(db, "get_setting", lambda name, default="": marker if name == "evidence_probe" else default)
    monkeypatch.setattr(db, "conn", lambda: c)
    writes = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
              sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE}
    c.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action in writes else sqlite3.SQLITE_OK)
    try:
        evidence.require_key_for_startup()
        assert c.execute(f"SELECT {column} FROM {table}").fetchone()[0] == stored
        ring.write_text(json.dumps({"keys": {}}))
        assert evidence.probe()
        with pytest.raises(evidence.EvidenceKeyError, match="stored evidence cannot be decrypted"):
            evidence.require_key_for_startup()
    finally:
        c.close()


def test_id_dispatch_never_trials_retained_keys(isolated, monkeypatch):
    _, ring = isolated
    stored = evidence.enc("synthetic strict dispatch")
    old = config.AEGIS_EVIDENCE_KEY
    ring.write_text(json.dumps({"keys": {key_id(old): old}}))
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    stored = stored.replace(key_id(old), "f" * 32)
    with pytest.raises(evidence.EvidenceKeyError, match="stored evidence cannot be decrypted"):
        evidence.dec(stored)


@pytest.mark.parametrize("invalid", ["inside", "symlink", "malformed"])
def test_keyring_rejects_unsafe_location_or_content(isolated, monkeypatch, invalid):
    _, ring = isolated
    old = config.AEGIS_EVIDENCE_KEY
    text = evidence.enc("private plaintext")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", key())
    monkeypatch.setattr(evidence, "_key_cache", None)
    if invalid in ("inside", "symlink"):
        inside = config.DATA_DIR / "keys.json"
        inside.write_text(json.dumps({"keys": {key_id(old): old}}))
        if invalid == "symlink":
            ring.symlink_to(inside)
        else:
            monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEYRING_FILE", str(inside))
    else:
        ring.write_text("private invalid key material")
    with pytest.raises(evidence.EvidenceKeyError, match="stored evidence cannot be decrypted"):
        evidence.dec(text)


def test_new_encoding_is_hex_random_authenticated_and_idempotent(isolated):
    first = evidence.enc("private evidence")
    second = evidence.enc("private evidence")
    header, encoded = first.rsplit(":", 1)
    blob = bytes.fromhex(encoded)
    assert len(blob) == 12 + len(b"private evidence") + 16
    assert blob[:12] != bytes.fromhex(second.rsplit(":", 1)[1])[:12]
    raw = base64.urlsafe_b64decode(config.AEGIS_EVIDENCE_KEY)
    assert AESGCM(raw).decrypt(blob[:12], blob[12:], (header + ":").encode()) == b"private evidence"
    assert evidence.enc(first) == first
    assert evidence.dec(first) == evidence.dec(second) == "private evidence"
    assert "610k" not in encoded


def test_current_key_file_remains_supported(isolated, monkeypatch):
    _, ring = isolated
    current = config.AEGIS_EVIDENCE_KEY
    path = ring.parent / "current.key"
    path.write_text(current)
    path.chmod(0o400)
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", "")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", str(path))
    monkeypatch.setattr(evidence, "_key_cache", None)
    stored = evidence.enc("file-key evidence")
    assert stored.startswith(evidence.PREFIX + key_id(current) + ":")
    assert evidence.dec(stored) == "file-key evidence"
    assert path.read_text() == current


def test_retired_rotation_refuses_without_database_access(isolated, monkeypatch):
    from scripts.rotate_evidence_key import rotate
    def forbidden(*args, **kwargs):
        pytest.fail("retired rotation accessed the database")
    monkeypatch.setattr(db, "init_db", forbidden)
    with pytest.raises(evidence.EvidenceKeyError, match="retired"):
        rotate(key(), key())
    result = subprocess.run([sys.executable, "scripts/rotate_evidence_key.py"],
                            capture_output=True, text=True, env={"PATH": os.defpath})
    assert result.returncode != 0
    assert "retired" in result.stderr
    assert "Traceback" not in result.stderr
