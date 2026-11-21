"""R4 — encrypt stored evidence at rest. Held action content, approval
evidence, withheld injection text, replay arguments, read records, audit
detail and run summaries are encrypted with a key from OUTSIDE the data
folder. No key -> enforce-mode startup refused. Wrong key -> fails safely.
Wrong role -> no clear text. Covers WAL/backups/temp files, error traces,
exports and planned key rotation."""
import base64
import json
import os
import shutil

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import audit, config, db, evidence, gateway, redteam, suites
from conftest import make_session

SEEDED = ["CANARY-7f3a9b2e", "SK-CANARY-9d81f2a77c", "MeridianVault!2026",
          "4.2M", "northern corridor", "2.9M", "fleet utilisation", "610k",
          "patient-data programme", "fee tiers", "renewal dates",
          "4111 1111 1111 1111", "S1234567D", "northern depot", "southern hub"]


@pytest.fixture
def fresh_db(tmp_path, monkeypatch, reviewed14_sandbox_tools):
    previous_connection = db.conn()
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(config, "ANCHOR_DIR", tmp_path / "anchors")
    monkeypatch.setattr(config, "RECORD_DIR", tmp_path / "recordings")
    monkeypatch.setattr(audit, "_KEY_FILE", tmp_path / "anchors" / "signing.key")
    monkeypatch.setattr(audit, "_ANCHOR_FILE", tmp_path / "anchors" / "checkpoints.jsonl")
    monkeypatch.setattr(config, "AEGIS_ANCHOR_EXTERNAL",
                        str(tmp_path.parent / (tmp_path.name + "-ext") / "anchor.json"),
                        raising=False)
    (tmp_path / "anchors").mkdir(exist_ok=True)
    (tmp_path / "recordings").mkdir(exist_ok=True)
    db._local.conn = None
    db.init_db()
    from conftest import _literal_test_registry
    _literal_test_registry(reviewed14_sandbox_tools)
    yield tmp_path
    db.conn().close()
    db._local.conn = previous_connection


def test_r4_no_seeded_string_anywhere_after_full_suites(fresh_db):
    for a in suites.ATTACKS:
        redteam.run_scenario("enforce", a)
    for n in suites.NORMAL:
        redteam.run_scenario("enforce", n, approve_held=n.get("approve_held", False))
    db.conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blobs = []
    for f in fresh_db.rglob("*"):
        if f.is_file():
            blobs.append(f.read_bytes())
    ext = config.AEGIS_ANCHOR_EXTERNAL
    if ext and os.path.exists(ext):
        blobs.append(open(ext, "rb").read())
    hay = b"\n".join(blobs)
    found = [s for s in SEEDED if s.encode() in hay]
    assert not found, f"clear-text sensitive strings found at rest: {found}"


def test_r4_no_key_refuses_enforce_startup(monkeypatch):
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", "")
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY_FILE", "")
    monkeypatch.setattr(evidence, "_key_cache", None)
    db.set_setting("default_mode", "enforce", "tests", 0)
    with pytest.raises(evidence.EvidenceKeyError) as ei:
        evidence.require_key_for_startup()
    assert "AEGIS_EVIDENCE_KEY" in str(ei.value)


def test_r4_wrong_key_fails_safely(fresh_db, monkeypatch):
    evidence.migrate_once()
    good = config.AEGIS_EVIDENCE_KEY
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY",
                        base64.urlsafe_b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(evidence, "_key_cache", None)
    with pytest.raises(evidence.EvidenceKeyError):
        evidence.probe()
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", good)
    monkeypatch.setattr(evidence, "_key_cache", None)
    assert evidence.probe() is True


def test_r4_viewer_cannot_fetch_clear_text(client=None):
    from fastapi.testclient import TestClient
    from aegis.app import app, startup
    startup()
    rid, s = make_session()
    gateway.handle_call(s["token"], "read_file", {"doc_id": "doc_acme_q3"}, None)
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acrne.example", "subject": "x",
                               "body": "the northern corridor plan, revenue 4.2M"}, "r4-key")
    with TestClient(app) as c:
        audi = c.post("/login", data={"username": "audi", "password": "demo-audi-2026"},
                      follow_redirects=False).cookies.get("aegis_session")
        # auditor may see the decrypted (masked) form
        r = c.get(f"/run/{rid}", cookies={"aegis_session": audi})
        assert r.status_code == 200
        # a viewer-role account gets no clear text
        from aegis import auth
        if not db.conn().execute("SELECT 1 FROM users WHERE username='r4viewer'").fetchone():
            auth.create_user("r4viewer", "viewer-password-1", "viewer")
        vw = c.post("/login", data={"username": "r4viewer", "password": "viewer-password-1"},
                    follow_redirects=False).cookies.get("aegis_session")
        r2 = c.get(f"/run/{rid}", cookies={"aegis_session": vw})
        assert r2.status_code == 200
        assert "northern corridor" not in r2.text
        assert "encrypted" in r2.text.lower()


def test_r4_error_traces_never_carry_clear_text(monkeypatch):
    _, s = make_session()
    def boom(*a, **k):
        raise RuntimeError("failure while handling CANARY-7f3a9b2e and MeridianVault!2026")
    monkeypatch.setattr(gateway, "_session_signals", boom)
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": "y"}, "r4-err")
    assert out["verdict"] in ("hold", "block")
    clear = "\n".join(str(evidence.dec(r["detail_json"])) for r in
                      db.conn().execute("SELECT detail_json FROM audit").fetchall())
    assert "CANARY-7f3a9b2e" not in clear
    assert "MeridianVault!2026" not in clear


def test_r4_key_rotation_keeps_old_rows_readable(fresh_db, monkeypatch):
    audit.record("r4_rot", {"note": "the northern corridor plan"})
    gateway.create_run("enforce", "dana")
    old_key = config.AEGIS_EVIDENCE_KEY
    new_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    from scripts.rotate_evidence_key import rotate
    before = [tuple(r) for r in db.conn().execute('SELECT * FROM audit')]
    with pytest.raises(RuntimeError):
        rotate(old_key, new_key)
    import hashlib
    ring = fresh_db.parent / (fresh_db.name + '-keyring.json')
    ring.write_text(json.dumps({'keys': {
        hashlib.sha256(base64.urlsafe_b64decode(old_key)).hexdigest()[:32]: old_key}}))
    monkeypatch.setattr(config, 'AEGIS_EVIDENCE_KEYRING_FILE', str(ring))
    assert [tuple(r) for r in db.conn().execute('SELECT * FROM audit')] == before
    monkeypatch.setattr(config, "AEGIS_EVIDENCE_KEY", new_key)
    monkeypatch.setattr(evidence, "_key_cache", None)
    rows = db.conn().execute("SELECT detail_json FROM audit WHERE event='r4_rot'").fetchall()
    assert rows
    d = evidence.dec_json(rows[0]["detail_json"])
    assert d["note"] == "the northern corridor plan"
    assert evidence.probe() is True


def test_r4_exports_role_gated_and_decryptable():
    from fastapi.testclient import TestClient
    from aegis.app import app, startup
    startup()
    audit.record("r4_export", {"note": "exportable"})
    with TestClient(app) as c:
        audi = c.post("/login", data={"username": "audi", "password": "demo-audi-2026"},
                      follow_redirects=False).cookies.get("aegis_session")
        ops = c.post("/login", data={"username": "ops", "password": "demo-ops-2026"},
                     follow_redirects=False).cookies.get("aegis_session")
        r = c.get("/audit/export.json", cookies={"aegis_session": audi})
        assert r.status_code == 200
        assert any(x.get("event") == "r4_export" for x in r.json())
        assert c.get("/audit/export.json", cookies={"aegis_session": ops}).status_code == 403


def test_r4_normal_suite_not_worse():
    sb = redteam.run_suite("enforce", kind="normal")
    assert sb["normal_completed"] / sb["normal_total"] >= 0.9
    assert sb["false_holds"] / sb["normal_total"] <= 0.1