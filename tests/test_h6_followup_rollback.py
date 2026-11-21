"""H6 follow-up — coordinated rollback: deleting the newest N audit records
TOGETHER WITH the newest N checkpoint lines must be detected. The checkpoint
file sits in the same data folder as the database, so a latest-checkpoint
anchor is kept OUTSIDE that folder; a data-folder rollback cannot reach it."""
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


def _truncate(n):
    """The attack: roll back the data folder — newest N records AND newest N
    checkpoint lines deleted together. No signing key needed."""
    db.conn().execute("DROP TRIGGER audit_no_delete")
    db.conn().execute("DELETE FROM audit WHERE id > (SELECT MAX(id)-? FROM audit)", (n,))
    db.conn().commit()
    db.conn().execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    db.conn().commit()
    lines = audit._ANCHOR_FILE.read_text().splitlines()
    audit._ANCHOR_FILE.write_text("\n".join(lines[:-n]) + "\n")


def test_h6f_coordinated_truncation_detected(fresh_audit):
    for i in range(20):
        audit.record("evt", {"i": i})
    _truncate(5)
    v = audit.verify()
    assert not v["ok"], "coordinated rollback of records + checkpoints went unnoticed"
    assert any("rollback" in p.lower() or "external" in p.lower() for p in v["problems"])


def test_h6f_external_anchor_lives_outside_data_folder(fresh_audit):
    audit.record("evt", {})
    ext = config.AEGIS_ANCHOR_EXTERNAL
    assert ext, "no external anchor configured"
    from pathlib import Path
    assert not Path(ext).is_relative_to(config.ANCHOR_DIR)
    assert not Path(ext).is_relative_to(config.DATA_DIR)
    assert Path(ext).exists()


def test_h6f_anchor_never_regresses(fresh_audit):
    from pathlib import Path
    for i in range(10):
        audit.record("evt", {"i": i})
    ext = json.loads(Path(config.AEGIS_ANCHOR_EXTERNAL).read_text())
    assert ext["body"]["count"] == 10
    _truncate(4)
    audit.record("after_rollback", {})
    ext2 = json.loads(Path(config.AEGIS_ANCHOR_EXTERNAL).read_text())
    assert ext2["body"]["count"] >= 10, "external anchor regressed with the rollback"
    assert not audit.verify()["ok"]


def test_h6f_verify_ok_when_intact(fresh_audit):
    for i in range(8):
        audit.record("evt", {"i": i})
    v = audit.verify()
    assert v["ok"], v["problems"]


def test_h6f_readme_and_trust_report_state_the_case():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text().lower()
    assert "rollback" in readme and "external anchor" in readme
    from fastapi.testclient import TestClient
    from aegis.app import app, startup
    startup()
    with TestClient(app) as c:
        tok = c.post("/login", data={"username": "audi", "password": "demo-audi-2026"},
                     follow_redirects=False).cookies.get("aegis_session")
        tr = c.get("/compliance/trust-report.json", cookies={"aegis_session": tok}).json()
        limits = " ".join(tr["stated_limits"]).lower()
        assert "external anchor" in limits
        assert "rollback" in limits