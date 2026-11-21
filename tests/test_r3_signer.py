"""R3 — separate signer process. The main app never handles the signing key;
the signer keeps its own forward-only record outside the data folder; Verify
compares against it; side effects are held when the signer is down.

States (state-machine skill): signer DOWN/UP; sign requests forward-only per
DB stream; restart resumes the same chain; gateway side-effect gate guarded
by signer health. Protocol tests use a dedicated stream; tamper tests use an
isolated DB so the shared session stream is never regressed.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from aegis import audit, config, db, gateway, signer_client
from conftest import make_session

ROOT = Path(__file__).resolve().parent.parent
@pytest.fixture
def protocol_stream():
    return f"r3-{os.urandom(16).hex()}"


@pytest.fixture
def isolated_signer(tmp_path, monkeypatch):
    manager = signer_client.SignerManager(str(tmp_path / "signer"))
    monkeypatch.setattr(config, "AEGIS_SIGNER_STATE", manager.state_dir)
    monkeypatch.setattr(config, "AEGIS_SIGNER_PORT", manager.port)
    monkeypatch.setattr(audit, "_signer_health_cache", {"ts": 0, "ok": False})
    monkeypatch.setattr(audit, "_signer_degraded", {"ts": 0, "reason": ""})
    try:
        yield manager
    finally:
        manager.stop()


def test_signer_reload_rejects_forged_history(tmp_path):
    from aegis.signer import SignerState
    state = SignerState(tmp_path / 'isolated')
    state.sign('test', {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64})
    record = json.loads(state.rec_file.read_text())
    record['body']['last_hash'] = 'forged'
    state.rec_file.write_text(json.dumps(record) + '\n')
    with pytest.raises(ValueError):
        state._load()


def test_signer_instances_refresh_before_append(tmp_path):
    from aegis.signer import SignerState
    first = SignerState(tmp_path / 'isolated')
    second = SignerState(tmp_path / 'isolated')
    assert first.sign('test', {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64})['seq'] == 1
    assert second.sign('test', {'count': 2, 'max_id': 2, 'last_hash': 'b' * 64})['seq'] == 2


def test_signer_processes_serialize_shared_stream(tmp_path):
    state_dir = str(tmp_path / 'multiprocess')
    code = '''
import sys
from aegis.signer import SignerState
state = SignerState(sys.argv[1])
for _ in range(12):
    with state.lock():
        state._load()
        count = state.latest.get('shared', {}).get('seq', 0) + 1
    result = state.sign('shared', {'count': count, 'max_id': count,
                                  'last_hash': format(count, '064x')})
    assert 'seq' in result or 'error' in result
'''
    processes = [subprocess.Popen([sys.executable, '-c', code, state_dir], cwd=ROOT)
                 for _ in range(4)]
    try:
        for process in processes:
            assert process.wait(timeout=20) == 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    from aegis.signer import SignerState
    state = SignerState(state_dir)
    records = state.records['shared']
    assert len(records) >= 12
    assert sorted(records) == list(range(1, len(records) + 1))
    assert state.latest['shared']['seq'] == len(records)


def test_signer_acknowledgement_fsyncs_file_and_directory(tmp_path, monkeypatch):
    from aegis import signer
    state = signer.SignerState(tmp_path / 'durable')
    calls = []
    original = signer.os.fsync

    def observe(fd):
        calls.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        original(fd)

    monkeypatch.setattr(signer.os, 'fsync', observe)
    state.sign('durable', {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64})
    assert calls == [False, True]


def _client():
    return signer_client.SignerClient("127.0.0.1", config.AEGIS_SIGNER_PORT)


@pytest.fixture
def fresh_db(tmp_path, monkeypatch, isolated_signer):
    tmp_path = tmp_path / "data"
    tmp_path.mkdir()
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(config, "ANCHOR_DIR", tmp_path)
    monkeypatch.setattr(audit, "_KEY_FILE", tmp_path / "signing.key")
    monkeypatch.setattr(audit, "_ANCHOR_FILE", tmp_path / "checkpoints.jsonl")
    monkeypatch.setattr(config, "AEGIS_ANCHOR_EXTERNAL",
                        str(tmp_path.parent / (tmp_path.name + "-ext") / "anchor.json"),
                        raising=False)
    monkeypatch.setattr(db._local, "conn", None)
    db.init_db()
    try:
        yield tmp_path
    finally:
        if db._local.conn is not None:
            db._local.conn.close()
        db._local.conn = None


def _truncate(n):
    db.conn().execute("DROP TRIGGER audit_no_delete")
    db.conn().execute("DELETE FROM audit WHERE id > (SELECT MAX(id)-? FROM audit)", (n,))
    db.conn().commit()
    db.conn().execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    db.conn().commit()
    lines = audit._ANCHOR_FILE.read_text().splitlines()
    audit._ANCHOR_FILE.write_text("\n".join(lines[:-n]) + "\n")


def test_r3_signer_is_up_and_signs_forward_only(protocol_stream):
    c = _client()
    assert c.request({"op": "ping"})["ok"]
    r1 = c.request({"op": "sign", "stream": protocol_stream,
                    "body": {"count": 10, "max_id": 10, "last_hash": "a" * 64, "ts": time.time()}})
    assert r1["seq"] >= 1
    r2 = c.request({"op": "sign", "stream": protocol_stream,
                    "body": {"count": 1, "max_id": 1, "last_hash": "b" * 64, "ts": time.time()}})
    assert r2.get("error"), r2


def test_r3_coordinated_truncation_fails_verify(fresh_db):
    for i in range(6):
        audit.record("r3_evt", {"i": i})
    _truncate(3)
    v = audit.verify()
    assert not v["ok"]
    assert any("signer" in p.lower() or "rollback" in p.lower() for p in v["problems"])


def test_r3_whole_data_folder_restore_fails_verify(fresh_db, tmp_path):
    for i in range(4):
        audit.record("r3_base", {"i": i})
    snap = tmp_path / "snapshot"
    shutil.copytree(fresh_db, snap)
    for i in range(5):
        audit.record("r3_advance", {"i": i})
    for f in snap.rglob("*"):
        if f.is_file():
            dest = fresh_db / f.relative_to(snap)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
    db._local.conn = None
    v = audit.verify()
    assert not v["ok"], "restoring an older data folder went unnoticed"
    assert any("signer" in p.lower() or "rollback" in p.lower() for p in v["problems"])


def test_r3_main_app_cannot_read_signing_key():
    state = Path(config.AEGIS_SIGNER_STATE)
    key = state / "signing.key"
    assert key.exists()
    assert not key.is_relative_to(config.DATA_DIR)            # outside data folder
    assert stat.S_IMODE(key.stat().st_mode) == 0o600          # owner-only
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert "AEGIS_SIGNER_KEY" not in os.environ               # no key in app env
    src = (ROOT / "aegis" / "audit.py").read_text()
    assert src.count("signing.key") == 1                      # legacy anchor key only
    r = _client().request({"op": "key"})
    assert r.get("error")                                     # protocol never yields the key


@pytest.fixture
def isolated_failure_stream(_clean_runtime, reviewed14_sandbox_tools, tmp_path, monkeypatch):
    data = tmp_path / 'data'
    anchors = data / 'anchors'
    anchors.mkdir(parents=True)
    monkeypatch.setattr(config, 'DATA_DIR', data)
    monkeypatch.setattr(config, 'DB_PATH', data / 'aegis.db')
    monkeypatch.setattr(config, 'ANCHOR_DIR', anchors)
    monkeypatch.setattr(config, 'AEGIS_ANCHOR_EXTERNAL', str(tmp_path / 'external' / 'anchor.json'))
    monkeypatch.setattr(audit, '_KEY_FILE', anchors / 'signing.key')
    monkeypatch.setattr(audit, '_ANCHOR_FILE', anchors / 'checkpoints.jsonl')
    monkeypatch.setattr(audit, '_signer_health_cache', {'ts': 0, 'ok': False})
    monkeypatch.setattr(audit, '_signer_degraded', {'ts': 0, 'reason': ''})
    monkeypatch.setattr(db._local, 'conn', None)
    state = str(tmp_path / 'signer')
    monkeypatch.setattr(config, 'AEGIS_SIGNER_STATE', state)
    manager = signer_client.SignerManager(state)
    monkeypatch.setattr(config, 'AEGIS_SIGNER_PORT', manager.port)
    try:
        db.init_db()
        # Dependency supplies the literal review; install it in the switched DB.
        from conftest import _literal_test_registry
        _literal_test_registry(reviewed14_sandbox_tools)
        from aegis import policy
        policy.ensure_default(str(ROOT / 'policies' / 'default.yaml'))
        policy.ensure_security_rules(str(ROOT / 'policies' / 'default.yaml'))
        audit.migrate_to_signer()
        yield
    finally:
        if db._local.conn is not None:
            db._local.conn.close()
        try:
            manager.stop()
        finally:
            # Restore the shared connection before the review fixture tears down.
            monkeypatch.undo()


def test_r3_signer_down_holds_side_effects(monkeypatch, isolated_failure_stream):
    monkeypatch.setattr(config, "AEGIS_SIGNER_PORT", 1)  # nothing listens here
    audit._signer_health_cache = {"ts": 0, "ok": False}
    _, s = make_session(task="Email the Acme Q3 report to Rosa at Acme Industries.")
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": "y"},
                              "r3-down-key")
    assert out["verdict"] in ("hold", "block")
    assert any(r["rule"] == "HARD-SIGNER" for r in out["reasons"])
    out2 = gateway.handle_call(s["token"], "list_inbox", {}, None)
    assert out2["verdict"] == "allow", (
        f"list_inbox verdict={out2['verdict']!r}; reasons={out2['reasons']!r}"
    )
    audit._signer_health_cache = {"ts": 0, "ok": False}


def test_r3_signer_restart_continues_chain(protocol_stream, isolated_signer):
    c = _client()
    before = c.request({"op": "sign", "stream": protocol_stream,
                        "body": {"count": 10, "max_id": 10, "last_hash": "a" * 64, "ts": time.time()}})
    assert before["seq"] == 1
    isolated_signer.restart()                      # same state dir, same port
    audit._signer_health_cache = {"ts": 0, "ok": False}
    c2 = _client()
    after = c2.request({"op": "latest", "stream": protocol_stream})
    assert after["seq"] == before["seq"]      # resumed, not a new chain
    r = c2.request({"op": "sign", "stream": protocol_stream,
                    "body": {"count": 11, "max_id": 11, "last_hash": "c" * 64, "ts": time.time()}})
    assert r["seq"] == before["seq"] + 1


def test_r3_concurrent_sign_requests_unique_seq(protocol_stream):
    c = _client()
    # (a) two processes checkpointing the SAME state at once: idempotent, one seq
    results, errors = [], []
    body = {"count": 500, "max_id": 500, "last_hash": "d" * 64, "ts": time.time()}
    def same_worker(_):
        try:
            results.append(c.request({"op": "sign", "stream": protocol_stream + "-conc",
                                      "body": body}))
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=same_worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    seqs = [r["seq"] for r in results]
    assert len(set(seqs)) == 1, seqs            # one chain position, not eight
    # (b) racing increasing counts: winners get unique contiguous seqs,
    # out-of-order losers are refused forward-only (never a crash)
    results2, errors2 = [], []
    def inc_worker(i):
        try:
            results2.append(c.request({"op": "sign", "stream": protocol_stream + "-conc2",
                                       "body": {"count": 600 + i, "max_id": 600 + i,
                                                "last_hash": format(i, '064x'), "ts": time.time()}}))
        except Exception as e:
            errors2.append(e)
    threads = [threading.Thread(target=inc_worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors2, errors2
    ok = [r["seq"] for r in results2 if "seq" in r]
    refused = [r for r in results2 if r.get("error")]
    assert ok and len(ok) == len(set(ok))
    assert sorted(ok) == list(range(min(ok), max(ok) + 1))
    assert all("regression" in r["error"] for r in refused)


def test_r3_clock_backwards_still_signs(protocol_stream):
    c = _client()
    latest = c.request({"op": "sign", "stream": protocol_stream,
                        "body": {"count": 11, "max_id": 11, "last_hash": "c" * 64, "ts": time.time()}})
    assert latest["seq"] == 1
    r = c.request({"op": "sign", "stream": protocol_stream,
                   "body": {"count": 12, "max_id": 12, "last_hash": "e" * 64, "ts": 1.0}})
    assert r.get("seq") == latest["seq"] + 1    # ordering by seq, not clock


def test_r3_signer_record_deleted_fails_verify(fresh_db, tmp_path):
    state = Path(config.AEGIS_SIGNER_STATE)
    rec = state / "records.jsonl"
    audit.record("r3_before_delete", {})
    rec.write_text("")
    c = _client()
    c.request({"op": "reload"})
    v = audit.verify()
    assert not v["ok"]
    assert any("signer" in p.lower() for p in v["problems"])
    # The fixture stops this disposable signer even if verification fails.


def test_r3_migration_recorded():
    events = [r["event"] for r in db.conn().execute("SELECT event FROM audit").fetchall()]
    assert "signer_migration" in events