"""Tamper-evident audit log.

Each record carries the SHA-256 fingerprint of the one before it. A signed
checkpoint (record count + max id + last hash + previous checkpoint signature,
HMAC-SHA256) is written OUTSIDE the database WITH EVERY RECORD, and each
checkpoint chains to the one before it.

Verify detects: edited/inserted records, deleted newest records, a deleted or
truncated checkpoint file, removed checkpoint lines (last or middle), and
checkpoints out of sequence.

Stated limit (plan section 8.7): an attacker who controls the database, the
signing key and the outside copies TOGETHER could rewrite history. Checkpoints
written before the per-record regime (legacy, every 25 records) are still
signature- and position-checked, but the per-record completeness guarantee
starts with the first chained checkpoint.
"""
import hashlib
import fcntl
from contextlib import contextmanager
import hmac
import json
import os
import threading
import tempfile
import time
from pathlib import Path
from . import config, db, evidence, signer_client
from .signer_client import SignerUnavailable

_KEY_FILE = config.ANCHOR_DIR / "signing.key"   # LEGACY anchor key only
_ANCHOR_FILE = config.ANCHOR_DIR / "checkpoints.jsonl"
CHECKPOINT_EVERY = 1   # a checkpoint with every record
_LOCK = threading.RLock()   # chain read+append+checkpoint is ONE step
_signer_health_cache = {"ts": 0.0, "ok": False}
_signer_degraded = {"ts": 0.0, "reason": ""}


_publication_local = threading.local()


@contextmanager
def publication_lock():
    """Serialize chain append through external publication across processes.

    Nested store/record/checkpoint/verify calls reuse the same file lock;
    acquiring a second descriptor would deadlock even in the same process.
    """
    with _LOCK:
        depth = getattr(_publication_local, 'depth', 0)
        connection = getattr(db._local, 'conn', None)
        if not depth and connection is not None and connection.in_transaction:
            raise RuntimeError('Acquire publication lock before SQLite transaction')
        if depth:
            _publication_local.depth = depth + 1
            try:
                yield
            finally:
                _publication_local.depth = depth
            return
        config.validate_db_path(config.DB_PATH)
        with open(str(config.DB_PATH) + '.audit.lock', 'a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            _publication_local.depth = 1
            try:
                yield
            finally:
                _publication_local.depth = 0
                fcntl.flock(handle, fcntl.LOCK_UN)


def _stream_id() -> str:
    """One signer stream per database path."""
    return hashlib.sha256(str(config.DB_PATH).encode()).hexdigest()[:12]


def _signer_request(obj: dict) -> dict:
    return signer_client.SignerClient("127.0.0.1", config.AEGIS_SIGNER_PORT).request(obj)


def signer_healthy(*, fresh=False) -> bool:
    now = time.time()
    if _signer_degraded["reason"] and now - _signer_degraded["ts"] < 5.0:
        return False   # a recent signing/write failure: fail closed
    if not fresh and now - _signer_health_cache["ts"] < 2.0:
        return _signer_health_cache["ok"]
    try:
        ok = bool(_signer_request({"op": "ping"}).get("ok"))
    except SignerUnavailable:
        ok = False
    _signer_health_cache.update(ts=now, ok=ok)
    return ok


def migrate_to_signer():
    """One-time migration: new checkpoints are signed by the separate signer.
    Legacy anchors stay verifiable with the legacy key. Recorded in the log."""
    if db.get_setting("signer_migrated") == "1":
        return
    if not signer_healthy():
        return   # retry at next startup; never migrate unsigned
    record("signer_migration",
           {"note": "checkpoints now signed by the separate signer process; "
                    "legacy anchors remain verifiable with the legacy key",
            "signer_state_outside_data_folder": True})
    db.set_setting("signer_migrated", "1", "system", time.time())


def _signing_key() -> bytes:
    if _KEY_FILE.exists():
        return bytes.fromhex(_KEY_FILE.read_text().strip())
    key = os.urandom(32)
    fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(key.hex())
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(str(_KEY_FILE.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return key


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def last_hash() -> str:
    row = db.conn().execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    return row["hash"] if row else "genesis"


def record(event: str, detail: dict, run_id=None, session_id=None) -> int:
    with publication_lock():
        c = db.conn()
        if getattr(db._local, 'incident_receipts', None) is not None:
            rid = append_incident(event, detail)
            db._local.incident_receipts.append(rid)
            return rid
        prev = last_hash()
        ts = time.time()
        payload = canonical({"ts": ts, "run_id": run_id, "session_id": session_id,
                             "event": event, "detail": detail})
        h = hashlib.sha256((prev + payload).encode()).hexdigest()
        cur = c.execute(
            "INSERT INTO audit(ts,run_id,session_id,event,detail_json,prev_hash,hash) "
            "VALUES(?,?,?,?,?,?,?)",
            (ts, run_id, session_id, event, evidence.enc(canonical(detail)), prev, h),
        )
        c.commit()
        rid = cur.lastrowid
        if rid % CHECKPOINT_EVERY == 0:
            checkpoint()
        return rid


def record_decision(event: str, detail: dict, *, trusted_ts, run_id=None,
                    session_id=None) -> dict:
    """Commit pending local writes with an encrypted event, then checkpoint."""
    with publication_lock():
        c = db.conn()
        try:
            prev = last_hash()
            payload = canonical({"ts": trusted_ts, "run_id": run_id,
                                 "session_id": session_id, "event": event,
                                 "detail": detail})
            h = hashlib.sha256((prev + payload).encode()).hexdigest()
            cur = c.execute(
                "INSERT INTO audit(ts,run_id,session_id,event,detail_json,prev_hash,hash) "
                "VALUES(?,?,?,?,?,?,?)",
                (trusted_ts, run_id, session_id, event,
                 evidence.enc(canonical(detail)), prev, h),
            )
            c.commit()
        except BaseException:
            c.rollback()
            raise
        # Postcommit failures must retain the decision and its audit history.
        return {"event_id": cur.lastrowid, "checkpoint_ok": checkpoint() is True}


def _last_anchor_line():
    """Read only the tail of the checkpoint file (O(1), no full-file parse)."""
    if not _ANCHOR_FILE.exists():
        return None
    with open(_ANCHOR_FILE, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if not size:
            return None
        f.seek(max(0, size - 65_536))
        tail = f.read().decode("utf-8", "replace")
    lines = [l for l in tail.splitlines() if l.strip()]
    return lines[-1] if lines else None


def _external_path():
    p = config.AEGIS_ANCHOR_EXTERNAL
    return Path(p) if p else None


def _write_external_anchor(count: int, max_id: int, last_hash: str, checkpoint_sig: str):
    """Forward-only latest-checkpoint record OUTSIDE the data folder. A data
    folder rollback (records + checkpoint lines together) cannot reach it.
    Never regresses: a smaller count means the data folder was rolled back."""
    path = _external_path()
    if path is None:
        return
    body = {"count": count, "max_id": max_id, "last_hash": last_hash,
            "checkpoint_sig": checkpoint_sig, "ts": time.time()}
    if path.exists():
        try:
            old = json.loads(path.read_text())
            if old["body"]["count"] >= count:
                return  # rollback in progress — keep the higher water mark
        except (ValueError, KeyError):
            pass  # unreadable external anchor: rewrite it (verify flags tampering)
    sig = hmac.new(_signing_key(), canonical(body).encode(), hashlib.sha256).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    tmp = Path(temporary)
    with os.fdopen(fd, 'w') as f:
        f.write(canonical({"body": body, "sig": sig}))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    directory_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def append_incident(event, detail):
    """Append without commit; the incident transaction owns publication."""
    c = db.conn()
    if (not c.in_transaction
            or getattr(db._local, 'incident_receipts', None) is None
            or not getattr(_publication_local, 'depth', 0)):
        raise RuntimeError('Incident audit append requires an owned transaction')
    prev = last_hash()
    ts = time.time()
    payload = canonical(dict(ts=ts, run_id=None, session_id=None,
                             event=event, detail=detail))
    return c.execute(
        'INSERT INTO audit(ts,run_id,session_id,event,detail_json,prev_hash,hash) '
        'VALUES(?,?,?,?,?,?,?)',
        (ts, None, None, event, evidence.enc(canonical(detail)), prev,
         hashlib.sha256((prev + payload).encode()).hexdigest())).lastrowid


def checkpoint(*, through_id=None) -> bool:
    with publication_lock():
        c = db.conn()
        row = c.execute("SELECT COUNT(*) n, MAX(id) mx FROM audit WHERE (? IS NULL OR id<=?)",
                        (through_id, through_id)).fetchone()
        if not row["n"]:
            return False
        last = c.execute("SELECT hash FROM audit WHERE id=?", (row['mx'],)).fetchone()["hash"]
        prior_bytes = _ANCHOR_FILE.read_bytes() if _ANCHOR_FILE.exists() else b''
        if prior_bytes and not prior_bytes.endswith(b'\n'):
            return False
        tail = _last_anchor_line()
        published_count = 0
        if tail:
            try:
                published_count = json.loads(tail)['body']['count']
            except (ValueError, KeyError, TypeError):
                return False
        if published_count < row['n'] - 1:
            missing = c.execute('SELECT id FROM audit WHERE (? IS NULL OR id<=?) '
                                'ORDER BY id LIMIT ? OFFSET ?',
                                (through_id, through_id, row['n'] - published_count - 1,
                                 published_count)).fetchall()
            for prefix in missing:
                if checkpoint(through_id=prefix['id']) is not True:
                    return False
            tail = _last_anchor_line()
        if tail:
            try:
                prev = json.loads(tail)
                # idempotent: an explicit checkpoint() after an automatic one adds nothing
                if (prev["body"].get("count") == row["n"] and prev["body"].get("max_id") == row["mx"]
                        and prev['body'].get('last_hash') == last):
                    with open(_ANCHOR_FILE, 'rb') as handle:
                        os.fsync(handle.fileno())
                    directory_fd = os.open(_ANCHOR_FILE.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                    _write_external_anchor(row["n"], row["mx"], last, prev.get("sig", ""))
                    return True
            except (ValueError, KeyError):
                pass
        body = {"count": row["n"], "max_id": row["mx"], "last_hash": last, "ts": time.time()}
        # R3: the SEPARATE SIGNER signs; the main app never touches the key.
        try:
            r = _signer_request({"op": "sign", "stream": _stream_id(), "body": body})
        except SignerUnavailable as e:
            _signer_degraded.update(ts=time.time(), reason=str(e))
            return False   # fail closed: gateway holds side effects while degraded
        if type(r) is not dict:
            return False
        if r.get("error"):
            _signer_degraded.update(ts=time.time(), reason=r["error"])
            return False
        try:
            prior_bytes = _ANCHOR_FILE.read_bytes() if _ANCHOR_FILE.exists() else b''
            fd, temporary = tempfile.mkstemp(prefix=_ANCHOR_FILE.name + '.', dir=_ANCHOR_FILE.parent)
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(prior_bytes + (canonical({"body": r["body"], "seq": r["seq"],
                            "sig": r["sig"], "signer": True}) + "\n").encode())
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temporary, _ANCHOR_FILE)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            directory_fd = os.open(str(_ANCHOR_FILE.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as e:
            _signer_degraded.update(ts=time.time(), reason=f"checkpoint write refused: {e}")
            return False
        _signer_degraded.update(ts=0.0, reason="")
        _write_external_anchor(row["n"], row["mx"], last, r["sig"])
        return True


def verify() -> dict:
    """Recompute the chain and compare against every outside checkpoint.

    Returns {ok, problems[], records}. Any edit, delete, truncation, missing
    checkpoint or out-of-sequence checkpoint is named.
    """
    with publication_lock():
        try:
            return _verify_inner()
        except (ValueError, KeyError, TypeError, IndexError, evidence.EvidenceKeyError):
            return {'ok': False, 'problems': ['audit evidence or checkpoint malformed'],
                    'records': db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]}


def _verify_inner() -> dict:
    problems = []
    rows = db.conn().execute("SELECT * FROM audit ORDER BY id").fetchall()
    pending = getattr(db._local, 'incident_receipts', None)
    # Unpublished transaction rows have no external checkpoint yet. Verify
    # their chain below, but compare anchors only with the committed prefix.
    committed_rows = [r for r in rows if not pending or r['id'] < pending[0]]
    prev = "genesis"
    for r in rows:
        payload = canonical({"ts": r["ts"], "run_id": r["run_id"],
                             "session_id": r["session_id"], "event": r["event"],
                             "detail": json.loads(evidence.dec(r["detail_json"]))})
        expect = hashlib.sha256((prev + payload).encode()).hexdigest()
        if r["prev_hash"] != prev:
            problems.append(f"record {r['id']}: broken chain link (edited or inserted)")
        if r["hash"] != expect:
            problems.append(f"record {r['id']}: content fingerprint mismatch (edited)")
        prev = r["hash"]
    rows = committed_rows
    count = len(rows)
    last = rows[-1]["hash"] if rows else "genesis"
    key = _signing_key()
    anchors = []
    new_anchors = []
    if _ANCHOR_FILE.exists():
        for line in _ANCHOR_FILE.read_text().splitlines():
            if not line.strip():
                continue
            try:
                a = json.loads(line)
                if not isinstance(a, dict) or not isinstance(a.get('body'), dict):
                    raise ValueError('Invalid checkpoint shape')
            except ValueError:
                problems.append("checkpoint file: unreadable line (tampered)")
                continue
            if a.get("signer"):
                if type(a.get('seq')) is not int or a['seq'] <= 0:
                    raise ValueError('Invalid checkpoint sequence')
                new_anchors.append(a)
            else:
                body = canonical(a["body"])
                sig = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, a.get("sig", "")):
                    problems.append("checkpoint: signature invalid (tampered)")
            anchors.append(a)
    # new-format (signer) checkpoints: sequence must be contiguous
    if new_anchors:
        seqs = [a.get("seq", 0) for a in new_anchors]
        if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
            problems.append("signer checkpoints out of sequence (removed or reordered)")
    # checkpoint sequence + chain of signatures — checked WITHIN each regime
    # (legacy local-key anchors and signer anchors have independent chains)
    legacy = [a for a in anchors if not a.get("signer")]
    for group in (legacy, new_anchors):
        prev_a = None
        for a in group:
            b = a["body"]
            if prev_a is not None:
                if b["count"] <= prev_a["body"]["count"] or b.get("max_id", 0) <= prev_a["body"].get("max_id", 0):
                    problems.append(f"checkpoint at record {b['count']}: out of sequence (reordered or inserted)")
                if "prev_sig" in b:
                    if b["prev_sig"] != prev_a.get("sig", "genesis"):
                        problems.append(f"checkpoint at record {b['count']}: chain link broken (removed or reordered)")
                    if "prev_sig" in prev_a["body"] and b["count"] != prev_a["body"]["count"] + 1:
                        problems.append(f"checkpoint missing between records {prev_a['body']['count']} and {b['count']}")
            if "prev_sig" in b and prev_a is None and b["prev_sig"] != "genesis":
                problems.append("first checkpoint does not start the chain (earlier checkpoints removed)")
            prev_a = a
    # checkpoints vs the log itself
    for a in anchors:
        b = a["body"]
        if b["count"] > count:
            problems.append(
                f"checkpoint expects {b['count']} records, found {count}: newest records deleted")
        elif rows:
            r = rows[b["count"] - 1]
            if r["hash"] != b["last_hash"]:
                problems.append(
                    f"checkpoint at record {b['count']}: hash mismatch (history rewritten)")
            if b.get("max_id") is not None and r["id"] != b["max_id"]:
                problems.append(
                    f"checkpoint at record {b['count']}: record id mismatch (history rewritten)")
    if rows and not anchors:
        problems.append(f"checkpoint file missing or empty: expected {count} checkpoints, found 0")
    elif rows and anchors:
        newest = anchors[-1]["body"]["count"]
        if newest < count:
            problems.append(f"checkpoints missing for newest records: expected {count}, last checkpoint covers {newest}")
    if anchors and not rows:
        problems.append("audit table empty but checkpoints exist: records deleted")
    # R3: compare against the SEPARATE SIGNER's own forward-only record
    try:
        checked = _signer_request({"op": "verify_batch", "stream": _stream_id(),
                                   "lines": new_anchors})
        if type(checked) is not dict:
            raise ValueError('Malformed signer response')
        results = checked.get("results")
        if (not isinstance(results, list) or len(results) != len(new_anchors)
                or any(ok is not True for ok in results)):
            problems.append("checkpoint: signature invalid (tampered)")
        latest = checked['latest']
        if (type(latest) is not dict or type(latest.get('seq')) is not int
                or latest['seq'] < 0 or (latest['seq'] == 0 and latest != {'seq': 0})):
            raise ValueError('Malformed signer latest')
        if latest['seq'] > 0:
            lb = latest['body']
            if (type(lb) is not dict or type(lb.get('count')) is not int
                    or lb['count'] <= 0 or type(lb.get('max_id')) is not int
                    or lb['max_id'] < lb['count'] or type(lb.get('last_hash')) is not str):
                raise ValueError('Malformed signer latest body')
    except SignerUnavailable as e:
        latest = None
        # Empty local evidence cannot establish that this stream is pristine.
        problems.append(f"signer unreachable: cannot verify against the signer's record ({e})")
    if latest is not None:
        if new_anchors and latest.get("seq", 0) == 0:
            problems.append("signer record missing or reset: checkpoint file holds signed "
                            "checkpoints but the signer remembers none")
        elif latest.get("seq", 0) > 0:
            lb = latest["body"]
            if lb["count"] > count:
                problems.append(
                    f"data folder rolled back: signer remembers {lb['count']} records, "
                    f"found {count} (records and checkpoints deleted together)")
            elif rows:
                r = rows[lb["count"] - 1]
                if r["hash"] != lb["last_hash"] or r["id"] != lb["max_id"]:
                    problems.append("signer record: hash/id mismatch (history rewritten)")
            if new_anchors:
                la = new_anchors[-1]
                if la.get("seq") != latest["seq"] or la.get("sig") != latest["sig"]:
                    problems.append("checkpoint file truncated below the signer's record "
                                    "(coordinated truncation)")
    # external anchor: catches a coordinated rollback of the WHOLE data folder
    # (newest records AND newest checkpoint lines deleted together)
    ext_path = _external_path()
    if rows and ext_path is None:
        problems.append("external anchor disabled (AEGIS_ANCHOR_EXTERNAL=''): "
                        "coordinated data-folder rollback is not detectable")
    elif ext_path is not None and (rows or ext_path.exists()):
        if not ext_path.exists():
            problems.append("external anchor missing (deleted or never created): "
                            "coordinated data-folder rollback is not detectable")
        else:
            try:
                ext = json.loads(ext_path.read_text())
                body = canonical(ext["body"])
                sig = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, ext.get("sig", "")):
                    problems.append("external anchor: signature invalid (tampered)")
                eb = ext["body"]
                if eb["count"] > count:
                    problems.append(
                        f"data folder rolled back: external anchor expects {eb['count']} "
                        f"records, found {count} (records and checkpoints deleted together)")
                elif rows:
                    r = rows[eb["count"] - 1]
                    if r["hash"] != eb["last_hash"] or r["id"] != eb["max_id"]:
                        problems.append("external anchor: hash/id mismatch (history rewritten)")
                if anchors and not any(a.get("sig") == eb.get("checkpoint_sig") for a in anchors):
                    problems.append("external anchor's checkpoint line missing from checkpoint "
                                    "file (coordinated truncation)")
            except (ValueError, KeyError, TypeError):
                problems.append("external anchor: unreadable (tampered)")
    return {"ok": not problems, "problems": problems, "records": count,
            "checkpoints": len(anchors), "last_hash": last}


def export_records() -> list:
    out = []
    for r in db.conn().execute("SELECT * FROM audit ORDER BY id").fetchall():
        d = dict(r)
        d["detail_json"] = evidence.dec(d["detail_json"])
        out.append(d)
    return out