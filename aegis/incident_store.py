"""Internal trusted-human service; no routes, reports, or notification actions.

The caller must authenticate the human session before passing a user mapping.
Stored identity/role and password-change gates are rechecked here, not replaced
by caller role flags. Epochs are supplied seconds since Unix epoch; only explicit
human confirmations establish awareness/determination. Steps never infer them.
Authorization, receipts and local inserts share an owned transaction.
Checkpoints follow commit; publication uncertainty never reports success.
"""
import hashlib
import math
import secrets
from collections.abc import Mapping

from . import audit, db, evidence


class IncidentIntegrityError(RuntimeError):
    """Stored evidence or its audit receipt could not be verified."""


def init_store():
    """Add only local tables/triggers without committing unrelated work."""
    c = db.conn()
    for table, columns in (
        ("incidents", "incident_id TEXT PRIMARY KEY"),
        ("incident_steps", "id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(incident_id)"),
    ):
        c.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns}, payload TEXT NOT NULL, audit_id INTEGER NOT NULL UNIQUE REFERENCES audit(id))")
        for operation in ("UPDATE", "DELETE"):
            c.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'incident records are append-only'); END")
        key = "incident_id" if table == "incidents" else "id"
        c.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table} WHEN EXISTS (SELECT 1 FROM {table} WHERE {key}=NEW.{key} OR audit_id=NEW.audit_id) BEGIN SELECT RAISE(ABORT, 'incident records are append-only'); END")


def _authorize(user, write=False):
    if (not isinstance(user, Mapping) or type(user.get("id")) is not int
            or not isinstance(user.get("username"), str)):
        raise PermissionError("Trusted human identity required")
    row = db.conn().execute("SELECT id, username, role, must_change FROM users WHERE id=?", (user["id"],)).fetchone()
    roles = ("admin",) if write else ("admin", "approver", "auditor")
    if (row is None or row["username"] != user["username"]
            or row["role"] != user.get("role") or row["role"] not in roles
            or row["must_change"]):
        raise PermissionError("Incident access refused")
    return row["id"]


def _verify():
    if audit.verify().get("ok") is not True:
        raise IncidentIntegrityError("Audit verification failed")


def _epoch(value):
    if value is not None and (type(value) not in (int, float)
            or not math.isfinite(value) or value < 0):
        raise ValueError("Finite nonnegative epoch required")
    return value


def _payload(text, facts, timestamp, awareness_at, human_awareness,
             determination_at, human_determination):
    if not isinstance(text, str) or not text.strip() or len(text) > 10000:
        raise ValueError("Nonblank text up to 10000 characters required")
    for epoch, confirmed in ((awareness_at, human_awareness), (determination_at, human_determination)):
        _epoch(epoch)
        if type(confirmed) is not bool or confirmed != (epoch is not None):
            raise ValueError("Epoch requires explicit human confirmation")
    if facts is None:
        facts = {}
    if not isinstance(facts, Mapping) or set(facts) - {"count", "data", "harm"}:
        raise ValueError("Only supplied count/data/harm facts accepted")
    known = {key: value for key, value in facts.items() if value is not None}
    if "count" in known and (type(known["count"]) is not int or not 0 <= known["count"] <= 2**63 - 1):
        raise ValueError("Nonnegative integer count required")
    if "harm" in known and type(known["harm"]) is not bool:
        raise ValueError("Explicit boolean harm required")
    if "data" in known:
        data = known["data"]
        if not isinstance(data, (str, list, tuple)) or (not isinstance(data, str) and any(not isinstance(v, str) for v in data)):
            raise ValueError("Data must be supplied text or text categories")
        if len(audit.canonical(data)) > 10000:
            raise ValueError("Data facts too long")
    return dict(text=text, facts=known, timestamp=_epoch(timestamp),
                awareness_at=awareness_at, human_awareness=human_awareness,
                determination_at=determination_at, human_determination=human_determination)


def _insert(table, iid, payload, actor):
    encrypted = evidence.enc_json(payload)
    event = "incident_created" if table == "incidents" else "incident_step_added"
    fingerprint = hashlib.sha256(encrypted.encode()).hexdigest()
    with audit.publication_lock():
        owned = getattr(db._local, 'incident_receipts', None) is not None
        if not owned:
            _verify()
        rid = audit.record(event, {"incident_id": iid, "actor_id": actor,
                                   "payload_sha256": fingerprint})
        if not owned:
            _verify()
        receipt = db.conn().execute("SELECT event, detail_json FROM audit WHERE id=?", (rid,)).fetchone()
        if receipt is None or receipt["event"] != event or evidence.dec_json(receipt["detail_json"]) != {
                "incident_id": iid, "actor_id": actor, "payload_sha256": fingerprint}:
            raise IncidentIntegrityError("Audit receipt mismatch")
        cur = db.conn().execute(f"INSERT INTO {table}(incident_id,payload,audit_id) VALUES(?,?,?)", (iid, encrypted, rid))
        if not owned:
            db.conn().commit()
    return {"id": iid if table == "incidents" else cur.lastrowid, "audit_id": rid}


def create_incident(user, *, title, facts=None, timestamp=None, awareness_at=None,
                    human_awareness=False, determination_at=None, human_determination=False):
    if db.conn().in_transaction:
        raise RuntimeError('Incident creation refuses an existing transaction')
    def prepare(stored):
        return _payload(title, facts, timestamp, awareness_at, human_awareness,
                        determination_at, human_determination), None
    return append_validated(user, None, prepare)


def add_step(user, incident_id, *, step, facts=None, timestamp=None, awareness_at=None,
             human_awareness=False, determination_at=None, human_determination=False):
    if getattr(db._local, 'incident_receipts', None) is None:
        if db.conn().in_transaction:
            raise RuntimeError('Incident append refuses an existing transaction')
        def prepare(stored):
            return _payload(step, facts, timestamp, awareness_at, human_awareness,
                            determination_at, human_determination), None
        return append_validated(user, incident_id, prepare)
    actor = _authorize(user, write=True)
    payload = _payload(step, facts, timestamp, awareness_at, human_awareness,
                       determination_at, human_determination)
    return _insert("incident_steps", incident_id, payload, actor)


def append_validated(user, incident_id, prepare):
    """Own authoritative validation and append; never commit caller writes.

    Checkpoints are published only after commit. Publication failure retains
    immutable evidence and is reported as an integrity failure, not success.
    """
    c = db.conn()
    if c.in_transaction:
        raise RuntimeError('Incident append refuses an existing transaction')
    with audit.publication_lock():
        c.execute('BEGIN IMMEDIATE')
        committed = False
        try:
            actor = _authorize(user, write=True)
            if incident_id is None:
                init_store()
                _verify()
                stored = None
            else:
                stored = get_incident(user, incident_id)
            payload, authority = prepare(stored)
            receipts = []
            db._local.incident_receipts = receipts
            if authority is not None:
                event, detail, attach = authority
                rid = audit.record(event, detail)
                payload['text'] = attach(rid)
            if incident_id is None:
                result = _insert('incidents', secrets.token_hex(16), payload, actor)
            else:
                result = add_step(user, incident_id, step=payload['text'],
                    **{key: value for key, value in payload.items() if key != 'text'})
            _verify()
            c.commit()
            committed = True
            db._local.incident_receipts = None
            for receipt in receipts:
                if audit.checkpoint(through_id=receipt) is not True:
                    raise IncidentIntegrityError('Incident committed; checkpoint publication failed')
            _verify()
            return result
        except BaseException:
            if not committed:
                c.rollback()
            raise
        finally:
            db._local.incident_receipts = None


def _decode(row, event):
    receipt = db.conn().execute("SELECT event, detail_json FROM audit WHERE id=?", (row["audit_id"],)).fetchone()
    if receipt is None or receipt["event"] != event:
        raise IncidentIntegrityError("Incident receipt missing")
    detail = evidence.dec_json(receipt["detail_json"])
    if (detail.get("incident_id") != row["incident_id"] or
            detail.get("payload_sha256") != hashlib.sha256(row["payload"].encode()).hexdigest()):
        raise IncidentIntegrityError("Incident receipt mismatch")
    payload = evidence.dec_json(row["payload"])
    payload["title" if event == "incident_created" else "step"] = payload.pop("text")
    return dict(payload, id=row["incident_id"] if event == "incident_created" else row["id"],
                actor_id=detail["actor_id"], audit_id=row["audit_id"])


def get_incident(user, incident_id):
    _authorize(user)
    if not isinstance(incident_id, str) or not incident_id:
        raise ValueError("Incident ID required")
    init_store()
    with audit.publication_lock():
        _verify()
        row = db.conn().execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise KeyError("Incident not found")
        result = _decode(row, "incident_created")
        result["steps"] = [_decode(s, "incident_step_added") for s in db.conn().execute(
            "SELECT * FROM incident_steps WHERE incident_id=? ORDER BY id", (incident_id,))]
        return result


def list_incidents(user):
    _authorize(user)
    init_store()
    with audit.publication_lock():
        _verify()
        return [get_incident(user, row[0]) for row in db.conn().execute(
            "SELECT incident_id FROM incidents ORDER BY audit_id").fetchall()]
