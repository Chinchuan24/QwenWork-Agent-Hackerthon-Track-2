"""Human approvals: fingerprint-bound, single-use, expiring, no self-approval.

The fingerprint covers the tool, the arguments, the content of every
attachment, the resolved recipients and their clients, the task limits and
the policy version. If any of these changes before execution, the approval
is void. Claiming is a single all-or-nothing step.
"""
import hashlib
import json
import time
import uuid
import unicodedata
from . import audit, config, db, evidence, gateway, policy


def fingerprint(sess, tool: str, args: dict, w) -> str:
    resolved = {"tool": tool, "args": args,
                "sandbox_passport": gateway._passport_state(tool)}
    if tool == "send_email":
        to = args.get("to", "").strip().lower()
        resolved["recipient_client"] = w.client_of_email(to)
        resolved["attachments"] = [
            {"id": aid, "sha256": hashlib.sha256(
                json.dumps(w.doc(aid) or {}, sort_keys=True).encode()).hexdigest()}
            for aid in args.get("attachment_ids", [])]
    if tool in ("delete_file", "upload_file", "accept_terms"):
        resolved["document"] = w.doc(args.get("doc_id", ""))
    if tool in ("pay_supplier", "order_supplier"):
        resolved["suppliers"] = w.state.get("suppliers", {})
        resolved["invoice"] = w.ledger_entry(args.get("invoice_id", ""))
    if tool == "issue_refund":
        resolved["ledger"] = w.ledger_entry(args.get("invoice_id", ""))
    if tool in gateway.SIDE_EFFECT:
        resolved['financial_sources'] = w.state.get('documents', {})
        resolved['financial_authority'] = db.get_setting('financial_agreement_authority', 'null')
        resolved['source_scope'] = db.get_setting('source_message_scope:' + sess['id'], 'null')
    resolved["limits_hash"] = sess["limits_hash"]
    resolved["policy_version"] = policy.active_version()
    return hashlib.sha256(json.dumps(resolved, sort_keys=True, default=str).encode()).hexdigest()


def request(action_id: str, sess, tool: str, args: dict, reasons: list) -> dict:
    w = gateway.get_world(sess["run_id"])
    fp = fingerprint(sess, tool, args, w)
    aid = uuid.uuid4().hex[:12]
    now = time.time()
    held_rules = [r["rule"] for r in reasons if not r.get("ai_written")]
    db.conn().execute(
        "INSERT INTO approvals(id,action_id,fingerprint,status,requested_at,expires_at,held_rules_json) "
        "VALUES(?,?,?,'pending',?,?,?)",
        (aid, action_id, fp, now, now + config.APPROVAL_TTL_S, json.dumps(held_rules)))
    db.conn().commit()
    audit.record("approval_requested", {"approval": aid, "action": action_id, "tool": tool,
                                        "fingerprint": fp, "reasons": reasons},
                 run_id=sess["run_id"], session_id=sess["id"])
    return {"id": aid, "fingerprint": fp, "expires_at": now + config.APPROVAL_TTL_S}


def _review_schema():
    cols = {row['name'] for row in db.conn().execute('PRAGMA table_info(approvals)')}
    for name, kind in (('viewed_at', 'REAL'), ('viewed_by', 'TEXT'), ('reason', 'TEXT')):
        if name not in cols:
            db.conn().execute(f'ALTER TABLE approvals ADD COLUMN {name} {kind}')
    db.conn().commit()


@gateway._serialized
@audit.publication_lock()
def mark_view(approval_id, user):
    _review_schema()
    if user['role'] not in ('admin', 'approver'):
        return {'ok': False, 'error': 'review role required'}
    c = db.conn()
    row = c.execute("SELECT ap.*, a.session_id, s.run_id FROM approvals ap "
                    "JOIN actions a ON a.id=ap.action_id "
                    "JOIN agent_sessions s ON s.id=a.session_id WHERE ap.id=?",
                    (approval_id,)).fetchone()
    if row is None:
        return {'ok': False, 'error': 'unknown approval'}
    if row['status'] != 'pending' or row['viewed_at'] is not None:
        return {'ok': True}
    now = time.time()
    try:
        cur = c.execute("UPDATE approvals SET viewed_at=?, viewed_by=? WHERE id=? "
                        "AND status='pending' AND viewed_at IS NULL",
                        (now, user['username'], approval_id))
        if cur.rowcount != 1:
            c.rollback()
            return {'ok': True}
        recorded = audit.record_decision('approval_screen_viewed',
                                {'approval': approval_id, 'by': user['username']},
                                trusted_ts=now, run_id=row['run_id'],
                                session_id=row['session_id'])
        if recorded['checkpoint_ok'] is not True:
            return {'ok': False, 'error': 'view saved but audit checkpoint unavailable'}
    except BaseException:
        c.rollback()
        raise
    return {'ok': True}


def review_metrics():
    _review_schema()
    rows = [dict(row) for row in db.conn().execute('SELECT * FROM approvals')]
    counts = {'approve': 0, 'reject': 0, 'change': 0}
    timings = []
    decisions = {}
    for event in db.conn().execute("SELECT ts, detail_json FROM audit WHERE event='approval_decided' ORDER BY id"):
        detail = evidence.dec_json(event['detail_json'])
        aid = detail.get('approval')
        if aid in decisions:
            raise ValueError('Conflicting approval decision history')
        decisions[aid] = (event['ts'], detail)
    for row in rows:
        historical = decisions.get(row['id'])
        if historical:
            end, detail = historical
            key = detail['decision']
            start = detail.get('viewed_at')
        else:
            # Earlier databases have no canonical review events; do not invent them.
            key = 'approve' if row['status'] in ('claimed', 'approved', 'executed') or (row['status'] == 'void' and row['claimed_at'] is not None) else 'reject' if row['status'] == 'denied' else 'change' if row['status'] == 'changed' else None
            end = row['decided_at']
            start = row['viewed_at'] if row['viewed_by'] == row['decided_by'] else None
        if key:
            counts[key] += 1
            if start is not None and end is not None and start <= end:
                timings.append(end - start)
    return {'counts': counts, 'review_seconds': timings,
            'missing_view_count': sum(counts.values()) - len(timings)}


def get(approval_id: str):
    _review_schema()
    row = db.conn().execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result['reason'] = evidence.dec(result['reason'])
    return result


@gateway._serialized
@audit.publication_lock()
def decide(approval_id: str, user: dict, decision: str, freeze: bool = False, reason=None) -> dict:
    """decision: approve | deny. The task giver cannot approve their own task."""
    ap = get(approval_id)
    if ap is None:
        return {"ok": False, "error": "unknown approval"}
    if ap["status"] != "pending":
        return {"ok": False, "error": f"approval already {ap['status']}"}
    if time.time() > ap["expires_at"]:
        db.conn().execute("UPDATE approvals SET status='expired' WHERE id=?", (approval_id,))
        db.conn().commit()
        return {"ok": False, "error": "approval expired"}
    action = db.conn().execute("SELECT * FROM actions WHERE id=?", (ap["action_id"],)).fetchone()
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE id=?", (action["session_id"],)).fetchone()
    if user["role"] not in ("admin", "approver"):
        return {"ok": False, "error": "your role cannot approve"}
    if user["username"] == sess["created_by"]:
        return {"ok": False, "error": "the person who set the task cannot approve it"}
    if decision not in ('approve', 'deny', 'change'):
        return {'ok': False, 'error': 'unknown decision'}
    high_risk = action['tool'] in (
        'send_email', 'order_supplier', 'issue_refund', 'pay_supplier', 'delete_file')
    if reason is not None and (not isinstance(reason, str) or len(reason) > 500):
        return {'ok': False, 'error': 'reason must be short text'}
    review_text = reason
    if reason and reason.startswith((evidence.PREFIX, evidence.LEGACY_PREFIX)):
        try:
            review_text = evidence.dec(reason)
        except evidence.EvidenceKeyError:
            # Invalid envelopes are literal reviewer text, not stored ciphertext.
            pass
    visible = isinstance(review_text, str) and any(
        not char.isspace() and not unicodedata.category(char).startswith('C')
        for char in review_text)
    if decision == 'change' and not visible:
        return {'ok': False, 'error': 'describe the requested change'}
    if decision == 'approve' and high_risk and not visible:
        return {'ok': False, 'error': 'type one short reason before approving'}
    reason = reason.strip() if reason is not None else None

    if decision == 'approve':
        # Preserve the current-world check before persisting any human reason.
        w = gateway.get_world(sess['run_id'])
        current_fp = fingerprint(sess, action['tool'], evidence.dec_json(action['args_json']), w)
        if current_fp != ap['fingerprint']:
            db.conn().execute("UPDATE approvals SET status='void' WHERE id=?", (approval_id,))
            db.conn().commit()
            audit.record('approval_void', {'approval': approval_id, 'reason': 'fingerprint changed'},
                         session_id=sess['id'])
            return {'ok': False, 'error': 'the action changed since it was held; approval void'}

    c = db.conn()
    status = {'approve': 'claimed', 'deny': 'denied', 'change': 'changed'}[decision]
    now = time.time()
    viewed_at = ap['viewed_at'] if ap['viewed_by'] == user['username'] else None
    try:
        cur = c.execute(
            "UPDATE approvals SET status=?, decided_by=?, decided_at=?, claimed_at=?, reason=? "
            "WHERE id=? AND status='pending'",
            (status, user['username'], now, now if decision == 'approve' else None,
             evidence.enc_plaintext(reason), approval_id))
        if cur.rowcount != 1:
            c.rollback()
            return {'ok': False, 'error': 'approval already decided'}
        if decision != 'approve':
            c.execute('UPDATE actions SET status=? WHERE id=?', (status, ap['action_id']))
        if decision == 'deny' and freeze:
            c.execute('UPDATE agent_sessions SET frozen=1, freeze_reason=? WHERE id=?',
                      ('denied and frozen by ' + user['username'], sess['id']))

        # Commit local writes and the event together; checkpoint faults after
        # commit retain history and must never release the action.
        recorded = audit.record_decision('approval_decided',
                                {'approval': approval_id, 'by': user['username'],
                                 'decision': 'reject' if decision == 'deny' else decision,
                                 'reason': reason, 'high_risk': high_risk,
                                 'viewed_at': viewed_at},
                                 trusted_ts=now, run_id=sess['run_id'], session_id=sess['id'])
        if recorded['checkpoint_ok'] is not True:
            return {'ok': False, 'error': 'decision saved but audit checkpoint unavailable; no release'}
    except BaseException:
        c.rollback()
        raise
    if decision == 'change':
        audit.record('approval_changed', {'approval': approval_id, 'by': user['username']},
                     run_id=sess['run_id'], session_id=sess['id'])
        return {'ok': True, 'status': 'changed'}
    if decision == 'deny':
        if freeze:
            gateway.freeze_session(sess['id'], 'denied and frozen by ' + user['username'])
        audit.record('approval_denied', {'approval': approval_id, 'by': user['username'],
                                         'freeze': freeze}, session_id=sess['id'])
        return {'ok': True, 'status': 'denied'}
    result = gateway.execute_approved(ap["action_id"], user["username"])
    if not result["ok"]:
        if result.get('uncertain'):
            return result
        db.conn().execute("UPDATE approvals SET status='void' WHERE id=?", (approval_id,))
        db.conn().execute("UPDATE actions SET status='blocked' WHERE id=?", (ap["action_id"],))
        db.conn().commit()
        return result
    db.conn().execute("UPDATE actions SET status='executed' WHERE id=?", (ap["action_id"],))
    db.conn().commit()
    return {"ok": True, "status": "executed", "result": result["result"]}


def queue() -> list:
    rows = db.conn().execute(
        "SELECT ap.*, a.tool, a.args_json, a.reasons_json, s.task_text, s.created_by, s.run_id "
        "FROM approvals ap JOIN actions a ON ap.action_id=a.id "
        "JOIN agent_sessions s ON a.session_id=s.id "
        "WHERE ap.status='pending' ORDER BY ap.requested_at").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["expired"] = time.time() > r["expires_at"]
        out.append(d)
    return out