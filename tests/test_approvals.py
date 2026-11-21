"""Approvals: fingerprint-bound, one-time, expiring, no self-approval,
re-checked at execution."""
import time
import uuid
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from aegis import approvals, db, gateway
from conftest import make_session


def held_refund(task="Process the large refund Cirrus Health asked for by email (INV-3008)."):
    rid, s = make_session(task=task)
    out = gateway.handle_call(s["token"], "issue_refund",
                              {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"},
                              uuid.uuid4().hex)
    assert out["verdict"] == "hold"
    return rid, s, out


def user(name):
    return dict(db.conn().execute("SELECT * FROM users WHERE username=?", (name,)).fetchone())


def test_second_person_approves_runs_once():
    rid, s, out = held_refund()
    res = approvals.decide(out["approval_id"], user("ops"), "approve",
                           reason="Verified the customer request and invoice.")
    assert res["ok"] and res["status"] == "executed"
    w = gateway.get_world(rid)
    assert len(w.refunds) == 1
    # claiming again does nothing
    res2 = approvals.decide(out["approval_id"], user("ops"), "approve")
    assert not res2["ok"]
    assert len(w.refunds) == 1


def test_no_self_approval():
    _, _, out = held_refund()
    res = approvals.decide(out["approval_id"], user("dana"), "approve")
    assert not res["ok"] and "cannot approve" in res["error"]


def test_role_cannot_approve():
    _, _, out = held_refund()
    res = approvals.decide(out["approval_id"], user("audi"), "approve")
    assert not res["ok"]


def test_fingerprint_void_on_change():
    rid, s, out = held_refund()
    # attacker changes the arguments after the hold
    db.conn().execute("UPDATE actions SET args_json=? WHERE id=?",
                      ('{"invoice_id": "INV-3008", "amount": 99999}', out["action_id"]))
    db.conn().commit()
    res = approvals.decide(out["approval_id"], user("ops"), "approve",
                           reason="Verified the customer request and invoice.")
    assert not res["ok"] and "void" in res["error"]


def test_expiry():
    _, _, out = held_refund()
    db.conn().execute("UPDATE approvals SET expires_at=? WHERE id=?",
                      (time.time() - 1, out["approval_id"]))
    db.conn().commit()
    res = approvals.decide(out["approval_id"], user("ops"), "approve")
    assert not res["ok"] and "expired" in res["error"]


def test_deny_and_freeze():
    rid, s, out = held_refund()
    res = approvals.decide(out["approval_id"], user("ops"), "deny", freeze=True)
    assert res["ok"]
    out2 = gateway.handle_call(s["token"], "list_inbox", {}, None)
    assert out2["verdict"] == "block"


def test_hard_rule_recheck_at_execution():
    rid, s, out = held_refund()
    gateway.freeze_session(s["session_id"], "test freeze before execution")
    res = approvals.decide(out["approval_id"], user("ops"), "approve",
                           reason="Verified the customer request and invoice.")
    assert not res["ok"]
    w = gateway.get_world(rid)
    assert len(w.refunds) == 0


def test_posteffect_failure_cannot_replay(monkeypatch):
    rid, _, out = held_refund()
    db.conn().execute("UPDATE agent_sessions SET created_by=? WHERE run_id=?", ('uncertain-' + rid, rid))
    db.conn().execute("UPDATE approvals SET status='claimed', decided_by='ops' WHERE id=?",
                      (out['approval_id'],))
    db.conn().commit()
    calls = []
    def effect(*args):
        calls.append(1)
        return {'amount': 1}
    monkeypatch.setattr(gateway, '_execute', effect)
    def fail(*args, **kwargs):
        raise RuntimeError('injected post-effect failure')
    monkeypatch.setattr(gateway, '_update_totals', fail)
    result = gateway.execute_approved(out['action_id'], 'ops')
    assert not result['ok'] and result['uncertain']
    assert len(calls) == 1
    assert not gateway.execute_approved(out['action_id'], 'ops')['ok']
    assert len(calls) == 1


@pytest.mark.parametrize('legacy', [False, True])
def test_exact_request_binding(legacy, monkeypatch):
    _, s = make_session()
    key = uuid.uuid4().hex
    args = {'invoice_id': 'INV-3008', 'source_email': 'em_cirrus_refund_large'}
    first = gateway.handle_call(s['token'], 'issue_refund', args, key)
    if legacy:
        db.conn().execute('UPDATE actions SET request_digest=NULL WHERE id=?',
                          (first['action_id'],))
        db.conn().commit()
    monkeypatch.setattr(gateway, '_mask_args', lambda *a: {})
    changed = gateway.handle_call(s['token'], 'issue_refund', dict(args, amount=1), key)
    assert changed['verdict'] == 'block'
    assert changed['reasons'][0]['rule'] == 'HARD-IDEM'


def test_approved_totals_do_not_commit_independently(monkeypatch):
    rid, _, out = held_refund()
    db.conn().execute("UPDATE agent_sessions SET created_by=? WHERE run_id=?", ('uncertain-' + rid, rid))
    db.conn().commit()
    original = gateway._update_totals
    def fail(sess, tool, args, result, **kwargs):
        original(sess, tool, args, result, **kwargs)
        raise RuntimeError('completion fault')
    monkeypatch.setattr(gateway, '_update_totals', fail)
    result = approvals.decide(out['approval_id'], user('ops'), 'approve', reason='Invoice verified')
    assert not result['ok'] and result['uncertain']
    row = db.conn().execute('SELECT refund_total,frozen FROM agent_sessions WHERE run_id=?', (rid,)).fetchone()
    assert row['refund_total'] == 0 and row['frozen'] == 1
    assert db.conn().execute('SELECT status FROM actions WHERE id=?', (out['action_id'],)).fetchone()[0] == 'executing'


def test_denial_freeze_survives_checkpoint_exception(monkeypatch):
    _, s, out = held_refund()
    original = gateway.audit.record_decision
    def fail(*a, **kw):
        original(*a, **kw)
        raise RuntimeError('checkpoint fault')
    monkeypatch.setattr(gateway.audit, 'record_decision', fail)
    with pytest.raises(RuntimeError):
        approvals.decide(out['approval_id'], user('ops'), 'deny', freeze=True)
    assert db.conn().execute('SELECT frozen FROM agent_sessions WHERE id=?',
                             (s['session_id'],)).fetchone()[0] == 1
    assert approvals.get(out['approval_id'])['status'] == 'denied'


def test_uncertain_key_replay_is_not_success(monkeypatch):
    _, s = make_session()
    args = {'invoice_id': 'INV-3008', 'source_email': 'em_cirrus_refund_large'}
    key = uuid.uuid4().hex
    out = gateway.handle_call(s['token'], 'issue_refund', args, key)
    db.conn().execute("UPDATE agent_sessions SET created_by=? WHERE id=?", ('uncertain-' + s['session_id'], s['session_id']))
    db.conn().execute("UPDATE actions SET status='executing', verdict='allow' WHERE id=?", (out['action_id'],))
    db.conn().commit()
    reply = gateway.handle_call(s['token'], 'issue_refund', args, key)
    assert reply['verdict'] == 'block'
    assert 'result' not in reply
    assert reply['reasons'][0]['rule'] == 'HARD-IDEM'
