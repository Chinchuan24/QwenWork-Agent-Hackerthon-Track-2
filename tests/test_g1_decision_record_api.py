"""Proposed contract for docs/handoff/section-2.md:22-25 (tests only).

audit.record_decision(event, detail, *, trusted_ts, run_id=None, session_id=None)
consumes the current db.conn() transaction: append encrypted event with the
explicit server-owned timestamp, atomically commit local decision/action writes
and event, then checkpoint. Return {event_id: int, checkpoint_ok: bool}.
checkpoint() explicitly returns True only on durable success; False/None refuses.
Precommit errors roll back and propagate. Postcommit exceptions propagate but
retain history. approvals.decide uses the same trusted timestamp for projections
and event and releases only on checkpoint_ok is True. Terminal retries reject,
never overwrite or release. Keep approval_changed/approval_denied compatibility.
No callback API, new retry API, trigger bypass, ciphertext rewrite or anchor reset.
Boundary interruption uses KeyboardInterrupt, not a real process kill. No claim
of universal rollback resistance or atomic external effects. API assertions occur
AFTER valid real-held-request fixtures, distinguishing missing-API RED from setup.
"""
import hashlib
import sqlite3

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, audit, config, db, evidence, gateway
from test_approvals import held_refund, user
from test_r3_signer import isolated_failure_stream


@pytest.fixture
def decision_case(isolated_failure_stream):
    from aegis import auth
    auth.ensure_demo_users()
    rid, session, held = held_refund()
    aid = held['approval_id']
    assert approvals.mark_view(aid, user('ops'))['ok']
    row = approvals.get(aid)
    assert row['status'] == 'pending' and row['reason'] is None
    assert row['viewed_by'] == 'ops'
    action = db.conn().execute('SELECT status FROM actions WHERE id=?',
                               (held['action_id'],)).fetchone()
    assert action['status'] == 'held'
    assert gateway.get_world(rid).refunds == []
    assert not db.conn().in_transaction
    yield rid, session, held
    db.conn().rollback()


@pytest.fixture(autouse=True)
def publication_before_local_writes(decision_case):
    # The supported transaction contract acquires publication before writes.
    with audit.publication_lock():
        yield


def recording_api():
    api = getattr(audit, 'record_decision', None)
    assert callable(api), 'Intentional RED: missing audit.record_decision API'
    return api


@pytest.mark.parametrize('checkpoint_result', [True, False, None])
def test_atomic_commit_precedes_explicit_checkpoint(decision_case, monkeypatch,
                                                   checkpoint_result):
    rid, session, held = decision_case
    api = recording_api()
    c = db.conn()
    ts = approvals.get(held['approval_id'])['viewed_at'] + 3.25
    detail = {'approval': held['approval_id'], 'decision': 'reject',
              'by': 'ops', 'reason': 'private-api-reason', 'high_risk': True,
              'viewed_at': ts - 3.25}
    c.execute("UPDATE approvals SET status='denied', decided_at=?, reason=? WHERE id=?",
              (ts, evidence.enc(detail['reason']), held['approval_id']))
    c.execute("UPDATE actions SET status='denied' WHERE id=?", (held['action_id'],))
    observed = []

    def checkpoint():
        assert not c.in_transaction
        with sqlite3.connect(str(config.DB_PATH)) as reader:
            assert reader.execute('SELECT status, decided_at FROM approvals WHERE id=?',
                                  (held['approval_id'],)).fetchone() == ('denied', ts)
            assert reader.execute('SELECT status FROM actions WHERE id=?',
                                  (held['action_id'],)).fetchone() == ('denied',)
            assert (ts,) in reader.execute(
                "SELECT ts FROM audit WHERE event='approval_decided'").fetchall()
        observed.append(True)
        return checkpoint_result

    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    result = api('approval_decided', detail, trusted_ts=ts,
                 run_id=rid, session_id=session['session_id'])
    assert observed == [True]
    assert type(result['event_id']) is int
    assert result['checkpoint_ok'] is (checkpoint_result is True)
    row = c.execute('SELECT * FROM audit WHERE id=?', (result['event_id'],)).fetchone()
    assert row['ts'] == ts and row['run_id'] == rid
    assert row['session_id'] == session['session_id']
    assert detail['reason'] not in row['detail_json']
    assert evidence.dec_json(row['detail_json']) == detail
    payload = audit.canonical(dict(ts=ts, run_id=rid,
                                  session_id=session['session_id'],
                                  event='approval_decided', detail=detail))
    assert row['hash'] == hashlib.sha256((row['prev_hash'] + payload).encode()).hexdigest()
    for sql in ('UPDATE audit SET ts=0 WHERE id=?', 'DELETE FROM audit WHERE id=?'):
        with pytest.raises(sqlite3.IntegrityError, match='append-only'):
            c.execute(sql, (row['id'],))
        c.rollback()


def test_insert_refusal_rolls_back_local_writes(decision_case, monkeypatch):
    _, _, held = decision_case
    api = recording_api()
    c = db.conn()
    before = approvals.get(held['approval_id'])
    history = audit.export_records()
    checkpoints = []
    monkeypatch.setattr(audit, 'checkpoint', lambda: checkpoints.append(True))
    c.execute("CREATE TEMP TRIGGER g1_api_refuse BEFORE INSERT ON audit "
              "BEGIN SELECT RAISE(ABORT, 'api insert refused'); END")
    try:
        c.execute("UPDATE approvals SET status='denied', reason=? WHERE id=?",
                  (evidence.enc('private'), held['approval_id']))
        c.execute("UPDATE actions SET status='denied' WHERE id=?", (held['action_id'],))
        with pytest.raises(sqlite3.IntegrityError, match='api insert refused'):
            api('approval_decided', {'approval': held['approval_id']}, trusted_ts=123.5)
        assert not c.in_transaction
        assert approvals.get(held['approval_id']) == before
        assert c.execute('SELECT status FROM actions WHERE id=?',
                         (held['action_id'],)).fetchone()['status'] == 'held'
        assert audit.export_records() == history and checkpoints == []
    finally:
        c.rollback()
        c.execute('DROP TRIGGER g1_api_refuse')
        c.commit()


def test_precommit_interruption_rolls_back_caller_writes(decision_case, monkeypatch):
    rid, _, held = decision_case
    aid = held['approval_id']
    before = approvals.get(aid)
    history = audit.export_records()

    def interrupt(*args, **kwargs):
        assert db.conn().in_transaction
        raise KeyboardInterrupt('injected before recording')

    monkeypatch.setattr(audit, 'record_decision', interrupt)
    with pytest.raises(KeyboardInterrupt, match='before recording'):
        approvals.decide(aid, user('ops'), 'approve', reason='checked interruption')
    assert not db.conn().in_transaction
    assert approvals.get(aid) == before
    assert audit.export_records() == history
    assert gateway.get_world(rid).refunds == []


@pytest.mark.parametrize('failure', [False, None, OSError, KeyboardInterrupt])
def test_postcommit_failure_retains_history_and_refuses_release(
        decision_case, monkeypatch, failure):
    rid, _, held = decision_case
    recording_api()
    aid = held['approval_id']
    ts = approvals.get(aid)['viewed_at'] + 2
    monkeypatch.setattr(approvals.time, 'time', lambda: ts)
    releases = []
    monkeypatch.setattr(gateway, 'execute_approved', lambda *args: releases.append(args))

    def checkpoint():
        assert not db.conn().in_transaction
        assert approvals.get(aid)['decided_at'] == ts
        if failure in (OSError, KeyboardInterrupt):
            raise failure('injected postcommit interruption')
        return failure

    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    if failure in (OSError, KeyboardInterrupt):
        with pytest.raises(failure, match='postcommit interruption'):
            approvals.decide(aid, user('ops'), 'approve', reason='private retained reason')
    else:
        assert not approvals.decide(aid, user('ops'), 'approve',
                                    reason='private retained reason')['ok']
    assert not db.conn().in_transaction
    events = [r for r in audit.export_records() if r['event'] == 'approval_decided'
              and evidence.dec_json(r['detail_json'])['approval'] == aid]
    assert len(events) == 1 and events[0]['ts'] == ts
    assert approvals.get(aid)['claimed_at'] == ts
    assert approvals.get(aid)['reason'] == 'private retained reason'
    history = audit.export_records()
    monkeypatch.setattr(audit, 'checkpoint', lambda: True)
    assert not approvals.decide(aid, user('ops'), 'approve', reason='rewrite')['ok']
    assert audit.export_records() == history
    assert releases == [] and gateway.get_world(rid).refunds == []


@pytest.mark.parametrize('decision,key,compat,status', [
    ('approve', 'approve', None, 'executed'),
    ('deny', 'reject', 'approval_denied', 'denied'),
    ('change', 'change', 'approval_changed', 'changed'),
])
def test_decide_uses_api_timestamp_and_preserves_compatibility(
        decision_case, monkeypatch, decision, key, compat, status):
    _, _, held = decision_case
    original = recording_api()
    calls = []
    releases = []

    def record(*args, **kwargs):
        assert 'trusted_ts' in kwargs
        result = original(*args, **kwargs)
        calls.append((args, kwargs, result))
        return result

    def release(*args):
        assert len(calls) == 1 and calls[0][2]['checkpoint_ok'] is True
        row = approvals.get(held['approval_id'])
        assert row['decided_at'] == row['claimed_at'] == calls[0][1]['trusted_ts']
        releases.append(args)
        return {'ok': True, 'result': {}}

    monkeypatch.setattr(audit, 'record_decision', record)
    monkeypatch.setattr(gateway, 'execute_approved', release)
    result = approvals.decide(held['approval_id'], user('ops'), decision, reason='checked')
    assert result['ok'] and result['status'] == status
    assert len(calls) == 1
    assert calls[0][0][0] == 'approval_decided'
    assert calls[0][0][1]['decision'] == key
    assert approvals.get(held['approval_id'])['decided_at'] == calls[0][1]['trusted_ts']
    assert len(releases) == int(decision == 'approve')
    if compat:
        assert any(r['event'] == compat
                   and evidence.dec_json(r['detail_json'])['approval'] == held['approval_id']
                   for r in audit.export_records())
