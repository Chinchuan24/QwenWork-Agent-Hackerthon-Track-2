"""Scoped G1 persistence regressions using real held requests."""
import json
import sqlite3

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from aegis import approvals, audit, db, gateway
from test_approvals import held_refund, user
from test_r3_signer import isolated_failure_stream


@pytest.mark.parametrize('reason', [None, '', '   '])
def test_all_callers_require_high_risk_reason(reason):
    rid, _, held = held_refund()
    assert not approvals.decide(held['approval_id'], user('ops'), 'approve', reason=reason)['ok']
    assert approvals.get(held['approval_id'])['status'] == 'pending'
    assert gateway.get_world(rid).refunds == []


def test_invalid_fingerprint_does_not_save_reason():
    _, _, held = held_refund()
    db.conn().execute('UPDATE approvals SET fingerprint=? WHERE id=?', ('changed', held['approval_id']))
    db.conn().commit()
    assert not approvals.decide(held['approval_id'], user('ops'), 'approve', reason='checked')['ok']
    assert approvals.get(held['approval_id'])['reason'] is None


@pytest.mark.parametrize('decision', ['deny', 'change'])
def test_action_write_failure_rolls_back_decision(decision):
    _, _, held = held_refund()
    c = db.conn()
    c.execute("CREATE TEMP TRIGGER g1_fail_action BEFORE UPDATE ON actions BEGIN SELECT RAISE(ABORT, 'injected'); END")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            approvals.decide(held['approval_id'], user('ops'), decision, reason='checked')
        assert not c.in_transaction
        row = approvals.get(held['approval_id'])
        assert (row['status'], row['reason'], row['decided_by']) == ('pending', None, None)
    finally:
        c.rollback()
        c.execute('DROP TRIGGER g1_fail_action')
        c.commit()


@pytest.mark.parametrize('operation', ['view', 'deny', 'change', 'approve'])
def test_audit_insert_refusal_rolls_back_local_writes(monkeypatch, operation):
    _, _, held = held_refund()
    before = approvals.get(held['approval_id'])
    history = audit.export_records()
    action_before = dict(db.conn().execute('SELECT * FROM actions WHERE id=?',
                                         (held['action_id'],)).fetchone())
    def refuse(*args, **kwargs):
        raise sqlite3.OperationalError('injected audit refusal')
    monkeypatch.setattr(audit, 'record_decision', refuse)
    with pytest.raises(sqlite3.OperationalError):
        if operation == 'view':
            approvals.mark_view(held['approval_id'], user('ops'))
        else:
            approvals.decide(held['approval_id'], user('ops'), operation, reason='checked')
    assert not db.conn().in_transaction
    assert approvals.get(held['approval_id']) == before
    assert dict(db.conn().execute('SELECT * FROM actions WHERE id=?',
                                  (held['action_id'],)).fetchone()) == action_before
    assert audit.export_records() == history


def test_failed_release_keeps_canonical_decision(monkeypatch):
    _, _, held = held_refund()
    before = approvals.review_metrics()['counts']['approve']
    monkeypatch.setattr(gateway, 'execute_approved', lambda *a: {'ok': False, 'error': 'held'})
    assert not approvals.decide(held['approval_id'], user('ops'), 'approve', reason='checked')['ok']
    events = [r for r in audit.export_records() if r['event'] == 'approval_decided'
              and json.loads(r['detail_json'])['approval'] == held['approval_id']]
    assert len(events) == 1
    assert json.loads(events[0]['detail_json'])['decision'] == 'approve'
    assert events[0]['ts'] == approvals.get(held['approval_id'])['decided_at']
    assert approvals.review_metrics()['counts']['approve'] == before + 1
    with pytest.raises(sqlite3.IntegrityError):
        db.conn().execute('DELETE FROM audit WHERE id=?', (events[0]['id'],))
    db.conn().rollback()


def test_other_reviewer_view_is_not_decision_timing():
    _, _, held = held_refund()
    assert approvals.mark_view(held['approval_id'], dict(username='other-reviewer', role='approver'))['ok']
    assert approvals.decide(held['approval_id'], user('ops'), 'deny', reason='checked')['ok']
    event = next(r for r in audit.export_records() if r['event'] == 'approval_decided'
                 and json.loads(r['detail_json'])['approval'] == held['approval_id'])
    assert json.loads(event['detail_json'])['viewed_at'] is None


@pytest.mark.parametrize('decision,key', [('approve', 'approve'), ('deny', 'reject'), ('change', 'change')])
def test_post_commit_audit_exception_preserves_history_without_release(
        monkeypatch, isolated_failure_stream, decision, key):
    from aegis import auth
    auth.ensure_demo_users()
    rid, _, held = held_refund()
    aid = held['approval_id']
    approvals.mark_view(aid, user('ops'))
    before = approvals.review_metrics()['counts'][key]
    releases = []
    monkeypatch.setattr(gateway, 'execute_approved', lambda *args: releases.append(args))
    def commit_then_refuse():
        assert not db.conn().in_transaction
        assert approvals.get(aid)['status'] == {
            'approve': 'claimed', 'deny': 'denied', 'change': 'changed'}[decision]
        raise OSError('injected after audit commit')
    monkeypatch.setattr(audit, 'checkpoint', commit_then_refuse)
    with pytest.raises(OSError, match='after audit commit'):
        approvals.decide(aid, user('ops'), decision, reason='private-post-commit-reason')
    assert not db.conn().in_transaction
    history = audit.export_records()
    events = [r for r in history if r['event'] == 'approval_decided'
              and json.loads(r['detail_json'])['approval'] == aid]
    assert len(events) == 1
    assert events[0]['ts'] == approvals.get(aid)['decided_at']
    assert releases == []
    assert json.loads(events[0]['detail_json'])['decision'] == key
    assert approvals.review_metrics()['counts'][key] == before + 1
    assert not approvals.decide(aid, user('ops'), decision, reason='rewrite')['ok']
    assert audit.export_records() == history
    assert approvals.get(aid)['reason'] == 'private-post-commit-reason'
    assert gateway.get_world(rid).refunds == []


def test_authenticated_home_real_decisions_counts_privacy_and_terminal_removal():
    import re
    from html import unescape
    from fastapi.testclient import TestClient
    from aegis import app as web
    from test_owner_home_wiring import signed_in

    held_ids = []
    private_reason = 'private-home-g1-review-reference-918273'
    # Ten real, fast, matched reviews meet the existing warning threshold.
    for decision in ['approve'] * 9 + ['change']:
        _, _, held = held_refund()
        held_ids.append(held['approval_id'])
        assert approvals.mark_view(held['approval_id'], user('ops'))['ok']
        assert approvals.decide(held['approval_id'], user('ops'), decision,
                                reason=private_reason)['ok']
    with TestClient(web.app) as client:
        signed_in(client)
        response = client.get('/', follow_redirects=False)
    assert response.status_code == 200
    text = ' '.join(unescape(re.sub('<[^>]+>', ' ', response.text)).split())
    # Other focused tests may contribute decisions today; derive exact totals.
    from datetime import datetime
    from zoneinfo import ZoneInfo
    start = datetime.now(ZoneInfo('Asia/Singapore')).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    counts = dict(approve=0, reject=0, change=0)
    for row in audit.export_records():
        if row['event'] == 'approval_decided' and start <= row['ts'] < start + 86400:
            counts[json.loads(row['detail_json'])['decision']] += 1
    assert f"{counts['approve']} approvals, {counts['reject']} rejections, {counts['change']} changes" in text
    assert private_reason not in response.text
    assert 'enc:v2:' not in response.text
    for aid in held_ids:
        assert f'href="/approvals/{aid}"' not in response.text
