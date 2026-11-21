"""Stored approval review must describe real held-refund decisions."""
import time

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway
from test_approvals import held_refund, user


def test_mark_view_persists_timestamp_for_real_held_refund(monkeypatch):
    _, _, held = held_refund()
    approval_id = held['approval_id']
    viewed_at = time.time()
    monkeypatch.setattr(approvals.time, 'time', lambda: viewed_at)

    approvals.mark_view(approval_id, user('ops'))

    stored = dict(approvals.get(approval_id))
    assert stored['viewed_at'] == viewed_at
    assert stored['status'] == 'pending'
    assert stored['decided_at'] is None


@pytest.mark.parametrize('reason', ['', '   ', '\t\n'])
def test_high_risk_refund_approval_requires_nonblank_reason(reason):
    rid, _, held = held_refund()

    result = approvals.decide(held['approval_id'], user('ops'), 'approve', reason=reason)

    assert not result['ok']
    assert 'reason' in result['error'].lower()
    stored = dict(approvals.get(held['approval_id']))
    assert stored['status'] == 'pending'
    assert stored['decided_at'] is None
    assert gateway.get_world(rid).refunds == []


def test_immediate_high_risk_approval_saves_reason_without_timing_gate(monkeypatch):
    rid, _, held = held_refund()
    now = time.time()
    monkeypatch.setattr(approvals.time, 'time', lambda: now)
    approvals.mark_view(held['approval_id'], user('ops'))
    reason = 'Verified the requested refund against the Cirrus invoice.'

    result = approvals.decide(held['approval_id'], user('ops'), 'approve', reason=reason)

    assert result['ok'] and result['status'] == 'executed'
    stored = dict(approvals.get(held['approval_id']))
    assert stored['reason'] == reason
    assert stored['decided_by'] == 'ops'
    assert stored['decided_at'] == stored['viewed_at'] == now
    assert len(gateway.get_world(rid).refunds) == 1


def test_review_metrics_counts_match_stored_approve_and_deny_records():
    before = approvals.review_metrics()
    approved_run, _, approved = held_refund()
    denied_run, _, denied = held_refund()
    _, _, pending = held_refund()
    reason = 'Verified invoice and customer request.'
    approvals.mark_view(approved['approval_id'], user('ops'))
    assert approvals.decide(approved['approval_id'], user('ops'), 'approve',
                            reason=reason)['ok']
    assert approvals.decide(denied['approval_id'], user('ops'), 'deny',
                            reason='Customer withdrew the request.')['ok']

    metrics = approvals.review_metrics()
    assert metrics['counts'] == dict(
        approve=before['counts']['approve'] + 1,
        reject=before['counts']['reject'] + 1,
        change=before['counts']['change'])
    rows = db.conn().execute('SELECT status, claimed_at FROM approvals').fetchall()
    assert metrics['counts']['approve'] == sum(
        row['status'] in ('claimed', 'approved', 'executed') or
        (row['status'] == 'void' and row['claimed_at'] is not None) for row in rows)
    assert metrics['counts']['reject'] == sum(row['status'] == 'denied' for row in rows)
    assert approvals.get(pending['approval_id'])['status'] == 'pending'
    assert len(gateway.get_world(approved_run).refunds) == 1
    assert gateway.get_world(denied_run).refunds == []
    assert approvals.review_metrics() == metrics
