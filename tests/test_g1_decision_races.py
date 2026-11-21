"""Concurrent decisions are single-use; failed release retains human review."""
import threading
import time

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway
from test_approvals import held_refund, user


@pytest.mark.parametrize('decisions', [('deny', 'change'), ('approve', 'deny')],
                         ids=['deny-change', 'approve-deny'])
def test_parallel_decisions_keep_only_winner_state_and_reason(monkeypatch, decisions):
    rid, _, held = held_refund()
    reviewer = user('ops')
    approval_id = held['approval_id']
    approvals.mark_view(approval_id, reviewer)
    before = approvals.review_metrics()['counts']
    barrier = threading.Barrier(2)
    results = [None, None]
    errors = [None, None]
    connections = [None, None]
    reasons = ['Verified invoice; first reviewer.', 'Correct amount; second reviewer.']
    original_get = approvals.get

    def delayed_get(aid):
        record = original_get(aid)
        # Widen stale reads without waiting inside the pipeline lock.
        time.sleep(0.05)
        return record

    monkeypatch.setattr(approvals, 'get', delayed_get)

    def worker(index):
        connection = None
        try:
            connection = db.conn()
            connections[index] = connection
            barrier.wait(timeout=5)
            results[index] = approvals.decide(
                approval_id, reviewer, decisions[index], reason=reasons[index])
        except Exception as exc:
            errors[index] = exc
        finally:
            if connection is not None:
                connection.close()
                del db._local.conn

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(2)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 15
    for thread in threads:
        thread.join(timeout=max(0, deadline - time.monotonic()))
    assert not any(thread.is_alive() for thread in threads), 'decision workers hung'
    assert errors == [None, None], errors
    assert connections[0] is not connections[1]
    assert all(connection is not db.conn() for connection in connections)
    winners = [i for i, result in enumerate(results) if result['ok']]
    assert len(winners) == 1, results
    winner = winners[0]
    assert 'already' in results[1 - winner]['error']
    status = {'approve': 'claimed', 'deny': 'denied', 'change': 'changed'}[decisions[winner]]
    action_status = {'approve': 'executed', 'deny': 'denied', 'change': 'changed'}[decisions[winner]]
    stored = original_get(approval_id)
    assert stored['status'] == status
    assert stored['reason'] == reasons[winner]
    assert stored['decided_by'] == reviewer['username']
    assert stored['decided_at'] is not None
    assert (stored['claimed_at'] is not None) == (decisions[winner] == 'approve')
    action = db.conn().execute('SELECT status, executed_at FROM actions WHERE id=?',
                               (held['action_id'],)).fetchone()
    assert action['status'] == action_status
    assert (action['executed_at'] is not None) == (decisions[winner] == 'approve')
    assert len(gateway.get_world(rid).refunds) == int(decisions[winner] == 'approve')
    expected = dict(before)
    expected[{'approve': 'approve', 'deny': 'reject', 'change': 'change'}[decisions[winner]]] += 1
    assert approvals.review_metrics()['counts'] == expected
    assert approval_id not in {row['id'] for row in approvals.queue()}


def test_failed_release_preserves_human_approve_count():
    rid, session, held = held_refund()
    reviewer = user('ops')
    approvals.mark_view(held['approval_id'], reviewer)
    before = approvals.review_metrics()['counts']
    gateway.freeze_session(session['session_id'], 'Release must fail closed.')
    reason = 'Verified invoice and customer request before release.'

    result = approvals.decide(held['approval_id'], reviewer, 'approve', reason=reason)

    assert result['ok'] is False
    stored = approvals.get(held['approval_id'])
    assert stored['status'] == 'void'
    assert stored['reason'] == reason
    assert stored['decided_by'] == reviewer['username']
    assert stored['decided_at'] is not None
    assert stored['claimed_at'] is not None
    action = db.conn().execute('SELECT status, executed_at FROM actions WHERE id=?',
                               (held['action_id'],)).fetchone()
    assert action['status'] == 'blocked'
    assert action['executed_at'] is None
    assert gateway.get_world(rid).refunds == []
    assert approvals.review_metrics()['counts'] == dict(
        before, approve=before['approve'] + 1)
