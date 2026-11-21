"""Change decisions are terminal review history, never refund execution."""
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway
from test_approvals import held_refund, user


def test_change_saves_reason_and_terminal_action_without_effect():
    rid, _, held = held_refund()
    reason = 'Confirm the refund amount with the customer first.'

    result = approvals.decide(held['approval_id'], user('ops'), 'change',
                              reason=reason)

    assert result['ok'] and result['status'] == 'changed'
    stored = approvals.get(held['approval_id'])
    assert stored['status'] == 'changed'
    assert stored['reason'] == reason
    assert stored['decided_by'] == 'ops'
    assert stored['decided_at'] is not None
    assert stored['claimed_at'] is None
    action = db.conn().execute('SELECT status FROM actions WHERE id=?',
                               (held['action_id'],)).fetchone()
    assert action['status'] == 'changed'
    assert gateway.get_world(rid).refunds == []
    assert held['approval_id'] not in {row['id'] for row in approvals.queue()}


def test_change_increments_review_metrics_once():
    _, _, held = held_refund()
    before = approvals.review_metrics()

    result = approvals.decide(held['approval_id'], user('ops'), 'change',
                              reason='Please correct the requested amount.')

    metrics = approvals.review_metrics()
    assert metrics['counts'] == dict(
        approve=before['counts']['approve'],
        reject=before['counts']['reject'],
        change=before['counts']['change'] + 1)
    assert result['ok']
    assert approvals.review_metrics() == metrics


@pytest.mark.parametrize('decision', ['change', 'approve', 'deny'])
def test_replay_cannot_replace_change_reason_or_execute(decision):
    rid, _, held = held_refund()
    approvals.decide(held['approval_id'], user('ops'), 'change',
                     reason='Ask the customer to clarify the amount.')
    before = approvals.get(held['approval_id'])
    metrics = approvals.review_metrics()

    result = approvals.decide(held['approval_id'], user('ops'), decision,
                              reason='Replacement reason from a replay.')

    assert not result['ok']
    assert approvals.get(held['approval_id']) == before
    assert before['status'] == 'changed'
    assert before['reason'] == 'Ask the customer to clarify the amount.'
    assert approvals.review_metrics() == metrics
    action = db.conn().execute('SELECT status FROM actions WHERE id=?',
                               (held['action_id'],)).fetchone()
    assert action['status'] == 'changed'
    assert gateway.get_world(rid).refunds == []


def test_unknown_decision_cannot_persist_reason():
    rid, _, held = held_refund()
    before = approvals.get(held['approval_id'])
    metrics = approvals.review_metrics()

    result = approvals.decide(held['approval_id'], user('ops'), 'unknown',
                              reason='This invalid decision must not be saved.')

    assert not result['ok'] and result['error'] == 'unknown decision'
    assert approvals.get(held['approval_id']) == before
    assert approvals.review_metrics() == metrics
    assert gateway.get_world(rid).refunds == []
