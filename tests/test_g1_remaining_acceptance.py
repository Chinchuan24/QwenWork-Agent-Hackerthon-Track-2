"""Remaining G1 contracts: immutable review facts and briefing integration."""
import json
import time

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approval_review, approvals, audit, briefing, db, gateway
from test_approvals import held_refund, user


def test_first_review_view_has_immutable_history(monkeypatch):
    _, session, held = held_refund()
    viewed_at = time.time()
    monkeypatch.setattr(approvals.time, 'time', lambda: viewed_at)
    assert approvals.mark_view(held['approval_id'], user('ops'))['ok']
    assert approvals.mark_view(held['approval_id'], user('ops'))['ok']

    events = [row for row in audit.export_records()
              if row['event'] == 'approval_screen_viewed'
              and json.loads(row['detail_json']).get('approval') == held['approval_id']]
    assert len(events) == 1, 'First stored view must emit exactly one immutable event'
    assert events[0]['session_id'] == session['session_id']
    assert events[0]['ts'] == viewed_at
    assert json.loads(events[0]['detail_json'])['by'] == 'ops'


@pytest.mark.parametrize('decision,expected', [
    ('approve', 'approve'), ('deny', 'reject'), ('change', 'change'),
])
def test_review_can_be_rebuilt_from_immutable_decision_history(decision, expected):
    rid, session, held = held_refund()
    reason = 'Checked the customer request; private reference 918273.'
    assert approvals.mark_view(held['approval_id'], user('ops'))['ok']
    assert approvals.decide(held['approval_id'], user('ops'), decision,
                            reason=reason)['ok']
    stored = approvals.get(held['approval_id'])
    history = audit.export_records()
    events = [row for row in history if row['event'] == 'approval_decided'
              and json.loads(row['detail_json']).get('approval') == held['approval_id']]
    assert len(events) == 1, 'Successful review must emit immutable decision facts'
    event = events[0]
    detail = json.loads(event['detail_json'])
    assert event['session_id'] == session['session_id']
    assert event['run_id'] == rid
    assert event['ts'] == stored['decided_at']
    assert detail['decision'] == expected
    assert detail['by'] == 'ops'
    assert detail['reason'] == reason
    assert detail['high_risk'] is True
    assert detail['viewed_at'] == stored['viewed_at']
    encrypted = db.conn().execute('SELECT detail_json FROM audit WHERE id=?',
                                  (event['id'],)).fetchone()['detail_json']
    assert reason not in encrypted

    assert not approvals.decide(held['approval_id'], user('ops'), decision,
                                reason='Replay must not replace history')['ok']
    assert audit.export_records() == history
    review = approval_review.build_approval_review([], events)
    assert review['counts'] == dict(approve=int(expected == 'approve'),
                                  reject=int(expected == 'reject'),
                                  change=int(expected == 'change'))
    assert review['decision_seconds'] == [stored['decided_at'] - stored['viewed_at']]
    assert review['high_risk_reason_coverage'] == 1
    assert len(gateway.get_world(rid).refunds) == int(decision == 'approve')


def test_changed_work_is_not_pending_in_current_or_later_briefing():
    rid, session, held = held_refund()
    reason = 'Private customer reference 918273: correct the amount first.'
    assert approvals.decide(held['approval_id'], user('ops'), 'change',
                            reason=reason)['ok']
    records = [row for row in audit.export_records()
               if row['session_id'] == session['session_id']]
    changed = next(row for row in records if row['event'] == 'approval_changed')
    end = max(row['ts'] for row in records) + 1

    for start, stop in ((0, end), (end, end + 1)):
        result = briefing.build_briefing(records, start=start, end=stop,
                                        seen_approval_ids=[held['approval_id']])
        assert result['counts']['needs_decision'] == 0
        assert result['counts']['still_waiting'] == 0, 'Changed work is terminal'
        assert result['counts']['went_fine'] == 0
        assert reason not in json.dumps(result)
        if start == 0:
            assert changed['id'] in result['headline']['proof_ids']
    assert gateway.get_world(rid).refunds == []
