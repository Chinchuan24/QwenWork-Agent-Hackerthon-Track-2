import copy
import json

import pytest

from aegis.approval_review import build_approval_review


def record(i, decision='approve', seconds=5, **extra):
    return dict(id=str(i), decision=decision, decided_at=100,
                viewed_at=None if seconds is None else 100 - seconds, **extra)


def test_empty():
    result = build_approval_review([], [])
    assert result['counts'] == dict(approve=0, reject=0, change=0)
    assert result['decision_seconds'] == []
    assert result['high_risk_reason_coverage'] is None
    assert result['warning'] is None


def test_stored_statuses_and_unknown_views():
    rows = [dict(id='a', status='claimed', decided_at=100, requested_at=1),
            dict(id='b', status='denied', decided_at=100), record('c', 'change', 12),
            dict(id='d', status='pending'), dict(id='e', status='void', decided_at=100)]
    result = build_approval_review(rows, [])
    assert result['counts'] == dict(approve=1, reject=1, change=1)
    assert result['decision_seconds'] == [None, None, 12]


def test_events_join_latest_predecision_view_without_double_counting():
    rows = [record('a', seconds=None, decided_by='alex')]
    events = [dict(event='approval_screen_viewed', ts=t,
                   detail_json=json.dumps(dict(approval='a', by=who)))
              for t, who in [(80, 'alex'), (95, 'alex'), (99, 'other'), (101, 'alex')]]
    events.append(dict(event='approval_decided', ts=100,
                       detail=dict(approval='a', decision='approve')))
    result = build_approval_review(rows, events)
    assert result['counts']['approve'] == 1
    assert result['decision_seconds'] == [5]
    assert build_approval_review(rows, events[::-1]) == result


def test_event_only_decision():
    events = [dict(event='approval_decided', ts=100,
                   detail=dict(approval='a', decision='reject', high_risk=True, reason='Scope'))]
    result = build_approval_review([], events)
    assert result['counts']['reject'] == 1
    assert result['high_risk_reason_coverage'] == 1


@pytest.mark.parametrize('identity', [{}, {'by': None}, {'by': ''}])
@pytest.mark.parametrize('stored', [False, True])
def test_anonymous_events_do_not_supply_timing_or_warning(identity, stored):
    rows = []
    events = []
    for i in range(10):
        events.append(dict(event='approval_screen_viewed', ts=95,
                           detail=dict(approval=str(i), **identity)))
        if stored:
            reviewer = {} if not identity else {'decided_by': identity['by']}
            rows.append(record(i, seconds=None, **reviewer))
        else:
            events.append(dict(event='approval_decided', ts=100,
                               detail=dict(approval=str(i), decision='approve', **identity)))
    result = build_approval_review(rows, events)
    assert result['decision_seconds'] == [None] * 10
    assert result['counts']['approve'] == 10
    assert result['warning'] is None


def test_explicit_stored_view_does_not_require_reviewer():
    result = build_approval_review([record(i) for i in range(10)])
    assert result['decision_seconds'] == [5] * 10
    assert result['warning'] is not None


def test_reason_presence_not_ai_quality_or_private_content():
    rows = [record(1, high_risk=True, reason='<script>private</script>'),
            record(2, high_risk=True, reason='  '), record(3, high_risk=False, reason='ok')]
    result = build_approval_review(rows, [])
    assert result['high_risk_decisions'] == 2
    assert result['high_risk_with_reason'] == 1
    assert result['high_risk_reason_coverage'] == .5
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize('count,approvals,fast,warning', [
    (9, 9, 9, False), (10, 9, 9, True), (10, 8, 10, False),
    (10, 10, 8, False), (10, 10, 9, True)])
def test_warning_thresholds(count, approvals, fast, warning):
    rows = [record(i, 'approve' if i < approvals else 'reject',
                   9 if i < fast else 10) for i in range(count)]
    result = build_approval_review(rows, [])
    assert bool(result['warning']) is warning
    assert sum(result['counts'].values()) == count
    if warning:
        assert 'does not block decisions' in result['warning']


def test_unknown_timing_stays_in_denominator():
    rows = [record(i, seconds=1 if i < 8 else None) for i in range(10)]
    assert build_approval_review(rows, [])['warning'] is None


@pytest.mark.parametrize('seconds', [None, -1, float('nan'), float('inf')])
def test_invalid_timing_is_unknown(seconds):
    assert build_approval_review([record(1, seconds=seconds)], [])['decision_seconds'] == [None]


def test_configuration_and_purity():
    rows = [record(i) for i in range(2)]
    before = copy.deepcopy(rows)
    options = dict(min_decisions=2, approval_ratio=1, fast_ratio=1, fast_seconds=6)
    result = build_approval_review(iter(rows), iter([]), **options)
    assert result['warning'] is not None
    assert rows == before
    assert result == build_approval_review(rows, [], **options)


@pytest.mark.parametrize('options', [dict(min_decisions=0), dict(approval_ratio=1.1),
                                    dict(fast_ratio=-1), dict(fast_seconds=float('nan'))])
def test_invalid_configuration(options):
    with pytest.raises(ValueError):
        build_approval_review([], [], **options)
