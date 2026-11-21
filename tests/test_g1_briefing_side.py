import json

import pytest

from aegis import briefing, db


def stored(i, status='executed', viewed_at=95):
    return dict(id=str(i), status=status, decided_at=100, claimed_at=100,
                viewed_at=viewed_at, viewed_by='ops', decided_by='ops')


def build(monkeypatch, rows, events=()):
    class Connection:
        def execute(self, sql):
            assert sql == 'SELECT * FROM approvals'
            return rows
    monkeypatch.setattr(db, 'conn', lambda: Connection())
    return briefing.build_briefing(list(events), start=90, end=110)


def review_line(result):
    return result['sections']['you_should_know'][0]['text']


def test_stored_counts_and_calm_warning(monkeypatch):
    result = build(monkeypatch, [stored(i) for i in range(9)] + [stored(9, 'changed')])
    text = review_line(result)
    assert '9 approvals, 0 rejections, 1 changes' in text
    assert 'may warrant review' in text and 'does not block decisions' in text
    assert '\n' not in text and briefing.plain_text_ok(text)
    assert result['check_status'] == 'checked'
    assert result['counts']['needs_decision'] == 0


@pytest.mark.parametrize('count,fast,warning', [(9, 9, False), (10, 8, False), (10, 9, True)])
def test_existing_thresholds_and_missing_samples(monkeypatch, count, fast, warning):
    text = review_line(build(monkeypatch, [stored(i, viewed_at=95 if i < fast else None)
                                          for i in range(count)]))
    assert ('may warrant review' in text) is warning
    assert f'{count-fast} missing' in text


def test_authenticated_matching_views_only(monkeypatch):
    rows = [dict(stored(i), viewed_by='other') for i in range(10)]
    events = [dict(id=i+1, ts=95, event='approval_screen_viewed',
                   detail_json=json.dumps(dict(approval=str(i), by='ops')))
              for i in range(9)]
    text = review_line(build(monkeypatch, rows, events))
    assert '9 timed, 1 missing' in text and 'may warrant review' in text
    for row in rows:
        row['decided_by'] = None
        row['viewed_by'] = None
    text = review_line(build(monkeypatch, rows, events))
    assert '0 timed, 10 missing' in text and 'may warrant review' not in text


def test_stored_truth_day_bounds_and_failed_release(monkeypatch):
    rows = [stored(0, 'void'), stored(1, 'denied'), stored(2, 'changed'),
            dict(stored(3), decided_at=89), dict(stored(4), decided_at=110),
            dict(stored(5, 'void'), claimed_at=None), stored(6, 'pending')]
    text = review_line(build(monkeypatch, rows))
    assert '1 approvals, 1 rejections, 1 changes' in text
    assert 'may warrant review' not in text


def event(i, kind, ts=100, **detail):
    return dict(id=i, event=kind, ts=ts, detail_json=json.dumps(detail))


@pytest.mark.parametrize('kind,decision', [('approval_changed', None),
                                         ('approval_decided', 'approve'),
                                         ('approval_decided', 'reject'),
                                         ('approval_decided', 'change')])
def test_terminal_history_removes_pending_without_success(monkeypatch, kind, decision):
    events = [event(1, 'approval_requested', ts=91, approval='a'),
              event(2, kind, approval='a', decision=decision, by='ops')]
    result = build(monkeypatch, [], events)
    assert result['counts']['needs_decision'] == 0
    assert result['counts']['went_fine'] == 0
    later = briefing.build_briefing(events, start=110, end=120, seen_approval_ids=['a'])
    assert later['counts']['still_waiting'] == 0


def test_invalid_canonical_decision_keeps_pending(monkeypatch):
    result = build(monkeypatch, [], [event(1, 'approval_requested', ts=91, approval='a'),
                                   event(2, 'approval_decided', approval='a', decision='invalid')])
    assert result['counts']['needs_decision'] == 1


def test_canonical_history_overrides_rollback_and_keeps_legacy(monkeypatch):
    events = [event(1, 'approval_decided', approval='0', decision='reject', by='ops', viewed_at=95),
              event(2, 'approval_decided', ts=89, approval='1', decision='approve', by='ops'),
              event(3, 'approval_decided', approval='missing', decision='change', by='ops', viewed_at=95)]
    rows = [stored(0), stored(1), stored(2)]
    result = build(monkeypatch, rows, events)
    assert '1 approvals, 1 rejections, 1 changes' in review_line(result)
    assert '3 timed, 0 missing' in review_line(result)
    assert result['sections']['you_should_know'][0]['proof_ids'] == [1, 3]


def test_anonymous_canonical_view_is_unknown(monkeypatch):
    result = build(monkeypatch, [], [event(1, 'approval_decided', approval='a',
                                         decision='approve', by=None, viewed_at=95)])
    assert '0 timed, 1 missing' in review_line(result)


def test_empty_and_future_view_do_not_invent_timing(monkeypatch):
    assert not build(monkeypatch, [])['sections']['you_should_know']
    text = review_line(build(monkeypatch, [stored(i, viewed_at=101) for i in range(10)]))
    assert '0 timed, 10 missing' in text and 'may warrant review' not in text
