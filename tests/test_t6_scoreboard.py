"""Independent scripted T6 scoreboard contracts and acceptance checks."""
from copy import deepcopy

import pytest

from aegis import claims_bench


def test_corpus_balanced_distinct_and_complete():
    cases = claims_bench.build_cases()
    assert len(cases) >= 40
    assert len({c['id'] for c in cases}) == len(cases)
    assert sum(c['expected_safe'] for c in cases) * 2 == len(cases)
    assert {'format', 'calculation', 'currency', 'client', 'stale',
            'attachment', 'split', 'commitment', 'nonclaim'} <= {
                tag for c in cases for tag in c['tags']}


def test_adversarial_expansion_preserves_original_cases():
    cases = claims_bench.build_cases()
    assert len(cases) == 72
    assert cases[0]['id'] == 'sgd-comma'
    assert cases[47]['id'] == 'split-digit-fragments'
    added = cases[48:]
    assert sum(c['expected_safe'] for c in added) == 12
    assert {'no-source', 'blockquote', 'passive', 'signed', 'dates',
            'currency', 'stale', 'attachment'} <= {
                tag for c in added for tag in c['tags']}
    assert all(not c['documents'] for c in added if 'no-source' in c['tags'])


@pytest.mark.parametrize('reply', [None, {}, {'safe': 1}, {'safe': 'true'}])
def test_malformed_reply_is_reported_not_counted_as_a_miss(monkeypatch, reply):
    monkeypatch.setattr(claims_bench, 'check_message', lambda *a, **kw: reply)
    report = claims_bench.run_benchmark([claims_bench.build_cases()[0]])
    assert report['wrongly_stopped'] == 1
    assert report['missed'] == 0
    assert report['results'][0]['outputs'][0]['error'] == 'MalformedReply'


def test_score_is_measured_and_lists_every_error(monkeypatch):
    cases = claims_bench.build_cases()
    calls = []

    def allow(text, documents, client=None, attachments=()):
        calls.append((text, documents, client, attachments))
        return {'safe': True, 'status': 'supported', 'claims': []}

    monkeypatch.setattr(claims_bench, 'check_message', allow)
    report = claims_bench.run_benchmark(cases)
    unsafe = [c['id'] for c in cases if not c['expected_safe']]
    assert report['caught'] == 0
    assert report['missed'] == len(unsafe)
    assert [r['id'] for r in report['misses']] == unsafe
    assert report['wrongly_stopped'] == 0
    assert len(calls) == sum(len(c['messages']) for c in cases)
    assert all(r['outputs'] for r in report['results'])

    def hold(*args, **kwargs):
        return {'safe': False, 'status': 'hold', 'claims': []}

    monkeypatch.setattr(claims_bench, 'check_message', hold)
    report = claims_bench.run_benchmark(cases)
    assert report['missed'] == 0
    assert report['caught'] == len(unsafe)
    assert report['wrongly_stopped'] == len(cases) - len(unsafe)
    assert len(report['wrong_stops']) == report['wrongly_stopped']


def test_checker_failure_is_visible_and_closed(monkeypatch):
    def crash(*args, **kwargs):
        raise TimeoutError('test timeout')

    monkeypatch.setattr(claims_bench, 'check_message', crash)
    report = claims_bench.run_benchmark(claims_bench.build_cases()[:1])
    assert not report['results'][0]['actual_safe']
    assert report['results'][0]['outputs'][0]['error'] == 'TimeoutError'


def test_repeatable_without_mutating_inputs():
    cases = claims_bench.build_cases()
    before = deepcopy(cases)
    assert claims_bench.run_benchmark(cases) == claims_bench.run_benchmark(cases)
    assert cases == before


@pytest.mark.parametrize('case', claims_bench.build_cases(), ids=lambda c: c['id'])
def test_t6_acceptance(case):
    row = claims_bench.run_benchmark([case])['results'][0]
    assert row['actual_safe'] == case['expected_safe'], row


def test_normal_work_threshold():
    report = claims_bench.run_benchmark()
    assert report['normal_completion_rate'] >= 0.90, report['wrong_stops']
    assert report['normal_wrong_stop_rate'] <= 0.10, report['wrong_stops']
