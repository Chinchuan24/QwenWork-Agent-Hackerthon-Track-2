import json

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegis.incident_report import build_incident_report, IncidentReports


def records(verdict='hold'):
    return [
        {'id': 1, 'ts': 30, 'session_id': 's', 'event': 'session_started', 'detail': {'task': 'PRIVATE <script>attack</script>'}},
        {'id': 2, 'ts': 20, 'session_id': 's', 'event': 'session_exposed', 'detail': {'kind': 'email', 'source': 'PRIVATE'}},
        {'id': 3, 'ts': 10, 'session_id': 's', 'event': 'second_opinion', 'detail': {'a': {'verdict': 'safe', 'mode': 'standin'}, 'b': {'verdict': 'unsure', 'reason': 'PRIVATE'}}},
        {'id': 4, 'ts': 5, 'session_id': 's', 'event': 'decision', 'detail': {'verdict': verdict, 'tool': 'send_email', 'args': {'body': 'PRIVATE'}, 'reasons': [{'rule': 'R-SECOND-UNSURE', 'reason': 'PRIVATE'}]}},
    ]


@pytest.mark.parametrize('verdict', ['hold', 'block'])
def test_decision(verdict):
    report = build_incident_report([4], records(verdict))
    assert report['trigger'] == verdict
    assert report['task']['record_id'] == 1
    assert report['action']['tool'] == 'send_email'
    assert report['cause']['exposure_record_ids'] == [2]
    assert report['policy']['rules'] == ['R-SECOND-UNSURE']
    assert report['policy']['version'] is None
    assert report['guards'][0]['a']['verdict'] == 'safe'
    assert report['guards'][0]['b']['verdict'] == 'unsure'
    assert [r['record_id'] for r in report['timeline']] == [1, 2, 3, 4]
    assert report['proof']['verified'] is False
    assert 'PRIVATE' not in json.dumps(report)


def test_frozen_isolated():
    rows = records() + [{'id': 5, 'ts': 40, 'session_id': 's', 'event': 'session_frozen', 'detail': {'reason': 'PRIVATE'}}, {'id': 6, 'ts': 41, 'session_id': 'other', 'event': 'session_started', 'detail': {'task': 'PRIVATE'}}]
    report = build_incident_report([5], rows)
    assert report['trigger'] == 'frozen'
    assert 6 not in report['proof']['record_ids']
    assert report['action']['tool'] == 'not recorded'


@pytest.mark.parametrize('ids', [[], [999], [True], [4, 4], [1]])
def test_invalid(ids):
    with pytest.raises(ValueError):
        build_incident_report(ids, records())


def test_large_and_future():
    rows = records() + [{'id': i, 'ts': i, 'session_id': 's', 'event': 'decision', 'detail': {'verdict': 'allow'}} for i in range(5, 305)]
    rows.append({'id': 305, 'ts': 0, 'session_id': 's', 'event': 'session_frozen', 'detail': {}})
    report = build_incident_report([305], rows)
    assert len(report['timeline']) == 305
    env = Environment(loader=FileSystemLoader('templates'), autoescape=select_autoescape())
    html = env.get_template('incident_report.html').render(report=report)
    assert 'PRIVATE' not in html
    assert '<details' in html
    assert len(build_incident_report([4], rows)['timeline']) == 4


def test_action_bound_guards():
    rows = records()
    rows[2]['detail']['action_id'] = 'a' * 12
    rows[3]['detail']['action_id'] = 'b' * 12
    report = build_incident_report([4], rows)
    assert report['guards'][0]['scope'] == 'other action'
    assert report['action']['guard_record_ids'] == []
    rows[3]['detail']['action_id'] = 'a' * 12
    report = build_incident_report([4], rows)
    assert report['guards'][0]['scope'] == 'selected action'
    assert report['action']['guard_record_ids'] == [3]
    assert report['action']['guard_verdict'] == 'unknown'
    assert 'a' * 12 not in json.dumps(report)


def test_missing_binding_unknown():
    report = build_incident_report([4], records())
    assert report['guards'][0]['scope'] == 'unknown'
    assert report['action']['guard_verdict'] == 'unknown'
    assert report['action']['guard_record_ids'] == []


def test_conflicting_private_and_frozen_bindings():
    rows = records()
    rows[2]['detail']['action_id'] = 'a' * 12
    for binding in ({'action_id': 'PRIVATE'},
                    {'action_id': 'a' * 12, 'action': 'b' * 12}):
        rows[3]['detail'].update(binding)
        report = build_incident_report([4], rows)
        assert report['guards'][0]['scope'] == 'unknown'
        assert report['action']['guard_record_ids'] == []
        assert 'PRIVATE' not in json.dumps(report)
    rows[3]['event'] = 'session_frozen'
    rows[3]['detail'] = {'action_id': 'a' * 12}
    assert build_incident_report([4], rows)['action']['guard_record_ids'] == []


def test_adapter_failure_has_no_fallback():
    calls = []
    class Adapter:
        def make(self, request, audit_ids):
            calls.append((request, audit_ids))
            raise PermissionError('Trusted session required')
    request = {'role': 'admin', 'authorized': True}
    with pytest.raises(PermissionError):
        IncidentReports(Adapter()).make(request, [4])
    assert calls == [(request, (4,))]
    with pytest.raises(ValueError):
        IncidentReports(Adapter()).make(request, [True])
    assert len(calls) == 1


def test_scope_visible_without_proof_links():
    env = Environment(loader=FileSystemLoader('templates'), autoescape=select_autoescape())
    html = env.get_template('incident_report.html').render(report=build_incident_report([4], records()))
    assert 'Action guard verdict: unknown' in html
    proof = html.split('Show proof and recorded checks')[1].split('</details>')[0]
    assert '<a ' not in proof
    assert 'PRIVATE' not in html


def test_boundary():
    with pytest.raises(PermissionError):
        IncidentReports().make({'role': 'admin', 'authorized': True}, [4])


def test_pure(monkeypatch):
    from aegis import audit, db
    def forbidden(*args, **kwargs):
        raise AssertionError('Storage touched')
    monkeypatch.setattr(db, 'conn', forbidden)
    monkeypatch.setattr(audit, 'record', forbidden)
    assert build_incident_report([4], records())['trigger'] == 'hold'


def test_json_and_missing_guard():
    rows = records()
    for row in rows:
        row['detail_json'] = json.dumps(row.pop('detail'))
    report = build_incident_report([4], rows)
    assert report['guards'][0]['b']['mode'] == 'not recorded'
    rows[3]['detail_json'] = 'broken'
    with pytest.raises(ValueError):
        build_incident_report([4], rows)
