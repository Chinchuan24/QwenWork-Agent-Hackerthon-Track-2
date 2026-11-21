"""Synthetic adapter fixtures, not proof of gateway enforcement."""
import copy

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis.lumen_normal import CASES, run_normal


def test_canonical_gateway_actions():
    from aegis import gateway
    assert len(CASES) == 16
    for case in CASES:
        for action in case['actions']:
            assert gateway._validate_args(action['tool'], action['args']) == ''


def test_upload_receipt_without_effect_is_not_completion():
    def execute(task, actions):
        reply = execute_fixture(task, actions)
        task['world'].state.pop('uploads', None)
        return reply
    report = run_normal(execute)
    assert {'N14', 'N15'} <= {m['id'] for m in report['misses']}


def test_integrated_gateway_evidence(monkeypatch):
    from aegis import approvals, db, evidence
    from aegis.lumen_normal import run_integrated

    def no_autoapproval(*args, **kwargs):
        pytest.fail('normal measurement must not inject approval decisions')

    monkeypatch.setattr(approvals, 'decide', no_autoapproval)
    before = db.conn().execute('SELECT COUNT(*) FROM approvals').fetchone()[0]
    report = run_integrated()
    assert report['evidence_kind'] == 'integrated-measured'
    assert report['total'] == 16
    assert report['audit_verified'] is True, report.get('audit_problems')
    assert all(c['api_evidence'] for c in report['cases'])
    assert all(e['persisted'] for c in report['cases'] for e in c['api_evidence'])
    # Misses were an outdated proxy for no autoapproval; normal work completes.
    assert report['completed'] == report['total'] == len(CASES) == 16
    assert report['completion_rate'] == 1
    assert report['false_holds'] == report['wrongly_stopped'] == 0
    assert report['false_hold_rate'] == 0
    assert report['meets_target'] is True and report['misses'] == []
    assert report['mode'] == 'scripted'
    assert report['judge_mode'] == 'standin'
    assert report['gateway_mode'] == 'enforce'
    assert report['audit_problems'] == []
    assert db.conn().execute('SELECT COUNT(*) FROM approvals').fetchone()[0] == before
    assert [c['id'] for c in report['cases']] == [c['id'] for c in CASES]
    action_ids, audit_ids = [], []
    for case, canonical in zip(report['cases'], CASES):
        assert case['completed'] is True
        assert case['false_hold'] is False and case['wrongly_stopped'] is False
        assert case['error'] is None
        assert case['action_checks'] == [True] * len(canonical['actions'])
        assert len(case['api_evidence']) == len(canonical['actions'])
        for item, action in zip(case['api_evidence'], canonical['actions']):
            assert item['tool'] == action['tool']
            assert item['verdict'] == 'allow' and item['status'] == 'executed'
            stored = db.conn().execute('SELECT * FROM actions WHERE id=?',
                                       (item['action_id'],)).fetchone()
            assert stored['session_id'] == item['session_id']
            assert stored['tool'] == action['tool']
            assert evidence.dec_json(stored['args_json']) == action['args']
            assert stored['verdict'] == 'allow' and stored['status'] == 'executed'
            assert stored['executed_at'] is not None
            assert stored['result_json'] is not None
            assert db.conn().execute('SELECT COUNT(*) FROM approvals WHERE action_id=?',
                                     (item['action_id'],)).fetchone()[0] == 0
            assert len(item['audit_ids']) == 1
            record = db.conn().execute('SELECT * FROM audit WHERE id=?',
                                       (item['audit_ids'][0],)).fetchone()
            assert record['run_id'] == item['run_id']
            assert record['session_id'] == item['session_id']
            assert record['event'] == 'decision'
            assert evidence.dec_json(record['detail_json']) == {
                'tool': action['tool'], 'args': action['args'], 'verdict': 'allow',
                'reasons': item['reasons'], 'mode': 'enforce', 'status': 'executed',
                'action_id': item['action_id'], 'stage': 'final',
                'request_digest': stored['request_digest']}
            assert db.conn().execute(
                "SELECT COUNT(*) FROM audit WHERE session_id=? AND event IN "
                "('approval_requested','approval_decided','approved_action_executed')",
                (item['session_id'],)).fetchone()[0] == 0
            action_ids.append(item['action_id'])
            audit_ids.extend(item['audit_ids'])
    assert len(set(action_ids)) == len(action_ids)
    assert len(set(audit_ids)) == len(audit_ids)


def execute_fixture(task, actions):
    rows = []
    for action in actions:
        tool, args = action['tool'], action['args']
        world = task['world']
        if tool == 'read_file':
            result = world.read_file(**args)
        elif tool == 'send_email':
            result = world.send_email(**args)
        elif tool == 'delete_file':
            del world.state['documents'][args['doc_id']]
            result = {'deleted': True, **args}
        elif tool == 'upload_file':
            result = world.office_action(tool, args)
        else:
            raise AssertionError(tool)
        rows.append({'tool': tool, 'args': copy.deepcopy(args),
                     'decision': 'ALLOW', 'result': result, 'logged': True})
    return {'results': rows}


def test_scoped_cases_and_measured_completion():
    assert len(CASES) >= 15
    assert len({c['id'] for c in CASES}) == len(CASES)
    def execute(task, actions):
        assert {'helper_id', 'needed_files', 'allowed_tools',
                'allowed_recipients', 'world', 'task'} <= task.keys()
        assert 'expected' not in task
        for action in actions:
            assert set(action) == {'tool', 'args'}
            assert action['tool'] in task['allowed_tools']
            for key in ('doc_id', 'file_id'):
                if key in action['args']:
                    path = action['args'][key]
                    assert path in task['needed_files']
                    assert task['world'].doc(path) is not None
            if 'to' in action['args']:
                assert action['args']['to'] in task['allowed_recipients']
        return execute_fixture(task, actions)
    report = run_normal(execute)
    assert report['completed'] == report['total'] == len(CASES)
    assert report['completion_rate'] == 1
    assert report['false_holds'] == 0 and report['meets_target']
    assert report['mode'] == 'scripted' and report['misses'] == []


def test_exception_and_public_case_study():
    exception = next(c for c in CASES if c['id'] == 'N16')
    actions = exception['actions']
    deletion = next(i for i, a in enumerate(actions) if a['tool'] == 'delete_file')
    sends = [(i, a) for i, a in enumerate(actions) if a['tool'] == 'send_email']
    assert {a['args']['to'] for _, a in sends} == {
        'daniel@lumen.example', 'nora@nimbus.example'}
    assert all(i > deletion for i, _ in sends)
    assert all(not a['args'].get('attachment_ids') for _, a in sends)
    assert 'INVALID-PATIENT' not in str(sends)
    assert not any(a['tool'] == 'read_file' and a['args']['doc_id'] ==
                   'admin/attachment_nimbus_patients.csv' for a in actions)
    public = next(c for c in CASES if c['id'] == 'N13')
    assert public['actions'][-1]['args']['attachment_ids'] == [
        'marketing/case_study_harbourbean.md']


def test_fresh_worlds_and_copies_per_task_and_rerun():
    worlds = []
    snapshot = copy.deepcopy(CASES)
    def execute(task, actions):
        assert len(task['world'].state['documents']) == 28
        worlds.append(task['world'])
        reply = execute_fixture(task, actions)
        actions.clear()
        return reply
    assert run_normal(execute)['completed'] == len(CASES)
    assert run_normal(execute)['completed'] == len(CASES)
    assert len({id(w) for w in worlds}) == 2 * len(CASES)
    assert CASES == snapshot


@pytest.mark.parametrize('reply', [None, {}, 'ALLOW', {'completed': True},
                                  {'decision': 'ALLOW'}, {'results': []}])
def test_malformed_results_are_not_success(reply):
    report = run_normal(lambda task, actions: reply)
    assert report['completed'] == 0 and not report['meets_target']
    assert len(report['misses']) == len(CASES)


@pytest.mark.parametrize('decision', ['HOLD', 'BLOCK'])
def test_wrong_stops_measured(decision):
    def execute(task, actions):
        return {'results': [{'tool': a['tool'], 'args': a['args'],
                             'decision': decision, 'result': {}, 'logged': True}
                            for a in actions]}
    report = run_normal(execute, mode='live')
    assert report['completed'] == 0
    assert report['false_holds'] == (len(CASES) if decision == 'HOLD' else 0)
    assert report['wrongly_stopped'] == len(CASES)
    assert report['mode'] == 'live'


@pytest.mark.parametrize('damage', ['error', 'missing', 'extra', 'wrong_args',
                                    'unlogged', 'fake_read', 'fake_send',
                                    'fake_delete', 'fake_upload', 'reordered'])
def test_actual_results_and_effects_required(damage):
    def execute(task, actions):
        before = copy.deepcopy(task['world'].state['documents'])
        reply = execute_fixture(task, actions)
        rows = reply['results']
        if damage == 'error':
            rows[-1]['result']['error'] = 'failure'
        elif damage == 'missing':
            rows.pop()
        elif damage == 'extra':
            rows.append(copy.deepcopy(rows[0]))
        elif damage == 'wrong_args':
            rows[-1]['args'] = {}
        elif damage == 'unlogged':
            rows[-1]['logged'] = False
        elif damage == 'fake_read':
            rows[0]['result'] = {'id': actions[0]['args']['doc_id'], 'body': 'invented'}
        elif damage == 'fake_send':
            task['world'].sent.clear()
        elif damage == 'fake_delete':
            task['world'].state['documents'] = before
        elif damage == 'fake_upload':
            for row in rows:
                if row['tool'] == 'upload_file':
                    row['result']['uploaded'] = 1
        elif damage == 'reordered':
            rows.reverse()
        return reply
    report = run_normal(execute)
    assert report['completed'] < len(CASES) and report['misses']


def test_partial_notification_and_errors():
    def partial(task, actions):
        reply = execute_fixture(task, actions)
        if task['scenario_id'] == 'N16':
            reply['results'][-1]['decision'] = 'HOLD'
        return reply
    report = run_normal(partial)
    assert report['completed'] == len(CASES) - 1
    assert report['false_holds'] == 1
    assert report['misses'][0]['id'] == 'N16'
    seen = []
    def fail(task, actions):
        seen.append(task['scenario_id'])
        raise RuntimeError('private payload')
    report = run_normal(fail)
    assert len(seen) == len(CASES) and report['completed'] == 0
    assert 'private payload' not in str(report)
    assert all(row['error'] == 'execution failed' for row in report['cases'])


def test_executor_and_mode_required():
    with pytest.raises(TypeError):
        run_normal(None)
    with pytest.raises(ValueError):
        run_normal(execute_fixture, mode='stand-in')
