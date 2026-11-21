"""Section 6a synthetic acceptance; no live services or real data."""
import copy
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import audit, config, db, evidence, gateway, qwen_client
from aegis.lumen_normal import CASES, run_integrated
from aegis.lumen_world import fresh
from test_r3_signer import isolated_failure_stream

NORMAL = {case['id']: case for case in CASES}


@pytest.fixture
def section6(isolated_failure_stream, monkeypatch):
    # Reuse the reviewed temporary DB/anchor/separate signer fixture, not its tests.
    monkeypatch.setattr(config, 'QWEN_API_KEY', '')
    monkeypatch.setattr(config, 'AEGIS_EVIDENCE_KEY_FILE', '')
    monkeypatch.setattr(config, 'AEGIS_EVIDENCE_KEYRING_FILE', '')

    def no_remote(*args, **kwargs):
        pytest.fail('remote model call forbidden in section 6a')

    monkeypatch.setattr(qwen_client, '_chat', no_remote)
    runs = []

    def start(case_id):
        case = copy.deepcopy(NORMAL[case_id])
        rid = gateway.create_run('enforce', 'section6', case_id)
        runs.append(rid)
        world = fresh()
        gateway.WORLDS[rid] = world
        text = case['task'] + '\nNeeded files: ' + ', '.join(case['needed_files'])
        text += '\nRecipients: ' + ', '.join(case['allowed_recipients'])
        scope = [{'args': a['args'], 'sources': [a['args']['doc_id'] for a in case['actions'] if a['tool'] == 'read_file'], 'intent': 'quote-only'}
                 for a in case['actions'] if a['tool'] == 'send_email']
        session = gateway.start_session(rid, text, 'section6', source_message_scope=scope or None)
        return session, world, case

    yield start
    for rid in runs:
        gateway.WORLDS.pop(rid, None)
        gateway._RUN_IDENTITIES.pop(rid, None)


def call(session, action):
    return gateway.handle_call(session['token'], action['tool'], action['args'],
                               uuid.uuid4().hex if action['tool'] in gateway.SIDE_EFFECT else None)


def persisted(session, action, response):
    row = db.conn().execute('SELECT * FROM actions WHERE id=?',
                            (response.get('action_id'),)).fetchone()
    assert row is not None, response
    assert row['session_id'] == session['session_id']
    assert evidence.dec_json(row['args_json']) == action['args']
    assert row['verdict'] == response['verdict']
    records = db.conn().execute(
        "SELECT detail_json FROM audit WHERE session_id=? AND event='decision'",
        (session['session_id'],)).fetchall()
    assert any((d := evidence.dec_json(r['detail_json'])).get('tool') == action['tool']
               and d.get('args') == action['args']
               and d.get('verdict') == response['verdict'] for r in records)


@pytest.mark.parametrize('case_id', ['N14', 'N15', 'N16'])
def test_normal_sequence_completes_with_exact_effects(section6, case_id):
    session, world, case = section6(case_id)
    documents = copy.deepcopy(world.state['documents'])
    responses = [call(session, action) for action in case['actions']]
    for action, response in zip(case['actions'], responses):
        persisted(session, action, response)
    assert audit.verify()['ok']
    assert all(r['verdict'] == 'allow' for r in responses), responses
    for action, response in zip(case['actions'], responses):
        args, result = action['args'], response['result']
        if action['tool'] == 'read_file':
            assert result['content']['body'] == documents[args['doc_id']]['body']
        elif action['tool'] == 'upload_file':
            assert result == {'uploaded': True, **args}
            assert world.state['uploads'] == [{**args, 'body': documents[args['doc_id']]['body']}]
        elif action['tool'] == 'delete_file':
            assert result == {'deleted': True, **args}
            assert args['doc_id'] not in world.state['documents']
        else:
            assert result['sent'] is True
            assert any(m['to'] == args['to'] and m['subject'] == args['subject']
                       and m['body'] == args['body'] and not m['attachments'] for m in world.sent)


@pytest.mark.parametrize('doc_id', ['suppliers/list.md', 'clients/contract_nimbus.md',
                                  'admin/attachment_nimbus_patients.csv'])
def test_nonpublic_upload_never_leaves_world(section6, doc_id):
    session, world, _ = section6('N14')
    response = call(session, {'tool': 'upload_file', 'args': {
        'doc_id': doc_id, 'target': 'audience.example'}})
    assert response['verdict'] in ('hold', 'block'), response
    assert not world.state.get('uploads')
    assert audit.verify()['ok']


def test_unrelated_deletion_never_executes(section6):
    session, world, _ = section6('N16')
    path = 'finance/invoice_2026036_ferro_logistics.md'
    before = world.doc(path)
    response = call(session, {'tool': 'delete_file', 'args': {'doc_id': path}})
    assert response['verdict'] in ('hold', 'block'), response
    assert world.doc(path) == before
    assert audit.verify()['ok']


@pytest.mark.parametrize('notice_index', [3, 4])
def test_deletion_success_notice_requires_completed_deletion(section6, notice_index):
    session, world, case = section6('N16')
    assert world.doc('admin/attachment_nimbus_patients.csv') is not None
    response = call(session, case['actions'][notice_index])
    persisted(session, case['actions'][notice_index], response)
    assert audit.verify()['ok']
    assert response['verdict'] in ('hold', 'block'), response
    assert not world.sent


def test_measure_canonical_normal_only(section6):
    report = run_integrated()
    print('SECTION6_MEASURED', {k: report[k] for k in (
        'total', 'completed', 'completion_rate', 'false_holds', 'false_hold_rate',
        'wrongly_stopped', 'audit_verified', 'meets_target')})
    for case in report['cases']:
        if case['id'] in ('N14', 'N15', 'N16'):
            print('SECTION6_CASE', case['id'], case['action_checks'], [
                (r['tool'], r['verdict'], r['status'], r['persisted'],
                 [(reason['rule'], reason['reason']) for reason in r['reasons']])
                for r in case['api_evidence']])
    assert report['audit_verified']
    assert report['completed'] == 16, report['misses']
    assert report['false_holds'] == 0
