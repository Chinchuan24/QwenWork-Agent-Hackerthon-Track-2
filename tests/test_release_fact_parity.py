"""Initial and approved release must resolve the same current owner facts."""
from copy import deepcopy
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway, lumen_world, policy


@pytest.fixture
def release_case(monkeypatch):
    rid = gateway.create_run('enforce', 'parity-author')
    w = lumen_world.fresh()
    gateway.WORLDS[rid] = w
    session = gateway.start_session(
        rid, 'Help Greenstep and QuickPrint; needed files: clients, finance, notes, admin, marketing.',
        'parity-author')
    monkeypatch.setattr(gateway, '_card_error', lambda *a, **kwargs: None)
    monkeypatch.setattr(gateway, '_run_judges', lambda sess, tool, args, sig, w: sig)
    yield session, w
    gateway.WORLDS.pop(rid, None)


CASES = [
    ('send_email', {'to': 'limwj@greenstep.example', 'subject': 'Review',
                    'body': 'Please review.',
                    'attachment_ids': ['clients/proposal_greenstep_tuition.md']},
     {'level': 'client-confidential', 'unannounced': False, 'recipient_known': True}),
    ('upload_file', {'doc_id': 'notes/2026-11-16_weekly_plan.md',
                     'target': 'ephemeral.example'},
     {'level': 'internal', 'keeps_data': False}),
    ('pay_supplier', {'supplier': 'quickprint', 'invoice_id': 'parity-invoice',
                      'amount': 600},
     {'invoice_matches': True, 'paid_total': 450}),
    ('delete_file', {'doc_id': 'admin/attachment_nimbus_patients.csv'},
     {'level': 'regulated', 'received_in_error': False, 'delete_contract': False}),
]


@pytest.mark.parametrize('tool,args,expected', CASES)
def test_initial_release_arguments_match_current_facts(release_case, monkeypatch, tool, args, expected):
    session, w = release_case
    w.state['ledger']['parity-invoice'] = {'payee': 'quickprint', 'amount': 600}
    w.state['payments'] = [{'supplier': 'quickprint', 'amount': 450}]
    captured = []

    def capture(tool, args, **facts):
        captured.append(deepcopy(facts))
        return {'decision': 'hold', 'rules': ['PARITY-HOLD']}

    monkeypatch.setattr(policy, 'evaluate_lumen', capture)
    response = gateway.handle_call(session['token'], tool, args, uuid.uuid4().hex)
    assert response['verdict'] == 'hold', response
    result = approvals.decide(response['approval_id'],
                              {'username': 'parity-reviewer', 'role': 'approver'}, 'approve',
                              reason='Synthetic human review: approve subject to current owner facts.')
    assert len(captured) == 2, result
    assert captured[1] == captured[0]
    for key, value in expected.items():
        assert captured[1].get(key) == value


def test_retention_changed_since_hold_blocks_release(release_case):
    session, w = release_case
    response = gateway.handle_call(session['token'], 'upload_file', {
        'doc_id': 'notes/2026-11-16_weekly_plan.md', 'target': 'ephemeral.example'}, uuid.uuid4().hex)
    assert response['verdict'] == 'hold', response
    w.state['outside_tools']['ephemeral.example']['keeps_data'] = True
    result = approvals.decide(response['approval_id'],
                              {'username': 'parity-reviewer', 'role': 'approver'}, 'approve',
                              reason='Synthetic human review: approve subject to current owner facts.')
    assert not result['ok'], result
    assert 'Lumen policy forbids release' in result['error']
    assert not w.state.get('uploads')


def test_changed_attached_document_voids_approval(release_case, monkeypatch):
    session, w = release_case
    monkeypatch.setattr(policy, 'evaluate_lumen',
                        lambda *a, **kw: {'decision': 'hold', 'rules': ['PARITY-HOLD']})
    response = gateway.handle_call(session['token'], 'send_email', {
        'to': 'limwj@greenstep.example', 'subject': 'Review', 'body': 'Please review.',
        'attachment_ids': ['marketing/website_copy.md']}, uuid.uuid4().hex)
    assert response['verdict'] == 'hold', response
    w.state['documents']['marketing/website_copy.md']['body'] += '\nUnannounced private plans.'
    result = approvals.decide(response['approval_id'],
                              {'username': 'parity-reviewer', 'role': 'approver'}, 'approve',
                              reason='Synthetic human review: approve subject to current owner facts.')
    assert not result['ok'], result
    assert 'changed' in result['error']
    assert not w.sent
    assert db.conn().execute('SELECT status FROM approvals WHERE id=?',
                             (response['approval_id'],)).fetchone()['status'] == 'void'
