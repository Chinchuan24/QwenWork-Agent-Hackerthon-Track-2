"""Office actions must use the existing logged channel."""
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from aegis import gateway


@pytest.mark.parametrize('amount', [True, -1, 0, float('inf'), float('nan')])
@pytest.mark.parametrize('tool', ['pay_supplier', 'order_supplier'])
def test_office_amounts_fail_closed(tool, amount):
    args = {'supplier': 'quickprint', 'amount': amount}
    if tool == 'pay_supplier':
        args['invoice_id'] = 'fixture-invoice'
    assert gateway._validate_args(tool, args)


def test_office_approval_binds_document_content():
    from aegis import approvals, world
    w = world.World()
    sess = {'limits_hash': 'fixed', 'id': 'fixture-session'}
    args = {'doc_id': 'doc_brochure', 'target': 'outside.example'}
    before = approvals.fingerprint(sess, 'upload_file', args, w)
    w.state['documents']['doc_brochure']['body'] = 'Changed after review'
    assert approvals.fingerprint(sess, 'upload_file', args, w) != before


def test_office_actions_have_validated_schemas():
    required = {
        'delete_file': ['doc_id'],
        'upload_file': ['doc_id', 'target'],
        'pay_supplier': ['supplier', 'amount', 'invoice_id'],
        'order_supplier': ['supplier', 'amount'],
        'accept_terms': ['doc_id', 'terms'],
    }
    for tool, fields in required.items():
        assert tool in gateway.SIDE_EFFECT
        assert tool in gateway.TOOL_SCHEMAS
        for field in fields:
            assert field in gateway.REQUIRED[tool]
        assert gateway._validate_args(tool, {})


@pytest.mark.parametrize('amount', [True, float('nan'), float('inf'), 0])
def test_refund_numeric_schema(amount):
    assert gateway._validate_args('issue_refund', {'invoice_id': 'i', 'amount': amount})


def test_exposed_office_target_must_be_authorized():
    from aegis import world
    assert not gateway._clearly_inside(
        {'task_text': 'Review the brochure'}, 'upload_file',
        {'doc_id': 'doc_brochure', 'target': 'attacker.example'}, world.World(),
        {'tools': ['upload_file']}, [])


def test_missing_persisted_card_refuses_every_action():
    from conftest import make_session
    from aegis import db
    rid, sess = make_session()
    db.conn().execute('DELETE FROM helper_cards WHERE helper_id=?', (sess['session_id'],))
    db.conn().commit()
    out = gateway.handle_call(sess['token'], 'list_inbox', {})
    assert out['verdict'] == 'block'
    assert out['reasons'][0]['rule'] == 'HARD-CARD'


def test_card_change_applies_next_call():
    from conftest import make_session
    from aegis import db, evidence
    rid, sess = make_session()
    db.conn().execute('UPDATE helper_cards SET content=? WHERE helper_id=?',
                      (evidence.enc_json({'tools': [], 'read_folders': [], 'read_sensitivity': []}),
                       sess['session_id']))
    db.conn().commit()
    assert gateway.handle_call(sess['token'], 'list_inbox', {})['verdict'] == 'block'

