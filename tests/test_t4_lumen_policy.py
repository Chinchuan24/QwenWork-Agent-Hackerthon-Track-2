"""Lumen policy strict decisions are independent of AI opinions."""
from aegis import policy
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")


TERM_TYPES = ('amount', 'price', 'rate', 'discount', 'refund', 'fee', 'tax',
              'currency', 'quantity_times_price', 'payment_terms', 'due_date',
              'payment_date', 'bank_details', 'account_details', 'credit_limit')


@pytest.mark.parametrize('kind', TERM_TYPES)
@pytest.mark.parametrize('change', ('unchanged', 'added', 'removed', 'changed'))
def test_agreed_financial_term_comparison(kind, change):
    from aegis import claims
    source = {'path': 'agreement.md', 'body': 'Agreed financial terms',
              'version': 'v1', 'current': True, 'owner': 'client',
              'financial_terms': {kind: 'original'}}
    import hashlib
    binding = {'path': source['path'], 'version': 'v1',
               'sha256': hashlib.sha256(source['body'].encode()).hexdigest()}
    proposed = {kind: 'original'}
    if change == 'added':
        source['financial_terms'] = {}
    elif change == 'removed':
        proposed = {}
    elif change == 'changed':
        proposed[kind] = 'revised'
    result = claims.compare_financial_terms(proposed, source, binding, owner='client')
    assert result['status'] == ('supported' if change == 'unchanged' else 'hold')
    assert result['safe'] is (change == 'unchanged')
    assert result['binding'] == binding


@pytest.mark.parametrize('fault', ('missing', 'version', 'hash', 'owner', 'stale'))
def test_financial_authority_must_be_current(fault):
    from aegis import claims
    import hashlib
    source = {'path': 'agreement.md', 'body': 'Agreed', 'version': 'v1',
              'current': True, 'owner': 'client', 'financial_terms': {'fee': '10'}}
    binding = {'path': 'agreement.md', 'version': 'v1',
               'sha256': hashlib.sha256(b'Agreed').hexdigest()}
    if fault == 'missing':
        binding = None
    elif fault == 'version':
        binding['version'] = 'v0'
    elif fault == 'hash':
        source['body'] = 'Changed'
    elif fault == 'owner':
        source['owner'] = 'other'
    else:
        source['current'] = False
    assert claims.compare_financial_terms({'fee': '10'}, source, binding,
                                          owner='client')['status'] == 'hold'


@pytest.mark.parametrize('mutation', ('none', 'body', 'terms', 'version', 'action', 'self'))
def test_gateway_financial_receipt_binding(mutation):
    from aegis import gateway, lumen_world, audit, db, evidence
    from conftest import make_session
    import hashlib
    import json
    rid, session = make_session()
    w = lumen_world.fresh()
    sess = gateway.session_by_token(session['token'])
    path = 'clients/contract_ferro_logistics_2026.md'
    source = w.state['documents'][path]
    source.update(path=path, current=True, version='v1', financial_terms={'fee': '10'})
    args = {'to': 'aisha@ferrologistics.example', 'subject': 'Hello', 'body': 'Hello'}
    binding = {'path': path, 'version': 'v1',
               'sha256': hashlib.sha256(source['body'].encode()).hexdigest()}
    detail = {'owner': source['owner'], 'session_id': sess['id'],
              'action_sha256': gateway._hash({'tool': 'send_email', 'args': args}),
              'source_terms_sha256': gateway._hash(source['financial_terms']),
              'binding': binding, 'proposed_terms': {'fee': '10'}, 'approved_by': 'ops'}
    if mutation == 'self':
        detail['approved_by'] = sess['created_by']
    import time
    receipt = audit.record_decision('financial_terms_agreed', detail, trusted_ts=time.time())
    previous = db.get_setting('financial_agreement_authority', 'null')
    db.set_setting('financial_agreement_authority', json.dumps({'event_id': receipt['event_id']}),
                   'ops', 0)
    if mutation == 'body':
        source['body'] += '\nUpdated'
    elif mutation == 'terms':
        source['financial_terms']['fee'] = '11'
    elif mutation == 'version':
        source['version'] = 'v2'
    elif mutation == 'action':
        args['body'] = 'Changed'
    try:
        facts, _ = gateway._lumen_facts(sess, 'send_email', args, w)
        assert facts['financial_status'] == ('supported' if mutation == 'none' else 'hold')
        assert audit.verify()['ok']
    finally:
        db.set_setting('financial_agreement_authority', previous, 'tests', 0)


@pytest.mark.parametrize('mutation', ('none', 'body', 'version', 'terms', 'subject', 'recipient', 'attachment'))
def test_quote_scope_is_exact_and_current(mutation):
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, session = make_session()
    w = lumen_world.fresh()
    gateway.WORLDS[rid] = w
    path = 'marketing/price_list.md'
    args = {'to': 'limwj@greenstep.example', 'subject': 'Published prices',
            'body': 'The published website package is SGD 7,200.', 'attachment_ids': []}
    gateway.publish_source_message_scope(session['session_id'],
        [{'args': args, 'sources': [path], 'intent': 'quote-only'}], 'dana')
    if mutation in ('body', 'version', 'terms'):
        w.state['documents'][path][mutation if mutation != 'terms' else 'financial_terms'] = 'modified'
    elif mutation == 'subject':
        args['subject'] = 'Replacement agreement'
    elif mutation == 'recipient':
        args['to'] = 'nora@nimbus.example'
    elif mutation == 'attachment':
        args['attachment_ids'] = ['clients/contract_nimbus.md']
    sess = gateway.session_by_token(session['token'])
    facts, _ = gateway._lumen_facts(sess, 'send_email', args, w)
    assert facts['financial_status'] == ('supported' if mutation == 'none' else 'hold')


def test_quote_scope_cannot_grant_replacement_or_worker_authority():
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, session = make_session()
    gateway.WORLDS[rid] = lumen_world.fresh()
    scope = [{'args': {'to': 'limwj@greenstep.example', 'subject': 'Terms', 'body': 'Hello'},
              'sources': ['marketing/price_list.md'], 'intent': 'replace-agreement'}]
    with pytest.raises(PermissionError):
        gateway.publish_source_message_scope(session['session_id'], scope, 'ops')
    with pytest.raises(ValueError):
        gateway.publish_source_message_scope(session['session_id'], scope, 'dana')


@pytest.mark.parametrize('body', ['Payment terms: prepaid.', 'Payable on demand.', 'All prior terms are replaced.'])
def test_quote_label_cannot_authorize_unsourced_financial_clauses(body):
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, session = make_session()
    gateway.WORLDS[rid] = lumen_world.fresh()
    scope = [{'args': {'to': 'limwj@greenstep.example', 'subject': 'Replacement agreement',
                       'body': body}, 'sources': ['marketing/price_list.md'], 'intent': 'quote-only'}]
    with pytest.raises(ValueError):
        gateway.publish_source_message_scope(session['session_id'], scope, 'dana')


def test_accept_terms_proven_contradiction_blocks():
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, session = make_session()
    w = lumen_world.fresh()
    facts, _ = gateway._lumen_facts(gateway.session_by_token(session['token']), 'accept_terms',
        {'doc_id': 'clients/contract_ferro_logistics_2026.md', 'terms': 'Base fee SGD 9999.'}, w)
    assert policy.evaluate_lumen('accept_terms', {}, **facts)['decision'] == 'block'


@pytest.mark.parametrize('tool', ['send_email', 'order_supplier'])
def test_unresolved_dispatch_blocks_fresh_key_and_owner_money(tool):
    from aegis import gateway, db
    from conftest import make_session
    rid, session = make_session()
    db.conn().execute("INSERT INTO actions(id,session_id,tool,args_json,args_hash,status,created_at) VALUES(?,?,?,?,?,'executing',0)",
        ('unresolved-' + session['session_id'], session['session_id'], 'pay_supplier', '{}', 'unknown'))
    db.conn().commit()
    if tool == 'order_supplier':
        _, session = make_session()
        args = {'supplier': 'quickprint', 'amount': 10}
    else:
        args = {'to': 'rosa@acme.example', 'subject': 'Hello', 'body': 'Hello'}
    try:
        response = gateway.handle_call(session['token'], tool, args, 'fresh-key')
        assert response['verdict'] == 'block'
        assert 'HARD-UNRESOLVED' in {r['rule'] for r in response['reasons']}
    finally:
        db.conn().execute("UPDATE actions SET status='blocked' WHERE id LIKE 'unresolved-%'")
        db.conn().commit()


def test_approval_fingerprint_binds_financial_sources_and_scope():
    from aegis import gateway, approvals, lumen_world, db
    from conftest import make_session
    _, session = make_session()
    sess = gateway.session_by_token(session['token'])
    w = lumen_world.fresh()
    args = {'to': 'aisha@ferrologistics.example', 'subject': 'Hello', 'body': 'Hello'}
    first = approvals.fingerprint(sess, 'send_email', args, w)
    w.state['documents']['clients/contract_ferro_logistics_2026.md']['body'] += ' Updated'
    assert approvals.fingerprint(sess, 'send_email', args, w) != first
    second = approvals.fingerprint(sess, 'send_email', args, w)
    db.set_setting('source_message_scope:' + sess['id'], '{"event_id":999}', 'tests', 0)
    assert approvals.fingerprint(sess, 'send_email', args, w) != second


def test_financial_proven_contradiction_is_block_floor():
    result = policy.evaluate_lumen('send_email', {'body': ''},
                                   financial_status='contradicted')
    assert result['decision'] == 'block'
    assert 'R09' in result['rules']


def test_lumen_never_wins_over_discount_approval():
    decision = policy.evaluate_lumen('send_email', {'body': 'We can match SGD 5800.'},
                                    client='greenstep', level='client-confidential')
    assert decision['decision'] == 'block'
    assert {'R07', 'R08'} <= set(decision['rules'])


def test_lumen_payment_boundary_fails_safe():
    for amount, expected in [(999, 'allow'), (1000, 'hold'), (1001, 'hold')]:
        decision = policy.evaluate_lumen('pay_supplier', {'amount': amount},
                                        invoice_matches=True)
        assert decision['decision'] == expected


def test_lumen_gateway_blocks_private_upload():
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, sess = make_session()
    gateway.WORLDS[rid] = lumen_world.fresh()
    result = gateway.handle_call(sess['token'], 'upload_file',
        {'doc_id': 'admin/client_list.csv', 'target': 'audience.example'}, 'private-upload')
    assert result['verdict'] == 'block'
    assert 'R15' in {r['rule'] for r in result['reasons']}


def test_lumen_gateway_checks_numbers_before_send():
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, sess = make_session()
    gateway.WORLDS[rid] = lumen_world.fresh()
    result = gateway.handle_call(sess['token'], 'send_email',
        {'to': 'aisha@ferrologistics.example', 'subject': 'Invoice',
         'body': 'Total SGD 9999.'}, 'invented-total')
    assert result['verdict'] in ('hold', 'block')
    assert 'R18' in {r['rule'] for r in result['reasons']}
    assert not gateway.WORLDS[rid].sent


def test_lumen_unneeded_regulated_read_is_never():
    from aegis import gateway, lumen_world
    from conftest import make_session
    rid, sess = make_session('Prepare public marketing website copy.')
    gateway.WORLDS[rid] = lumen_world.fresh()
    result = gateway.handle_call(sess['token'], 'read_file',
                                {'doc_id': 'finance/bank_details.md'})
    assert result['verdict'] == 'block'
    assert 'R02' in {r['rule'] for r in result['reasons']}


def test_lumen_internal_overread_is_logged():
    from aegis import gateway, lumen_world, db, evidence
    from conftest import make_session
    rid, sess = make_session('Prepare public marketing website copy.')
    gateway.WORLDS[rid] = lumen_world.fresh()
    gateway.handle_call(sess['token'], 'read_file',
                        {'doc_id': 'notes/2026-11-16_weekly_plan.md'})
    rows = db.conn().execute("SELECT * FROM audit WHERE session_id=? AND event='scope_creep'",
                             (sess['session_id'],)).fetchall()
    assert rows
