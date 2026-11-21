"""C3 enforcement regressions through local sandbox entry points."""
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, evidence, gateway
from conftest import make_session


def save_card(session, **changes):
    card = dict(tools=list(gateway.TOOL_SCHEMAS), read_folders=[''],
                read_sensitivity=['public', 'internal', 'confidential'],
                never_read=[], never=[], frozen=False)
    card.update(changes)
    db.conn().execute('UPDATE helper_cards SET content=? WHERE helper_id=?',
                      (evidence.enc_json(card), session['session_id']))
    db.conn().commit()


def call(session, tool, args):
    return gateway.handle_call(session['token'], tool, args, uuid.uuid4().hex)


@pytest.mark.parametrize('change', [dict(tools=[]), dict(frozen=True),
                                  dict(never=['send_email'])])
def test_current_card_blocks_approved_send(change):
    rid, session = make_session()
    out = call(session, 'send_email', dict(to='outsider@unknown.example',
                                         subject='hello', body='hello'))
    assert out['verdict'] == 'hold'
    save_card(session, **change)
    result = approvals.decide(out['approval_id'],
                              dict(username='reviewer', role='approver'), 'approve')
    assert result['ok'] is False
    assert gateway.get_world(rid).sent == []


@pytest.mark.parametrize('restriction', [dict(read_folders=['notes']),
    dict(read_sensitivity=['public']), dict(never_read=['doc_acme_q3'])])
def test_search_does_not_reveal_restricted_body_matches(restriction):
    rid, session = make_session(mode='off')
    gateway.get_world(rid).doc('doc_acme_q3')['body'] = 'unique-hidden-body'
    save_card(session, **restriction)
    out = call(session, 'search_files', dict(query='unique-hidden-body'))
    assert out['result'] == []


@pytest.mark.parametrize('tool,args', [('list_inbox', {}),
    ('read_email', {'email_id': 'em_poisoned_forward'})])
def test_inbox_restrictions(tool, args):
    _, session = make_session(mode='off')
    save_card(session, read_folders=['notes'])
    out = call(session, tool, args)
    if tool == 'list_inbox':
        assert out['result'] == []
    else:
        assert out['verdict'] == 'block'


@pytest.mark.parametrize('restriction', [dict(frozen=True),
    dict(never=['order_supplier']),
    dict(money_limits=dict(currency='SGD', per_action='10', per_day='100')),
    dict(money_limits=dict(currency='SGD', per_action='100', per_day='10')),
    dict(money_limits=dict(currency='SGD', per_action='bad', per_day='100'))])
def test_off_mode_cannot_bypass_card(restriction):
    rid, session = make_session(mode='off')
    save_card(session, **restriction)
    out = call(session, 'order_supplier', dict(supplier='fixture', amount=20))
    assert out['verdict'] == 'block'
    assert gateway.get_world(rid).state.get('orders', []) == []


def test_document_folder_is_component_bounded():
    rid, session = make_session(mode='off')
    w = gateway.get_world(rid)
    w.state['documents']['notes-private/secret'] = dict(
        title='secret', body='secret', owner='firm', sensitivity='internal')
    save_card(session, read_folders=['notes'])
    assert call(session, 'read_file', dict(doc_id='notes-private/secret'))['verdict'] == 'block'


@pytest.mark.parametrize('scope', ['/', '///'])
def test_absolute_folder_cannot_become_root_permission(scope):
    _, session = make_session(mode='off')
    save_card(session, read_folders=[scope])
    out = call(session, 'read_file', dict(doc_id='doc_acme_q3'))
    assert out['verdict'] == 'block'


def test_backslash_document_is_checked_against_denied_components():
    rid, session = make_session(mode='off')
    gateway.get_world(rid).state['documents']['notes\\private\\secret'] = dict(
        title='secret', body='secret', owner='firm', sensitivity='internal')
    save_card(session, never_read=['notes/private'])
    out = call(session, 'read_file', dict(doc_id='notes\\private\\secret'))
    assert out['verdict'] == 'block'


def test_daily_money_limit_counts_previous_actions():
    rid, session = make_session(mode='off', by='isolated-money-' + uuid.uuid4().hex)
    save_card(session, money_limits=dict(currency='SGD', per_action='20', per_day='30'))
    assert call(session, 'order_supplier', dict(supplier='fixture', amount=20))['verdict'] == 'allow'
    assert call(session, 'order_supplier', dict(supplier='fixture', amount=20))['verdict'] == 'block'
    assert len(gateway.get_world(rid).state['orders']) == 1
