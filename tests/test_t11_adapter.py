"""Local adapter contract. No live external sessions or calls."""
from unittest.mock import patch

import pytest
from aegis import gateway
from aegis.qwenwork_adapter import QwenWorkAdapter
from conftest import make_session

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")


@pytest.mark.parametrize('tool', list(gateway.TOOL_SCHEMAS) + ['run_shell'])
def test_every_action_routes_through_gateway(tool):
    args = {'untrusted': 'data'}
    reply = {'verdict': 'hold', 'approval_id': 'proof'}
    with patch.object(gateway, 'handle_call', return_value=reply) as routed:
        assert QwenWorkAdapter('caller-token')(tool, args, 'caller-key') is reply
        routed.assert_called_once_with('caller-token', tool, args, 'caller-key')


def test_no_session_creation_or_token_disclosure():
    with patch.object(gateway, 'start_session') as start:
        adapter = QwenWorkAdapter('private-token')
        assert 'private-token' not in repr(adapter)
        assert adapter.label == 'stand-in'
        assert adapter.live_status == 'waiting for key'
        start.assert_not_called()


def test_missing_key_is_not_invented():
    with patch.object(gateway, 'handle_call', return_value={'verdict': 'block'}) as routed:
        QwenWorkAdapter('caller-token').call('send_email', {})
        routed.assert_called_once_with('caller-token', 'send_email', {}, None)


def test_exception_fails_closed_without_private_error():
    with patch.object(gateway, 'handle_call', side_effect=RuntimeError('private-token')):
        out = QwenWorkAdapter('private-token')('list_inbox', {})
    assert out['verdict'] == 'block'
    assert 'private-token' not in str(out)
    assert 'result' not in out


def test_allowed_read_matches_builtin():
    _, session = make_session()
    args = {'doc_id': 'doc_acme_q3'}
    direct = gateway.handle_call(session['token'], 'read_file', args)
    out = QwenWorkAdapter(session['token'])('read_file', args)
    assert out['verdict'] == direct['verdict'] == 'allow'
    assert out['result'] == direct['result']
    assert out['action_id']


def test_attack_is_blocked_without_send():
    rid, session = make_session()
    args = {'to': 'ivy@boreal.example', 'subject': 'report',
            'body': 'Attached', 'attachment_ids': ['doc_acme_q3']}
    out = QwenWorkAdapter(session['token'])('send_email', args, 'adapter-attack')
    assert out['verdict'] == 'block'
    assert any(r['rule'] == 'R-OWNER' for r in out['reasons'])
    assert not gateway.get_world(rid).sent


def test_retry_and_missing_key_preserve_gateway_guarantees():
    rid, session = make_session()
    adapter = QwenWorkAdapter(session['token'])
    args = {'to': 'rosa@acme.example', 'subject': 'hello', 'body': 'hello'}
    assert adapter('send_email', args)['verdict'] == 'block'
    first = adapter('send_email', args, 'adapter-once')
    second = adapter('send_email', args, 'adapter-once')
    assert first['verdict'] == second['verdict'] == 'allow'
    assert first['action_id'] == second['action_id']
    assert len(gateway.get_world(rid).sent) == 1


def test_invalid_token_is_blocked():
    assert QwenWorkAdapter('not-a-session')('list_inbox', {})['verdict'] == 'block'
