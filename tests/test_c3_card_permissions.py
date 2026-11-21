"""Helper-card permissions must constrain otherwise authorized email sends."""
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import approvals, db, gateway, qwen_client
from conftest import make_session
from test_c3_enforcement_review import call, save_card


def test_ask_only_send_holds_without_effects(monkeypatch):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    save_card(session, tools=["send_email"], alone=[], ask=["send_email"])
    w = gateway.get_world(rid)
    sink = Mock(wraps=w.send_email)
    monkeypatch.setattr(w, "send_email", sink)
    monkeypatch.setattr(qwen_client, "judge", lambda kind, payload, model=None: {
        "verdict": "yes" if kind == "intent" else "safe"
    })

    out = call(session, "send_email", dict(
        to="rosa@acme.example", subject="Hello", body="Hello"))

    total = db.conn().execute(
        "SELECT send_total FROM agent_sessions WHERE id=?",
        (session["session_id"],)).fetchone()["send_total"]
    assert (out["verdict"], sink.call_count, w.sent, total) == ("hold", 0, [], 0)
    assert out["approval_id"]
    action = db.conn().execute(
        "SELECT status, executed_at FROM actions WHERE id=?",
        (out["action_id"],)).fetchone()
    assert (action["status"], action["executed_at"]) == ("held", None)


def test_send_missing_from_tools_blocks_without_effects(monkeypatch):
    rid, session = make_session("Email Rosa at Acme a greeting.")
    save_card(session, tools=[], alone=[], ask=["send_email"])
    w = gateway.get_world(rid)
    sink = Mock(wraps=w.send_email)
    monkeypatch.setattr(w, "send_email", sink)

    out = call(session, "send_email", dict(
        to="rosa@acme.example", subject="Hello", body="Hello"))

    assert out["verdict"] == "block"
    assert any(reason["rule"] == "HARD-CARD" for reason in out["reasons"])
    sink.assert_not_called()
    assert w.sent == []
    total = db.conn().execute(
        "SELECT send_total FROM agent_sessions WHERE id=?",
        (session["session_id"],)).fetchone()["send_total"]
    assert total == 0


@pytest.mark.parametrize('mode', ['enforce', 'monitor', 'off'])
@pytest.mark.parametrize('permissions', [dict(alone=[], ask=[]), dict(alone=[]), dict(ask=[])])
def test_explicit_permissions_block_unlisted_tool(mode, permissions):
    _, session = make_session(mode=mode)
    save_card(session, **permissions)
    out = call(session, 'search_files', {'query': 'report'})
    assert out['verdict'] == 'block'
    assert any(r['rule'] == 'HARD-CARD' for r in out['reasons'])


@pytest.mark.parametrize('mode', ['enforce', 'monitor', 'off'])
@pytest.mark.parametrize('tool,args', [
    ('search_files', {'query': 'report'}),
    ('send_email', {'to': 'rosa@acme.example', 'subject': 'Hello', 'body': 'Hello'})])
def test_ask_floor_all_tools_and_modes(monkeypatch, mode, tool, args):
    _, session = make_session('Email Rosa at Acme a greeting.', mode=mode)
    save_card(session, alone=[tool], ask=[tool])
    sink = Mock(wraps=gateway._execute)
    monkeypatch.setattr(gateway, '_execute', sink)
    out = call(session, tool, args)
    assert out['verdict'] == 'hold'
    assert out['approval_id']
    sink.assert_not_called()
    row = db.conn().execute('SELECT status,executed_at FROM actions WHERE id=?',
                            (out['action_id'],)).fetchone()
    assert (row['status'], row['executed_at']) == ('held', None)


@pytest.mark.parametrize('mode', ['enforce', 'monitor', 'off'])
def test_legacy_absent_permissions_preserve_baseline(mode):
    _, session = make_session(mode=mode)
    save_card(session)
    assert call(session, 'search_files', {'query': 'report'})['verdict'] == 'allow'


@pytest.mark.parametrize('mode', ['enforce', 'monitor', 'off'])
def test_explicit_alone_allows_tool(mode):
    _, session = make_session(mode=mode)
    save_card(session, alone=['search_files'], ask=[])
    assert call(session, 'search_files', {'query': 'report'})['verdict'] == 'allow'


@pytest.mark.parametrize('release', [False, True])
def test_final_permission_membership_rechecked(monkeypatch, release):
    rid, session = make_session('Email Rosa at Acme a greeting.')
    save_card(session, alone=['send_email'], ask=[])
    args = dict(to='rosa@acme.example', subject='Hello', body='Hello')
    if release:
        save_card(session, alone=[], ask=['send_email'])
        out = call(session, 'send_email', args)
        assert out['verdict'] == 'hold'
    original = gateway._run_judges

    def revoke(*a, **kw):
        result = original(*a, **kw)
        save_card(session, alone=[], ask=[])
        return result

    monkeypatch.setattr(gateway, '_run_judges', revoke)
    if release:
        result = approvals.decide(out['approval_id'],
                                  dict(username='reviewer', role='approver'), 'approve')
        assert result['ok'] is False
    else:
        assert call(session, 'send_email', args)['verdict'] == 'block'
    assert gateway.get_world(rid).sent == []


def test_ask_read_can_release_once():
    _, session = make_session()
    save_card(session, alone=[], ask=['search_files'])
    out = call(session, 'search_files', {'query': 'report'})
    assert out['verdict'] == 'hold'
    user = dict(username='reviewer', role='approver')
    assert approvals.decide(out['approval_id'], user, 'approve')['ok'] is True
    assert approvals.decide(out['approval_id'], user, 'approve')['ok'] is False
