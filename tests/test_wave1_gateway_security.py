"""Direct dispatch uncertainty and initial passport binding regressions."""
import uuid
import pytest
from aegis import db, gateway, policy
from conftest import make_session


@pytest.mark.parametrize('mode', ['off', 'enforce'])
def test_direct_totals_failure(reviewed_sandbox_tools, monkeypatch, mode):
    rid, helper = make_session('Send an internal fixture note.', mode=mode)
    monkeypatch.setattr(gateway, '_card_error', lambda *a, **k: None)
    monkeypatch.setattr(gateway, '_run_judges', lambda s, t, a, sig, w: {
        **sig, '_second_a': {'verdict': 'safe'}, '_second_b': {'verdict': 'safe'}})
    monkeypatch.setattr(policy, 'evaluate', lambda *a: [])
    original = gateway._update_totals
    def fail(*a, **k):
        original(*a, **k)
        raise RuntimeError('injected totals completion fault')
    monkeypatch.setattr(gateway, '_update_totals', fail)
    key = uuid.uuid4().hex
    args = {'to': 'dana@consulting.example', 'subject': 'Fixture', 'body': 'Fixture note.'}
    result = gateway.handle_call(helper['token'], 'send_email', args, key)
    assert result['verdict'] == 'block'
    assert len(gateway.get_world(rid).sent) == 1
    sess = db.conn().execute('SELECT * FROM agent_sessions WHERE id=?',
                             (helper['session_id'],)).fetchone()
    assert sess['send_total'] == 0
    assert sess['frozen'] == 1
    assert gateway.handle_call(helper['token'], 'send_email', args, key)['verdict'] == 'block'
    assert len(gateway.get_world(rid).sent) == 1


def test_direct_error_acknowledgement(reviewed_sandbox_tools, monkeypatch):
    _, helper = make_session('Order fixture supplies.', mode='off')
    monkeypatch.setattr(gateway, '_card_error', lambda *a, **k: None)
    monkeypatch.setattr(gateway, '_execute', lambda *a: {'error': 'completion not acknowledged'})
    result = gateway.handle_call(helper['token'], 'order_supplier',
                                 {'supplier': 'fixture', 'amount': 10}, uuid.uuid4().hex)
    assert result['verdict'] == 'block'
    row = db.conn().execute('SELECT status FROM actions WHERE session_id=?',
                            (helper['session_id'],)).fetchone()
    assert row['status'] == 'executing'


def test_passport_drift_cannot_mint_approval(reviewed_sandbox_tools, monkeypatch):
    _, helper = make_session('Send a fixture note.')
    monkeypatch.setattr(gateway, '_card_error', lambda *a, **k: None)
    state = gateway._passport_state('send_email')
    monkeypatch.setattr(gateway, '_passport_state', lambda *a: dict(state))
    def judges(s, t, a, sig, w):
        state['fingerprint'] = 'changed-during-judges'
        return sig
    monkeypatch.setattr(gateway, '_run_judges', judges)
    monkeypatch.setattr(policy, 'evaluate', lambda *a: [
        {'id': 'FIXTURE-HOLD', 'decision': 'hold', 'explain': 'Fixture review'}])
    result = gateway.handle_call(helper['token'], 'send_email', {
        'to': 'dana@consulting.example', 'subject': 'Fixture', 'body': 'Fixture'}, uuid.uuid4().hex)
    assert 'approval_id' not in result
    assert any(r['rule'] == 'HARD-PASSPORT' for r in result['reasons'])
    assert db.conn().execute('SELECT COUNT(*) FROM approvals ap JOIN actions a ON a.id=ap.action_id '
                            'WHERE a.session_id=?', (helper['session_id'],)).fetchone()[0] == 0
