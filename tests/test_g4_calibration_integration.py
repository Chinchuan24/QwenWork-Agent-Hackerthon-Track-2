import pytest
from aegis import db, gateway
from conftest import make_session


def sample():
    rid, session = make_session()
    assert gateway.handle_call(session['token'], 'list_inbox', {})['verdict'] == 'allow'
    db.conn().execute('UPDATE runs SET finished=1 WHERE id=?', (rid,))
    db.conn().commit()
    return rid, session


def test_actual_observation_unknown(reviewed14_sandbox_tools):
    rid, session = sample()
    events = gateway.helper_observations([rid])
    assert len(events) == 1
    assert events[0]['helper'] == session['session_id']
    assert events[0]['timestamp'].utcoffset() is not None
    assert events[0]['refused'] is False
    assert events[0]['tool'] == 'list_inbox'
    assert gateway.helper_baseline(session['session_id']) is None


def test_actual_reviewed_immutable_and_trigger(reviewed14_sandbox_tools):
    rid, source = sample()
    _, target = make_session()
    baseline = gateway.calibrate_helper_baseline(target['session_id'], [rid],
        reviewer={'username': 'dana', 'role': 'admin'}, review_note='Reviewed isolated normal sample')
    assert baseline['daily'][target['session_id']]['total_actions'] == 1
    assert baseline['minute'][target['session_id']]['tools']['list_inbox'] == 1
    with pytest.raises(Exception):
        db.conn().execute('UPDATE helper_baselines SET content=?', ('{}',))
    db.conn().rollback()
    for _ in range(19):
        assert gateway.handle_call(target['token'], 'list_inbox', {})['verdict'] == 'allow'
    out = gateway.handle_call(target['token'], 'list_inbox', {})
    assert out['verdict'] == 'block'
    assert out['reasons'][0]['rule'] == 'HARD-G4'
    assert gateway._load_card(target['session_id'])['frozen'] is True
    assert gateway.helper_baseline(target['session_id']) == baseline
    assert gateway.handle_call(source['token'], 'list_inbox', {})['verdict'] == 'allow'


def test_reject_monitor_and_fake_review(reviewed14_sandbox_tools):
    rid, target = make_session(mode='monitor')
    for reviewer, error in [({'username': 'agent', 'role': 'admin'}, PermissionError),
                            ({'username': 'dana', 'role': 'admin'}, ValueError)]:
        with pytest.raises(error):
            gateway.calibrate_helper_baseline(target['session_id'], [rid],
                reviewer=reviewer, review_note='review')


def test_actual_refusals_freeze_unknown(reviewed14_sandbox_tools):
    _, target = make_session()
    for _ in range(5):
        assert gateway.handle_call(target['token'], 'not_a_tool', {})['verdict'] == 'block'
    out = gateway.handle_call(target['token'], 'list_inbox', {})
    assert out['verdict'] == 'block'
    assert gateway._load_card(target['session_id'])['frozen'] is True
