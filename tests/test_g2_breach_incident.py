"""G2 persistence and authentication through existing APIs."""
from datetime import datetime, timezone
import importlib
import threading

import pytest
from aegis import auth, audit, db, evidence, incident_store


@pytest.fixture
def session():
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    login = auth.login('dana', 'demo-dana-2026')
    yield login
    auth.logout(login['token'])
    db.conn().execute("UPDATE users SET must_change=1 WHERE username IN ('dana','ops','audi')")
    db.conn().commit()


def adapter():
    return importlib.import_module('aegis.breach_incident')


def test_INCIDENT02_creation_rechecks_session_in_transaction(session, monkeypatch):
    api = adapter()
    original = api._human
    checks = []
    def human(*args, **kwargs):
        checks.append(db.conn().in_transaction)
        if db.conn().in_transaction:
            raise PermissionError('session revoked')
        return original(*args, **kwargs)
    before = [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')]
    monkeypatch.setattr(api, '_human', human)
    with pytest.raises(PermissionError, match='session revoked'):
        api.create_incident(session['token'], session['csrf'], title='refused')
    assert checks == [False, True]
    assert not db.conn().in_transaction
    assert [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')] == before


@pytest.mark.parametrize('operation', ['append', 'complete'])
def test_revoked_before_transaction(session, monkeypatch, operation):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='review',
        awareness_at=0, human_awareness=True)['id']
    original = incident_store.append_validated
    def revoked(*args, **kwargs):
        auth.logout(session['token'])
        return original(*args, **kwargs)
    monkeypatch.setattr(incident_store, 'append_validated', revoked)
    before = incident_store.get_incident(session['user'], iid)
    receipts = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(PermissionError):
        if operation == 'append':
            api.add_step(session['token'], session['csrf'], iid, step='refused')
        else:
            api.complete_assessment(session['token'], session['csrf'], iid,
                reason='refused', completed_at=100, human_confirmed=True)
    assert incident_store.get_incident(session['user'], iid) == before
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == receipts
    assert not db.conn().in_transaction


def test_notifiable_completed(session):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='determined',
        awareness_at=0, human_awareness=True, determination_at=100,
        human_determination=True)['id']
    clock = api.get_incident(session['token'], iid)
    assert clock.assessment.status == 'completed'
    assert clock.assessment.days_remaining is None
    assert clock.assessment.deadline_date.isoformat() == '1970-01-31'
    assert clock.notification.deadline_date.isoformat() == '1970-01-04'


def test_huge_epoch_sanitized():
    with pytest.raises(ValueError, match='supported reminder range'):
        adapter()._at(10**1000)


def test_explicit_completion(session):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='review',
        awareness_at=0, human_awareness=True)['id']
    for reason in ('', '  '):
        with pytest.raises(ValueError):
            api.complete_assessment(session['token'], session['csrf'], iid,
                reason=reason, completed_at=86400, human_confirmed=True)
    api.complete_assessment(session['token'], session['csrf'], iid,
        reason='Owner decision', completed_at=86400, human_confirmed=True)
    got = importlib.reload(api).get_incident(session['token'], iid)
    assert got.assessment.status == 'completed'
    assert got.assessment.deadline_date.isoformat() == '1970-01-31'
    assert got.notification.status == 'not_required'
    with pytest.raises(ValueError):
        api.add_step(session['token'], session['csrf'], iid, step='conflict',
            determination_at=86400, human_determination=True)


@pytest.mark.parametrize('receipt', [None, 1])
def test_direct_storage_completion_forgery(session, receipt):
    import json
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='forgery',
        awareness_at=0, human_awareness=True)['id']
    value = dict(schema='aegis.g2.completion.v1', outcome='not_notifiable',
                 actor_id=session['user']['id'], reason='Forged decision',
                 completed_at=86400, human_confirmed=True)
    if receipt is not None:
        value['receipt_id'] = receipt
    incident_store.add_step(session['user'], iid, step=json.dumps(value), timestamp=86400)
    with pytest.raises((ValueError, incident_store.IncidentIntegrityError)):
        api.get_incident(session['token'], iid)


@pytest.mark.parametrize('determination, completed, deadline', [
    ('2026-01-31T23:59:00+08:00', '2026-02-01T00:00:00+08:00', '2026-02-03'),
    ('2024-02-29T23:59:00+08:00', '2024-03-01T00:00:00+08:00', '2024-03-03')])
def test_completion_stops_prior_notification(session, determination, completed, deadline):
    api = adapter()
    d = datetime.fromisoformat(determination).timestamp()
    c = datetime.fromisoformat(completed).timestamp()
    iid = api.create_incident(session['token'], session['csrf'], title='prior clock',
        awareness_at=d - 86400, human_awareness=True,
        determination_at=d, human_determination=True)['id']
    before = incident_store.get_incident(session['user'], iid)
    with pytest.raises(ValueError):
        api.complete_assessment(session['token'], session['csrf'], iid,
            reason='Too early', completed_at=d - 1, human_confirmed=True)
    api.complete_assessment(session['token'], session['csrf'], iid,
        reason='Explicit later decision', completed_at=c, human_confirmed=True)
    got = importlib.reload(api).get_incident(session['token'], iid)
    assert got.notification.status == 'not_required'
    assert got.notification.deadline_date.isoformat() == deadline
    after = incident_store.get_incident(session['user'], iid)
    assert after['determination_at'] == before['determination_at']
    assert len(after['steps']) == 1


def test_completion_determination_race(session, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='race',
        awareness_at=0, human_awareness=True)['id']
    entered = threading.Event()
    contender = threading.Event()
    original = incident_store.add_step

    def append(*args, **kwargs):
        assert audit._LOCK._is_owned()
        if 'aegis.g2.completion.v1' in kwargs['step']:
            entered.set()
            assert contender.wait(2)
        return original(*args, **kwargs)

    monkeypatch.setattr(incident_store, 'add_step', append)
    def complete():
        return api.complete_assessment(session['token'], session['csrf'], iid,
            reason='Human final decision', completed_at=100, human_confirmed=True)
    def determine():
        contender.set()
        with pytest.raises(ValueError, match='terminal'):
            api.add_step(session['token'], session['csrf'], iid, step='notifiable',
                determination_at=200, human_determination=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(complete)
        assert entered.wait(2)
        other = pool.submit(determine)
        first.result(timeout=5)
        other.result(timeout=5)
    assert api.get_incident(session['token'], iid).notification.status == 'not_required'
    assert len(incident_store.get_incident(session['user'], iid)['steps']) == 1


def test_completion_audit_failure_refuses(session, monkeypatch):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='audit failure',
        awareness_at=0, human_awareness=True)['id']
    original = audit.record
    def record(*args, **kwargs):
        receipt = original(*args, **kwargs)
        monkeypatch.setattr(audit, 'verify', lambda: {'ok': False})
        return receipt
    monkeypatch.setattr(audit, 'record', record)
    with pytest.raises(incident_store.IncidentIntegrityError):
        api.complete_assessment(session['token'], session['csrf'], iid,
            reason='Explicit human decision', completed_at=100, human_confirmed=True)
    assert db.conn().execute('SELECT COUNT(*) FROM incident_steps WHERE incident_id=?', (iid,)).fetchone()[0] == 0


def test_reserved_completion_text(session):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='review')['id']
    api.add_step(session['token'], session['csrf'], iid, step='assessed as not notifiable')
    assert api.get_incident(session['token'], iid).assessment.status == 'unknown'
    with pytest.raises(ValueError):
        api.add_step(session['token'], session['csrf'], iid,
            step='{"schema":"aegis.g2.completion.v1"}')


def test_restart_projection_and_encryption(session):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='private G2',
        awareness_at=0, human_awareness=True, facts={'count': 500, 'harm': False})['id']
    api.add_step(session['token'], session['csrf'], iid, step='private check',
        timestamp=20, facts={'data': ['private category']})
    assert api.get_incident(session['token'], iid).notification.deadline_date is None
    api.add_step(session['token'], session['csrf'], iid, step='owner decision',
        timestamp=0, determination_at=86400, human_determination=True)
    db.conn().close()
    db._local.conn = None
    api = importlib.reload(api)
    got = api.get_incident(session['token'], iid, now=datetime(1970, 1, 3, tzinfo=timezone.utc))
    assert got.assessment.deadline_date.isoformat() == '1970-01-31'
    assert got.notification.deadline_date.isoformat() == '1970-01-05'
    assert [r.step for r in got.records] == ['private G2', 'private check', 'owner decision']
    assert got.records[0].facts == (('count', 500), ('harm', False))
    assert got.records[1].facts == (('data', ('private category',)),)
    assert got.records[0].actor == str(session['user']['id'])
    assert got.notice == 'reminder, not legal advice'
    for table in ('incidents', 'incident_steps'):
        for row in db.conn().execute(f'SELECT payload FROM {table} WHERE incident_id=?', (iid,)):
            assert row[0].startswith(evidence.PREFIX)
            assert 'private' not in row[0]
    assert audit.verify()['ok']


def test_append_confirmation_not_inference(session):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='facts only',
        facts={'count': 500, 'harm': True})['id']
    assert api.get_incident(session['token'], iid).notification.status == 'unknown'
    for epoch in (0, 0):
        api.add_step(session['token'], session['csrf'], iid, step='grounds',
            awareness_at=epoch, human_awareness=True)
    api.add_step(session['token'], session['csrf'], iid, step='ordinary step')
    got = api.get_incident(session['token'], iid)
    assert got.assessment.deadline_date.isoformat() == '1970-01-31'
    assert got.notification.deadline_date is None
    assert len(incident_store.get_incident(session['user'], iid)['steps']) == 3


def test_auth_csrf_and_password_gate(session):
    api = adapter()
    before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    for token, csrf in [('', session['csrf']), ('helper-token', session['csrf']),
                        (session['token'], 'wrong')]:
        with pytest.raises(PermissionError):
            api.create_incident(token, csrf, title='refused')
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
    iid = api.create_incident(session['token'], session['csrf'], title='restricted')['id']
    db.conn().execute("UPDATE users SET must_change=1 WHERE username='dana'")
    db.conn().commit()
    with pytest.raises(PermissionError):
        api.get_incident(session['token'], iid)
    auth.logout(session['token'])
    with pytest.raises(PermissionError):
        api.get_incident(session['token'], iid)


@pytest.mark.parametrize('username', ['ops', 'audi'])
def test_read_roles_not_writers(session, username):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='readable')['id']
    db.conn().execute('UPDATE users SET must_change=0 WHERE username=?', (username,))
    db.conn().commit()
    login = auth.login(username, f'demo-{username}-2026')
    try:
        assert api.get_incident(login['token'], iid).notification.status == 'unknown'
        with pytest.raises(PermissionError):
            api.add_step(login['token'], login['csrf'], iid, step='refused')
    finally:
        auth.logout(login['token'])


@pytest.mark.parametrize('field', ['awareness_at', 'determination_at'])
def test_conflict_preserves_history(session, field):
    api = adapter()
    flag = 'human_awareness' if field == 'awareness_at' else 'human_determination'
    iid = api.create_incident(session['token'], session['csrf'], title='canonical',
        **dict(awareness_at=100, human_awareness=True, **(
            {'determination_at': 100, flag: True} if field == 'determination_at' else {})))['id']
    before = incident_store.get_incident(session['user'], iid)
    receipts = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(ValueError):
        api.add_step(session['token'], session['csrf'], iid, step='reset',
            **{field: 200, flag: True})
    assert incident_store.get_incident(session['user'], iid) == before
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == receipts
    incident_store.add_step(session['user'], iid, step='legacy conflict',
        **{field: 200, flag: True})
    with pytest.raises(ValueError):
        api.get_incident(session['token'], iid)


@pytest.mark.parametrize('kwargs', [
    {'awareness_at': 1e20, 'human_awareness': True},
    {'determination_at': 1e20, 'human_determination': True},
    {'timestamp': 1e20},
    {'awareness_at': 200, 'human_awareness': True,
     'determination_at': 100, 'human_determination': True},
])
def test_invalid_epochs_write_and_projection(session, kwargs):
    api = adapter()
    before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(ValueError):
        api.create_incident(session['token'], session['csrf'], title='invalid', **kwargs)
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
    iid = incident_store.create_incident(session['user'], title='legacy', **kwargs)['id']
    with pytest.raises(ValueError):
        api.get_incident(session['token'], iid)


@pytest.mark.parametrize('field', ['awareness_at', 'determination_at'])
def test_future_trigger_and_step_chronology(session, field):
    api = adapter()
    flag = 'human_awareness' if field == 'awareness_at' else 'human_determination'
    future = datetime.now(timezone.utc).timestamp() + 86400
    with pytest.raises(ValueError):
        api.create_incident(session['token'], session['csrf'], title='future',
            **{field: future, flag: True})
    iid = incident_store.create_incident(session['user'], title='legacy future',
        **{field: future, flag: True})['id']
    with pytest.raises(ValueError):
        api.get_incident(session['token'], iid)
    iid = api.create_incident(session['token'], session['csrf'], title='grounds',
        awareness_at=200, human_awareness=True)['id']
    with pytest.raises(ValueError):
        api.add_step(session['token'], session['csrf'], iid, step='early decision',
            determination_at=100, human_determination=True)
    incident_store.add_step(session['user'], iid, step='legacy early',
        determination_at=100, human_determination=True)
    with pytest.raises(ValueError):
        api.get_incident(session['token'], iid)


def test_determination_requires_grounds_and_future_step_refused(session):
    api = adapter()
    for kwargs in ({'determination_at': 100, 'human_determination': True},
                   {'timestamp': datetime.now(timezone.utc).timestamp() + 86400}):
        before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        with pytest.raises(ValueError):
            api.create_incident(session['token'], session['csrf'], title='no', **kwargs)
        assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
        iid = incident_store.create_incident(session['user'], title='legacy', **kwargs)['id']
        with pytest.raises(ValueError):
            api.get_incident(session['token'], iid)
        iid = api.create_incident(session['token'], session['csrf'], title='empty')['id']
        with pytest.raises(ValueError):
            api.add_step(session['token'], session['csrf'], iid, step='no', **kwargs)
        assert incident_store.get_incident(session['user'], iid)['steps'] == []


def test_read_validation_append_holds_shared_reentrant_lock(session, monkeypatch):
    api = adapter()
    iid = api.create_incident(session['token'], session['csrf'], title='race')['id']
    original = incident_store.get_incident
    attempted = threading.Event()
    acquired = threading.Event()
    outcomes = []

    def screen_writer():
        try:
            attempted.set()
            with audit._LOCK:
                acquired.set()
                stored = original(session['user'], iid)
                if any(row['human_awareness'] for row in (stored, *stored['steps'])):
                    outcomes.append('conflict refused')
                else:
                    incident_store.add_step(session['user'], iid, step='screen',
                        awareness_at=200, human_awareness=True)
                    outcomes.append('screen appended')
        finally:
            db.conn().close()
            db._local.conn = None

    worker = threading.Thread(target=screen_writer)
    first = True
    def paused_read(user, incident_id):
        nonlocal first
        stored = original(user, incident_id)
        if threading.current_thread() is threading.main_thread() and first:
            first = False
            worker.start()
            assert attempted.wait(2)
            # Probe lock ownership at the exact stale-snapshot boundary.
            assert not acquired.wait(0.1), 'competing writer entered validation gap'
        return stored

    monkeypatch.setattr(incident_store, 'get_incident', paused_read)
    try:
        api.add_step(session['token'], session['csrf'], iid, step='adapter',
            awareness_at=100, human_awareness=True)
    finally:
        worker.join(3)
    assert not worker.is_alive()
    assert outcomes == ['conflict refused']
    assert [r['step'] for r in original(session['user'], iid)['steps']] == ['adapter']
    assert audit.verify()['ok']


def test_invalid_claim_and_integrity_failure(session, monkeypatch):
    api = adapter()
    before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(ValueError):
        api.create_incident(session['token'], session['csrf'], title='no', awareness_at=0)
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
    iid = api.create_incident(session['token'], session['csrf'], title='existing')['id']
    monkeypatch.setattr(audit, 'verify', lambda: {'ok': False})
    with pytest.raises(incident_store.IncidentIntegrityError):
        api.get_incident(session['token'], iid)
    with pytest.raises(incident_store.IncidentIntegrityError):
        api.add_step(session['token'], session['csrf'], iid, step='no')
