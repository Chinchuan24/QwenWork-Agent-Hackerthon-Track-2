"""Real interpreter races against a paused authoritative history read."""
import json
import os
import selectors
import subprocess
import sys

import pytest

from aegis import audit, auth, breach_incident, db, evidence, incident_store

@pytest.mark.parametrize('failure', [False, RuntimeError('publication interrupted')])
def test_postcommit_failure_retains_history(monkeypatch, failure):
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    session = auth.login('dana', 'demo-dana-2026')
    try:
        iid = breach_incident.create_incident(session['token'], session['csrf'],
            title='publication', awareness_at=0, human_awareness=True)['id']
        original = audit.checkpoint
        def fail(**kwargs):
            if isinstance(failure, Exception):
                raise failure
            return failure
        monkeypatch.setattr(audit, 'checkpoint', fail)
        with pytest.raises((incident_store.IncidentIntegrityError, RuntimeError)):
            breach_incident.complete_assessment(session['token'], session['csrf'], iid,
                reason='Private retained decision', completed_at=100, human_confirmed=True)
        assert db.conn().in_transaction is False
        assert db._local.incident_receipts is None
        assert db.conn().execute('SELECT COUNT(*) FROM incident_steps WHERE incident_id=?',
                                 (iid,)).fetchone()[0] == 1
        assert audit.verify()['ok'] is False
        monkeypatch.setattr(audit, 'checkpoint', original)
        tail = db.conn().execute('SELECT MAX(id) FROM audit').fetchone()[0]
        assert original(through_id=tail - 1)
        assert original(through_id=tail)
        assert audit.verify()['ok']
        assert breach_incident.get_incident(session['token'], iid).assessment.status == 'completed'
    finally:
        auth.logout(session['token'])
        db.conn().execute("UPDATE users SET must_change=1 WHERE username='dana'")
        db.conn().commit()


@pytest.mark.parametrize('writer', ['record', 'record_decision'])
def test_mixed_writer_waits_for_incident_publication(writer):
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    session = auth.login('dana', 'demo-dana-2026')
    workers = []
    try:
        iid = breach_incident.create_incident(session['token'], session['csrf'],
            title='mixed publication', awareness_at=0, human_awareness=True)['id']
        before = db.conn().execute('SELECT MAX(id) FROM audit').fetchone()[0]
        script = r'''
import sys
from aegis import audit, breach_incident, db
if sys.argv[1] == 'incident':
    original = audit.checkpoint
    first = True
    def paused(**kwargs):
        global first
        if first:
            first = False
            assert not db.conn().in_transaction
            print('committed', flush=True)
            assert sys.stdin.readline().strip() == 'continue'
        return original(**kwargs)
    audit.checkpoint = paused
    breach_incident.complete_assessment(sys.argv[2], sys.argv[3], sys.argv[4],
        reason='mixed decision', completed_at=100, human_confirmed=True)
else:
    print('entering', flush=True)
    if sys.argv[1] == 'record':
        audit.record('mixed_normal_writer', {'private': 'normal'})
    else:
        assert audit.record_decision('mixed_normal_writer', {'private': 'normal'},
            trusted_ts=100.0)['checkpoint_ok']
print('published', flush=True)
'''
        def start(operation):
            worker = subprocess.Popen([sys.executable, '-u', '-c', script,
                operation, session['token'], session['csrf'], iid],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=os.environ.copy())
            workers.append(worker)
            return worker
        first = start('incident')
        assert line(first) == 'committed'
        second = start(writer)
        assert line(second) == 'entering'
        with selectors.DefaultSelector() as selector:
            selector.register(second.stdout, selectors.EVENT_READ)
            blocked = not selector.select(0.3)
        out1, err1 = first.communicate('continue\n', timeout=20)
        out2, err2 = second.communicate(timeout=20)
        assert blocked, 'normal writer published before incident receipts'
        assert first.returncode == second.returncode == 0, (err1, err2)
        assert out1.strip() == out2.strip() == 'published'
        verification = audit.verify()
        assert verification['ok'], verification
        anchors = [json.loads(value) for value in audit._ANCHOR_FILE.read_text().splitlines()]
        assert [a['body']['max_id'] for a in anchors if a['body']['max_id'] > before] == [
            before + 1, before + 2, before + 3]
        assert [a['body']['count'] for a in anchors] == list(range(1, len(anchors) + 1))
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.communicate('continue\n', timeout=20)
        auth.logout(session['token'])
        db.conn().execute("UPDATE users SET must_change=1 WHERE username='dana'")
        db.conn().commit()


def test_creation_refuses_caller_transaction():
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    session = auth.login('dana', 'demo-dana-2026')
    try:
        before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        db.conn().execute("INSERT INTO settings(key,value) VALUES('incident-sentinel','pending')")
        with pytest.raises(RuntimeError, match='existing transaction'):
            breach_incident.create_incident(session['token'], session['csrf'], title='refused')
        assert db.conn().in_transaction
        assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
        db.conn().rollback()
        assert db.conn().execute("SELECT value FROM settings WHERE key='incident-sentinel'").fetchone() is None
    finally:
        db.conn().rollback()
        auth.logout(session['token'])
        db.conn().execute("UPDATE users SET must_change=1 WHERE username='dana'")
        db.conn().commit()


WORKER = r'''
import json, sys
from aegis import breach_incident, incident_store
original = incident_store.get_incident
first = True
def read(*args, **kwargs):
    global first
    result = original(*args, **kwargs)
    if first and sys.argv[5] == 'pause':
        first = False
        print('ready', flush=True)
        assert sys.stdin.readline().strip() == 'continue'
    return result
incident_store.get_incident = read
append = incident_store.append_validated
def entering(*args, **kwargs):
    if sys.argv[5] != 'pause':
        print('entering', flush=True)
    return append(*args, **kwargs)
incident_store.append_validated = entering
print('started', flush=True)
assert sys.stdin.readline().strip() == 'start'
try:
    token, csrf, iid, operation = sys.argv[1:5]
    if operation == 'complete':
        breach_incident.complete_assessment(token, csrf, iid,
            reason='Private decision', completed_at=100, human_confirmed=True)
    else:
        breach_incident.add_step(token, csrf, iid, step='Private determination',
            determination_at=200, human_determination=True)
    print(json.dumps({'status': 'accepted'}), flush=True)
except ValueError as exc:
    print(json.dumps({'status': 'refused', 'reason': str(exc)}), flush=True)
'''


def line(process):
    # Text readline can buffer the next event beyond the selector's visibility.
    result = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            assert selector.select(15), 'worker did not reach synchronization point'
            char = os.read(process.stdout.fileno(), 1)
            assert char, 'worker closed stdout before synchronization point'
            if char == b'\n':
                return result.decode().strip()
            result.extend(char)


def test_worker_lines_do_not_read_ahead():
    worker = subprocess.Popen([sys.executable, '-u', '-c',
        "import sys; print('started\\nentering', flush=True); sys.stdin.readline()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        assert line(worker) == 'started'
        assert line(worker) == 'entering'
    finally:
        out, err = worker.communicate('continue\n', timeout=20)
    assert worker.returncode == 0, err
    assert out == ''


@pytest.mark.parametrize('contender', ['complete', 'determine'])
def test_competing_interpreters(contender):
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    session = auth.login('dana', 'demo-dana-2026')
    workers = []
    try:
        iid = breach_incident.create_incident(session['token'], session['csrf'],
            title='Private incident', awareness_at=0, human_awareness=True)['id']
        before = [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')]
        def start(operation, pause):
            worker = subprocess.Popen([sys.executable, '-u', '-c', WORKER,
                session['token'], session['csrf'], iid, operation, pause],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=os.environ.copy())
            workers.append(worker)
            assert line(worker) == 'started'
            worker.stdin.write('start\n')
            worker.stdin.flush()
            return worker
        first = start('complete', 'pause')
        assert line(first) == 'ready'
        second = start(contender, 'run')
        assert line(second) == 'entering'
        with selectors.DefaultSelector() as selector:
            selector.register(second.stdout, selectors.EVENT_READ)
            assert not selector.select(0.2), 'contender passed the validation boundary'
        # Release only after the other interpreter has entered the actual API.
        first_out, first_err = first.communicate('continue\n', timeout=20)
        second_out, second_err = second.communicate(timeout=20)
        assert first.returncode == 0, first_err
        assert second.returncode == 0, second_err
        assert json.loads(first_out)['status'] == 'accepted'
        assert json.loads(second_out)['status'] == 'refused'
        stored = incident_store.get_incident(session['user'], iid)
        assert len(stored['steps']) == 1
        assert breach_incident.get_incident(session['token'], iid).assessment.status == 'completed'
        rows = [tuple(row) for row in db.conn().execute('SELECT * FROM audit ORDER BY id')]
        assert rows[:len(before)] == before
        assert [row['event'] for row in db.conn().execute(
            'SELECT event FROM audit WHERE id>? ORDER BY id', (before[-1][0],))] == [
                'g2_assessment_completed', 'incident_step_added']
        assert db.conn().execute('SELECT payload FROM incident_steps WHERE incident_id=?',
            (iid,)).fetchone()[0].startswith(evidence.PREFIX)
        assert audit.verify()['ok']
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.communicate('continue\n', timeout=20)
        auth.logout(session['token'])
        db.conn().execute("UPDATE users SET must_change=1 WHERE username='dana'")
        db.conn().commit()
