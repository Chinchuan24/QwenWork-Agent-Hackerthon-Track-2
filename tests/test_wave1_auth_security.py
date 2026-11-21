import json
import multiprocessing

from aegis import auth, db


def _worker_throttled(username, queue):
    if getattr(db._local, 'conn', None):
        db._local.conn.close()
        db._local.conn = None
    if isinstance(auth._login_fails, dict):
        auth._login_fails.clear()
    queue.put(auth._throttled(username))


def test_AUTH02_password_change_throttled(monkeypatch):
    auth.create_user('auth02-change', 'old-password-123', 'viewer')
    session = auth.login('auth02-change', 'old-password-123')
    for _ in range(auth.LOGIN_MAX_FAILS):
        assert not auth.change_password('auth02-change', 'wrong', 'new-password-456')['ok']
    assert not auth.change_password('auth02-change', 'old-password-123',
                                    'new-password-456', session['token'])['ok']
    assert auth.user_by_token(session['token']) is not None
    now = auth.time.time()
    monkeypatch.setattr(auth.time, 'time', lambda: now + auth.LOGIN_FAIL_WINDOW_S + 1)
    assert auth.change_password('auth02-change', 'old-password-123',
                                'new-password-456', session['token'])['ok']


def test_AUTH02_failures_shared_between_processes():
    for _ in range(auth.LOGIN_MAX_FAILS):
        auth._login_fails.setdefault('auth02-shared', []).append(auth.time.time())
    ctx = multiprocessing.get_context('fork')
    queue = ctx.Queue()
    process = ctx.Process(target=_worker_throttled, args=('auth02-shared', queue))
    process.start()
    try:
        assert queue.get(timeout=10) is True
    finally:
        process.join(timeout=10)
    assert process.exitcode == 0


def test_AUTH02_failure_storage_bounded(monkeypatch):
    monkeypatch.setattr(auth, '_hash_pw', lambda *args: 'dummy')
    for i in range(4200):
        assert auth.login('auth02-missing-' + str(i), 'wrong') is None
    assert not isinstance(auth._login_fails, dict)
    rows = db.conn().execute("SELECT value FROM settings WHERE key LIKE 'auth:fail:%'").fetchall()
    assert len(rows) <= 256
    assert all(len(json.loads(row['value'])) <= auth.LOGIN_MAX_FAILS for row in rows)
    auth.create_user('auth02-capacity-new', 'old-password-123', 'viewer')
    assert not auth._throttled('auth02-capacity-new')
    now = auth.time.time()
    monkeypatch.setattr(auth.time, 'time', lambda: now + auth.LOGIN_FAIL_WINDOW_S + 1)
    assert not auth._throttled('auth02-capacity-new')
    auth._login_fails.setdefault('auth02-capacity-new', []).append(auth.time.time())
    assert db.conn().execute(
        "SELECT COUNT(*) FROM settings WHERE key LIKE 'auth:fail:%'"
    ).fetchone()[0] == 1
