import pytest

from aegis import auth, db


@pytest.mark.parametrize('operation', ['login', 'change'])
def test_stale_credentials_cannot_commit(monkeypatch, operation):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    username = 'race-stale-' + operation
    auth.create_user(username, 'old-password-123', 'viewer')
    verified, resume = threading.Event(), threading.Event()
    original = auth._verify_pw

    def verify(*args):
        result = original(*args)
        if threading.current_thread().name.startswith('stale'):
            verified.set()
            assert resume.wait(10)
        return result

    monkeypatch.setattr(auth, '_verify_pw', verify)
    with ThreadPoolExecutor(1, thread_name_prefix='stale') as pool:
        future = pool.submit(auth.login, username, 'old-password-123') if operation == 'login' else pool.submit(
            auth.change_password, username, 'old-password-123', 'loser-password-123')
        try:
            assert verified.wait(10)
            assert auth.change_password(username, 'old-password-123', 'winner-password-123')['ok']
        finally:
            resume.set()
        result = future.result(timeout=10)
    assert result is None if operation == 'login' else not result['ok']
    assert auth.login(username, 'winner-password-123') is not None


def test_throttle_admission_counts_inflight(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    username = 'race-admission'
    auth.create_user(username, 'old-password-123', 'viewer')
    entered = []
    lock = threading.Lock()
    ready, resume = threading.Event(), threading.Event()

    def verify(*args):
        with lock:
            entered.append(1)
            if len(entered) == auth.LOGIN_MAX_FAILS:
                ready.set()
        assert resume.wait(10)
        return False

    monkeypatch.setattr(auth, '_verify_pw', verify)
    monkeypatch.setattr(auth.audit, 'record', lambda *args, **kwargs: None)
    with ThreadPoolExecutor(8) as pool:
        futures = [pool.submit(auth.login, username, 'wrong') for _ in range(5)]
        try:
            assert ready.wait(10)
            extras = [pool.submit(auth.login, username, 'wrong') for _ in range(3)]
            assert all(f.result(timeout=2) is None for f in extras)
        finally:
            resume.set()
        assert all(f.result(timeout=10) is None for f in futures)
    assert len(entered) == auth.LOGIN_MAX_FAILS


def test_unknown_name_flood_does_not_block_real_account(monkeypatch):
    auth.create_user('flood-real', 'old-password-123', 'viewer')
    monkeypatch.setattr(auth, '_hash_pw', lambda *args: 'dummy')
    for i in range(4200):
        assert auth.login('flood-missing-' + str(i), 'wrong') is None
    assert auth.login('flood-real', 'old-password-123') is not None


@pytest.mark.parametrize("preserve", ["current", "foreign", "expired", "missing", "none"])
def test_password_change_revokes_other_sessions(preserve):
    username = "pw-revoke-" + preserve
    auth.create_user(username, "old-password-123", "viewer", must_change=1)
    current = auth.login(username, "old-password-123")
    other = auth.login(username, "old-password-123")
    auth.create_user(username + "-foreign", "foreign-password-123", "viewer")
    foreign = auth.login(username + "-foreign", "foreign-password-123")
    token = current["token"]
    if preserve == "expired":
        db.conn().execute("UPDATE web_sessions SET expires_at=0 WHERE token=?",
                          (auth._token_hash(token),))
        db.conn().commit()
    if preserve == "foreign":
        token = foreign["token"]
    elif preserve == "missing":
        token = "not-a-session"
    kwargs = {} if preserve == "none" else {"session_token": token}
    assert auth.change_password(username, "old-password-123", "new-password-456", **kwargs)["ok"]
    assert auth.user_by_token(other["token"]) is None
    kept = auth.user_by_token(current["token"])
    if preserve == "current":
        assert kept["must_change"] == 0
        assert auth.check_csrf(kept, current["csrf"])
    else:
        assert kept is None
    assert auth.user_by_token(foreign["token"]) is not None
    assert auth.login(username, "old-password-123") is None
    assert auth.login(username, "new-password-456") is not None


def test_failed_password_change_keeps_sessions():
    auth.create_user("pw-failure", "old-password-123", "viewer", must_change=1)
    sessions = [auth.login("pw-failure", "old-password-123") for _ in range(2)]
    for current, new in [("wrong", "new-password-456"),
                         ("old-password-123", "short"),
                         ("old-password-123", "old-password-123")]:
        assert not auth.change_password("pw-failure", current, new)["ok"]
        for session in sessions:
            assert auth.user_by_token(session["token"])["must_change"] == 1
