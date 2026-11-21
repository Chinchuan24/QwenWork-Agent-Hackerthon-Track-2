"""Logins, roles, CSRF protection. Passwords: PBKDF2-HMAC-SHA256, 600k rounds
(current guidance), stored with the iteration count so older hashes upgrade
transparently on login. Web-session tokens are stored HASHED. Login attempts
are throttled per account. Fixed demo passwords carry a forced-change flag.
Roles: admin, approver, auditor, viewer. Agent tokens are one-session and can
never start sessions or change tasks — those endpoints require a human login."""
import hashlib
import hmac
import json
import os
import secrets
import time
from . import db, audit

ROLES = {"admin", "approver", "auditor", "viewer"}
SESSION_TTL = 8 * 3600
ITERATIONS = 600_000
LEGACY_ITERATIONS = 200_000
LOGIN_MAX_FAILS = 5
LOGIN_FAIL_WINDOW_S = 900
class _FailureStore:
    """Account counters plus 256 shared unknown-name buckets, across workers."""

    def _key(self, username):
        known = db.conn().execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        digest = _token_hash(username)
        return "auth:fail:" + (digest if known else "unknown:" + str(int(digest[:8], 16) % 256))

    def get(self, username, default=None):
        now = time.time()
        row = db.conn().execute("SELECT value FROM settings WHERE key=?",
                                (self._key(username),)).fetchone()
        if row is not None:
            return json.loads(row['value'])
        return []

    def setdefault(self, username, default=None):
        return _FailureBucket(self, username)

    def pop(self, username, default=None):
        with db.conn() as connection:
            connection.execute("DELETE FROM settings WHERE key=?", (self._key(username),))

    def clear(self):
        with db.conn() as connection:
            connection.execute("DELETE FROM settings WHERE key LIKE 'auth:fail:%'")


class _FailureBucket:
    def __init__(self, store, username):
        self.store = store
        self.username = username

    def append(self, timestamp, admission=False):
        connection = db.conn()
        # Serialize read/modify/write across workers, not just Python threads.
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DELETE FROM settings WHERE key LIKE 'auth:fail:%' AND ts<=?",
                (timestamp - LOGIN_FAIL_WINDOW_S,))
            key = self.store._key(self.username)
            fails = [t for t in self.store.get(self.username)
                     if timestamp - t < LOGIN_FAIL_WINDOW_S]
            if admission and len(fails) >= LOGIN_MAX_FAILS:
                connection.commit()
                return False
            fails = (fails + [timestamp])[-LOGIN_MAX_FAILS:]
            connection.execute(
                "INSERT INTO settings(key,value,ts) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts",
                (self.store._key(self.username), json.dumps(fails), timestamp))
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise


_login_fails = _FailureStore()


def _hash_pw(password: str, salt: bytes, iterations: int = ITERATIONS) -> str:
    return f"pbkdf2:{iterations}:" + hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations).hex()


def _verify_pw(password: str, salt: bytes, stored: str) -> bool:
    if stored.startswith("pbkdf2:"):
        try:
            _, iters, digest = stored.split(":", 2)
            expect = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters)).hex()
            return hmac.compare_digest(expect, digest)
        except (ValueError, TypeError):
            return False
    # legacy bare-hex hash (200k rounds)
    expect = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, LEGACY_ITERATIONS).hex()
    return hmac.compare_digest(expect, stored)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(username: str, password: str, role: str, must_change: int = 0):
    if role not in ROLES:
        raise ValueError("unknown role")
    salt = os.urandom(16)
    db.conn().execute("INSERT INTO users(username,pw_hash,salt,role,must_change) VALUES(?,?,?,?,?)",
                      (username, _hash_pw(password, salt), salt.hex(), role, must_change))
    db.conn().commit()
    audit.record("user_created", {"username": username, "role": role,
                                  "must_change": bool(must_change)})


def ensure_demo_users():
    if db.conn().execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
        return
    # fixed demo passwords are openly printed in the README, so every demo
    # account must change its password before privileged actions
    create_user("dana", "demo-dana-2026", "admin", must_change=1)
    create_user("ops", "demo-ops-2026", "approver", must_change=1)
    create_user("audi", "demo-audi-2026", "auditor", must_change=1)


def _throttled(username: str) -> bool:
    now = time.time()
    fails = [t for t in _login_fails.get(username, []) if now - t < LOGIN_FAIL_WINDOW_S]
    return len(fails) >= LOGIN_MAX_FAILS


def login(username: str, password: str):
    if not _login_fails.setdefault(username, []).append(time.time(), admission=True):
        audit.record("login_throttled", {"username": username})
        return None
    row = db.conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if row is None:
        _hash_pw(password, b"dummy-salt-value")  # constant-ish time
        return None
    if not _verify_pw(password, bytes.fromhex(row["salt"]), row["pw_hash"]):
        audit.record("login_failed", {"username": username})
        return None
    upgrade = None
    if not row["pw_hash"].startswith(f"pbkdf2:{ITERATIONS}:"):
        salt = os.urandom(16)
        upgrade = (_hash_pw(password, salt), salt.hex(), row["id"])
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = time.time()
    connection = db.conn()
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        # The verified snapshot must still be authoritative at session issuance.
        live = connection.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
        if live is None or (live['pw_hash'], live['salt']) != (row['pw_hash'], row['salt']):
            return None
        connection.execute("DELETE FROM settings WHERE key=?", (_login_fails._key(username),))
        if upgrade:
            connection.execute("UPDATE users SET pw_hash=?, salt=? WHERE id=?", upgrade)
        connection.execute("INSERT INTO web_sessions(token,user_id,csrf,created_at,expires_at) "
                           "VALUES(?,?,?,?,?)", (_token_hash(token), row["id"], csrf, now, now + SESSION_TTL))
        row = connection.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
    audit.record("login", {"username": username})
    return {"token": token, "csrf": csrf, "user": dict(row)}


def change_password(username: str, current: str, new: str,
                    session_token: str = "") -> dict:
    """Change password and revoke sessions except the supplied live user session."""
    if len(new) < 10:
        return {"ok": False, "error": "Refused: the new password must be at least 10 characters"}
    if new == current:
        return {"ok": False, "error": "Refused: the new password must differ from the current one"}
    if not _login_fails.setdefault(username, []).append(time.time(), admission=True):
        audit.record("password_change_throttled", {"username": username})
        return {"ok": False, "error": "Refused: too many failed attempts; try again later"}
    row = db.conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if row is None or not _verify_pw(current, bytes.fromhex(row["salt"]), row["pw_hash"]):
        audit.record("password_change_failed", {"username": username})
        return {"ok": False, "error": "Refused: current password is wrong"}
    salt = os.urandom(16)
    password_hash = _hash_pw(new, salt)
    connection = db.conn()
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        live = connection.execute("SELECT pw_hash,salt FROM users WHERE id=?", (row['id'],)).fetchone()
        if live is None or (live['pw_hash'], live['salt']) != (row['pw_hash'], row['salt']):
            return {"ok": False, "error": "Refused: credentials changed; try again"}
        connection.execute("DELETE FROM settings WHERE key=?", (_login_fails._key(username),))
        connection.execute("UPDATE users SET pw_hash=?, salt=?, must_change=0 WHERE id=?",
                           (password_hash, salt.hex(), row["id"]))
        connection.execute(
            "DELETE FROM web_sessions WHERE user_id=? "
            "AND NOT (token=? AND expires_at>?)",
            (row["id"], _token_hash(session_token), time.time()))
    audit.record("password_changed", {"username": username, "via": "self-service"})
    return {"ok": True}


def user_by_token(token: str):
    if not token:
        return None
    row = db.conn().execute(
        "SELECT u.*, w.csrf, w.expires_at FROM web_sessions w JOIN users u ON w.user_id=u.id "
        "WHERE w.token=?", (_token_hash(token),)).fetchone()
    if row is None or time.time() > row["expires_at"]:
        return None
    return dict(row)


def check_csrf(user: dict, submitted: str) -> bool:
    return bool(submitted) and hmac.compare_digest(user["csrf"], submitted)


def logout(token: str):
    db.conn().execute("DELETE FROM web_sessions WHERE token=?", (_token_hash(token),))
    db.conn().commit()


def require_role(user, *roles) -> bool:
    return user is not None and user["role"] in roles


def list_users() -> list:
    return [dict(r) for r in db.conn().execute(
        "SELECT id, username, role, must_change FROM users ORDER BY id").fetchall()]