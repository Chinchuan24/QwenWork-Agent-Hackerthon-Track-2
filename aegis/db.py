"""SQLite storage. The audit table refuses UPDATE and DELETE at the database level."""
import sqlite3
import threading
from . import config

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL,
  must_change INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS web_sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, mode TEXT NOT NULL, label TEXT NOT NULL,
  scenario TEXT, created_by TEXT, created_at REAL NOT NULL,
  finished INTEGER DEFAULT 0, summary TEXT
);
CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, token_hash TEXT NOT NULL,
  task_text TEXT NOT NULL, limits_json TEXT NOT NULL, limits_hash TEXT NOT NULL,
  created_by TEXT NOT NULL, frozen INTEGER DEFAULT 0, freeze_reason TEXT,
  reads_json TEXT NOT NULL DEFAULT '[]', suspicious INTEGER DEFAULT 0,
  refund_total REAL DEFAULT 0, send_total INTEGER DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool TEXT NOT NULL,
  args_json TEXT NOT NULL, args_hash TEXT NOT NULL, idem_key TEXT,
  verdict TEXT, reasons_json TEXT, status TEXT NOT NULL DEFAULT 'pending',
  result_json TEXT, created_at REAL NOT NULL, executed_at REAL,
  paid_amount REAL,
  UNIQUE(session_id, idem_key)
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, action_id TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  requested_at REAL NOT NULL, expires_at REAL NOT NULL,
  decided_by TEXT, decided_at REAL, claimed_at REAL, held_rules_json TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
  run_id TEXT, session_id TEXT, event TEXT NOT NULL, detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
CREATE TABLE IF NOT EXISTS policy_versions (
  version INTEGER PRIMARY KEY, content TEXT NOT NULL,
  activated_by TEXT NOT NULL, ts REAL NOT NULL, note TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, changed_by TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS idem_seen (
  session_id TEXT NOT NULL, key TEXT NOT NULL, action_id TEXT NOT NULL,
  PRIMARY KEY (session_id, key)
);
CREATE TABLE IF NOT EXISTS spend (
  id INTEGER PRIMARY KEY, ts REAL, model TEXT, tokens_in INTEGER,
  tokens_out INTEGER, est_usd REAL, mode TEXT
);
CREATE TABLE IF NOT EXISTS worker_usage (
  session_id TEXT PRIMARY KEY, calls INTEGER NOT NULL DEFAULT 0
);
"""


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(config.DB_PATH, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return c


def init_db():
    conn().executescript(SCHEMA)
    # additive migrations for databases created by earlier versions
    cols = [r["name"] for r in conn().execute("PRAGMA table_info(approvals)")]
    if "held_rules_json" not in cols:
        conn().execute("ALTER TABLE approvals ADD COLUMN held_rules_json TEXT")
    scols = [r["name"] for r in conn().execute("PRAGMA table_info(agent_sessions)")]
    if "exposed" not in scols:
        conn().execute("ALTER TABLE agent_sessions ADD COLUMN exposed INTEGER DEFAULT 0")
    if "exposures_json" not in scols:
        conn().execute("ALTER TABLE agent_sessions ADD COLUMN exposures_json TEXT NOT NULL DEFAULT '[]'")
    acols = [r["name"] for r in conn().execute("PRAGMA table_info(actions)")]
    if "paid_amount" not in acols:
        conn().execute("ALTER TABLE actions ADD COLUMN paid_amount REAL")
    conn().commit()
    if 'request_digest' not in acols:
        conn().execute('ALTER TABLE actions ADD COLUMN request_digest TEXT')


def get_setting(key: str, default: str = "") -> str:
    row = conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str, by: str, ts: float):
    if key in ('sandbox_tool_approvals', 'sandbox_tool_authority'):
        from . import audit
        with audit.publication_lock():
            conn().execute(
                'INSERT INTO settings(key,value,changed_by,ts) VALUES(?,?,?,?) '
                'ON CONFLICT(key) DO UPDATE SET value=excluded.value, changed_by=excluded.changed_by, ts=excluded.ts',
                (key, value, by, ts))
            conn().commit()
        return
    conn().execute(
        "INSERT INTO settings(key,value,changed_by,ts) VALUES(?,?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, changed_by=excluded.changed_by, ts=excluded.ts",
        (key, value, by, ts),
    )
    conn().commit()