"""R4 — encryption of stored evidence at rest.

Sensitive stored content (action arguments/results/reasons, read records,
exposure snapshots, run summaries, audit detail, replay responses) is
encrypted with AES-256-GCM BEFORE it touches SQLite, so database files, WAL
files, backups and temp copies only ever hold ciphertext.

The key comes from AEGIS_EVIDENCE_KEY (base64url, 32 bytes) or
AEGIS_EVIDENCE_KEY_FILE — never stored next to the data. With no key the app
refuses to start (enforce mode especially) and says why. A wrong key fails
the startup probe safely. New records include an authenticated key ID.
Rotation retains historical keys in an external read-only keyring and changes
only the current env/file key; stored evidence and audit receipts are untouched.
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, db

PREFIX = "enc:v2:"
LEGACY_PREFIX = "enc:v1:"
_key_cache = None


class EvidenceKeyError(RuntimeError):
    pass


def _load_key():
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    raw = config.AEGIS_EVIDENCE_KEY
    if not raw and config.AEGIS_EVIDENCE_KEY_FILE:
        try:
            p = Path(config.AEGIS_EVIDENCE_KEY_FILE).resolve(strict=True)
            if p.is_relative_to(Path(config.DATA_DIR).resolve()):
                raise EvidenceKeyError("the evidence key file must live OUTSIDE the data folder")
            raw = p.read_text().strip()
        except EvidenceKeyError:
            raise
        except Exception:
            raise EvidenceKeyError("the evidence key file cannot be loaded") from None
    if not raw:
        return None
    try:
        key = base64.urlsafe_b64decode(raw.encode())
    except Exception:
        raise EvidenceKeyError("AEGIS_EVIDENCE_KEY must be base64url-encoded 32 bytes") from None
    if len(key) != 32:
        raise EvidenceKeyError("AEGIS_EVIDENCE_KEY must decode to exactly 32 bytes")
    _key_cache = key
    return key


def available() -> bool:
    return _load_key() is not None


def enc(text):
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if text.startswith((PREFIX, LEGACY_PREFIX)):
        return text
    return enc_plaintext(text)


def enc_plaintext(text):
    """Encrypt caller plaintext even when it resembles an evidence envelope."""
    if text is None:
        return None
    key = _load_key()
    if key is None:
        raise EvidenceKeyError("no evidence encryption key set; refusing to store clear text")
    nonce = os.urandom(12)
    key_id = hashlib.sha256(key).hexdigest()[:32]
    header = PREFIX + key_id + ":"
    ct = AESGCM(key).encrypt(nonce, text.encode(), header.encode())
    return header + (nonce + ct).hex()


def dec(text):
    if text is None or not isinstance(text, str) or not text.startswith((PREFIX, LEGACY_PREFIX)):
        return text   # legacy clear row (pre-migration) passes through
    if text.startswith(PREFIX) and ":" in text[len(PREFIX):]:
        try:
            key_id, encoded = text[len(PREFIX):].split(":", 1)
            if len(key_id) != 32 or any(c not in "0123456789abcdef" for c in key_id):
                raise ValueError("invalid key ID")
            key = _load_key()
            if key is None or hashlib.sha256(key).hexdigest()[:32] != key_id:
                key = None
                if config.AEGIS_EVIDENCE_KEYRING_FILE:
                    path = Path(config.AEGIS_EVIDENCE_KEYRING_FILE).resolve()
                    if path.is_relative_to(Path(config.DATA_DIR).resolve()):
                        raise ValueError("unsafe keyring location")
                    # Missing historical keys fail closed; never try the current key.
                    raw = json.loads(path.read_text())["keys"][key_id]
                    key = base64.b64decode(raw.encode(), altchars=b"-_", validate=True)
                    if len(key) != 32 or hashlib.sha256(key).hexdigest()[:32] != key_id:
                        raise ValueError("invalid historical key")
            if key is None:
                raise ValueError("missing key")
            blob = bytes.fromhex(encoded)
            header = PREFIX + key_id + ":"
            return AESGCM(key).decrypt(blob[:12], blob[12:], header.encode()).decode()
        except Exception:
            raise EvidenceKeyError("stored evidence cannot be decrypted") from None
    try:
        key = _load_key()
        if key is None:
            raise EvidenceKeyError("no evidence encryption key set; cannot decrypt stored evidence")
        if text.startswith(PREFIX):
            blob = bytes.fromhex(text[len(PREFIX):])
        else:
            blob = base64.urlsafe_b64decode(text[len(LEGACY_PREFIX):].encode())
        try:
            return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()
        except InvalidTag:
            pass
        # Only ID-less envelopes may try retained keys; GCM authenticates each trial.
        if config.AEGIS_EVIDENCE_KEYRING_FILE:
            path = Path(config.AEGIS_EVIDENCE_KEYRING_FILE).resolve(strict=True)
            if path.is_relative_to(Path(config.DATA_DIR).resolve()):
                raise ValueError("unsafe keyring location")
            retained = json.loads(path.read_text())["keys"]
            for key_id, raw in retained.items():
                historical = base64.b64decode(raw.encode(), altchars=b"-_", validate=True)
                if len(historical) != 32 or hashlib.sha256(historical).hexdigest()[:32] != key_id:
                    raise ValueError("invalid historical key")
                try:
                    return AESGCM(historical).decrypt(blob[:12], blob[12:], None).decode()
                except InvalidTag:
                    continue
        raise ValueError("missing legacy key")
    except Exception:
        raise EvidenceKeyError("stored evidence cannot be decrypted") from None


def enc_json(obj) -> str:
    return enc(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str))


def dec_json(text):
    v = dec(text)
    if v is None:
        return None
    return json.loads(v) if isinstance(v, str) else v


def probe() -> bool:
    """Encrypt/decrypt round-trip against a stored marker. A wrong key fails here."""
    if _load_key() is None:
        raise EvidenceKeyError("no evidence encryption key set")
    stored = db.get_setting("evidence_probe", "")
    if not stored:
        db.set_setting("evidence_probe", enc("aegis-evidence-probe"), "system", time.time())
        return True
    try:
        ok = dec(stored) == "aegis-evidence-probe"
    except EvidenceKeyError:
        raise
    except Exception as e:
        raise EvidenceKeyError(f"wrong evidence key (or corrupted probe): {type(e).__name__}")
    if not ok:
        raise EvidenceKeyError("wrong evidence key: stored probe does not decrypt")
    return True


def require_key_for_startup():
    mode = db.get_setting("default_mode", "enforce")
    if not available():
        raise EvidenceKeyError(
            f"refusing to start (default mode: {mode}): no evidence encryption key. "
            "Set AEGIS_EVIDENCE_KEY (base64url 32 bytes) or AEGIS_EVIDENCE_KEY_FILE "
            "outside the data folder. Stored evidence must never be written in clear text.")
    probe()
    # Fixed inventory only: never rewrite ciphertext, receipts, or schema here.
    c = db.conn()
    for table, columns in (
            ("actions", ("args_json", "result_json", "reasons_json")),
            ("agent_sessions", ("reads_json", "exposures_json")),
            ("runs", ("summary",)), ("audit", ("detail_json",)),
            ("approvals", ("reason",)), ("helper_cards", ("content",)),
            ("helper_baselines", ("content",)),
            ("incidents", ("payload",)), ("incident_steps", ("payload",))):
        present = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
        for column in columns:
            if column not in present:
                continue
            for row in c.execute(f"SELECT {column} FROM {table}"):
                value = row[0]
                if isinstance(value, str) and value.startswith((PREFIX, LEGACY_PREFIX)):
                    dec(value)


def migrate_once():
    """One-time encryption of pre-existing clear rows. Recorded in the audit log."""
    if db.get_setting("evidence_encrypted") == "1":
        return
    if not available():
        return
    probe()
    c = db.conn()
    for table, cols in (("actions", ["args_json", "result_json", "reasons_json"]),
                        ("agent_sessions", ["reads_json", "exposures_json"]),
                        ("runs", ["summary"]),
                        ("audit", ["detail_json"])):
        if table == "audit":
            c.execute("DROP TRIGGER IF EXISTS audit_no_update")
        rows = c.execute(f"SELECT id, {', '.join(cols)} FROM {table}").fetchall()
        for r in rows:
            updates = {col: enc(r[col]) for col in cols
                       if r[col] and not str(r[col]).startswith((PREFIX, LEGACY_PREFIX))}
            if updates:
                sets = ", ".join(f"{col}=?" for col in updates)
                c.execute(f"UPDATE {table} SET {sets} WHERE id=?",
                          (*updates.values(), r["id"]))
        if table == "audit":
            c.execute("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit "
                      "BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
    c.commit()
    db.set_setting("evidence_encrypted", "1", "system", time.time())
    from . import audit
    audit.record("evidence_encrypted_migration",
                 {"note": "pre-existing stored evidence encrypted at rest (one-time)"})