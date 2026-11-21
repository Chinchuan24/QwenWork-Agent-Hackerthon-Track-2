"""Settings. Secrets only ever come from environment variables."""
import hashlib
import os
from pathlib import Path

def validate_db_path(path):
    """Reject aliases without changing persisted signer identity or history."""
    try:
        path = Path(path)
        if not path.is_absolute() or str(path) != str(path.resolve()):
            raise ValueError
        if path.exists() and path.stat().st_nlink != 1:
            raise ValueError
    except (OSError, RuntimeError, ValueError):
        raise ValueError(
            'Database path unsupported: canonical absolute path and single link '
            'required; existing alias history needs explicit operator recovery, '
            'not automatic migration') from None


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("AEGIS_DATA_DIR", ROOT / "aegis_data"))
DB_PATH = DATA_DIR / "aegis.db"
validate_db_path(DB_PATH)  # Before directory creation or signer startup.
ANCHOR_DIR = DATA_DIR / "anchors"
RECORD_DIR = DATA_DIR / "recordings"

# Latest-checkpoint anchor kept OUTSIDE the data folder, so rolling back the
# data folder (records + checkpoint lines together) cannot erase it.
# Set AEGIS_ANCHOR_EXTERNAL="" to disable (Verify then reports the gap).
_DEFAULT_EXTERNAL = Path.home() / ".aegis" / (
    "anchor-" + hashlib.sha256(str(DATA_DIR).encode()).hexdigest()[:12] + ".json")
AEGIS_ANCHOR_EXTERNAL = os.environ.get("AEGIS_ANCHOR_EXTERNAL", str(_DEFAULT_EXTERNAL))

# Separate signer process (R3): its state (key + forward-only record) lives
# OUTSIDE the data folder. Port 0 means "not launched yet"; the app launches
# the signer at startup, tests launch their own.
_DEFAULT_SIGNER_STATE = Path.home() / ".aegis" / (
    "signer-" + hashlib.sha256(str(DATA_DIR).encode()).hexdigest()[:12])
AEGIS_SIGNER_STATE = os.environ.get("AEGIS_SIGNER_STATE", str(_DEFAULT_SIGNER_STATE))
AEGIS_SIGNER_PORT = int(os.environ.get("AEGIS_SIGNER_PORT", "0"))

# R4: evidence encryption key — from the environment or a file OUTSIDE the
# data folder; never stored next to the data. base64url-encoded 32 bytes.
AEGIS_EVIDENCE_KEY = os.environ.get("AEGIS_EVIDENCE_KEY", "")
AEGIS_EVIDENCE_KEY_FILE = os.environ.get("AEGIS_EVIDENCE_KEY_FILE", "")
# Read-only historical keys: external JSON {"keys": {key_id: base64url_key}}.
# Rotation retains old keys here and selects the new current key via the env/file.
AEGIS_EVIDENCE_KEYRING_FILE = os.environ.get("AEGIS_EVIDENCE_KEYRING_FILE", "")

QWEN_API_KEY = os.environ.get("AEGIS_QWEN_API_KEY", "")
# International Model Studio endpoint by default; the China endpoint is
# https://dashscope.aliyuncs.com/compatible-mode/v1 — set AEGIS_QWEN_BASE_URL.
# With a key present, startup lists the account's models to confirm both.
QWEN_BASE_URL = os.environ.get(
    "AEGIS_QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
)
MODEL_JUDGE = os.environ.get("AEGIS_MODEL_JUDGE", "qwen-max")
MODEL_WORKER = os.environ.get("AEGIS_MODEL_WORKER", "qwen-plus")
MODEL_FAST = os.environ.get("AEGIS_MODEL_FAST", "qwen-turbo")
MODEL_PROVIDER = 'qwen'
LOCAL_AI = os.environ.get('AEGIS_LOCAL_AI') == '1'
if LOCAL_AI:
    from .provider import resolve
    MODEL_PROVIDER, QWEN_BASE_URL, model, QWEN_API_KEY = resolve(os.environ)
    if model:
        MODEL_JUDGE = MODEL_WORKER = MODEL_FAST = model
LOCAL_DAY_CALLS = int(os.environ.get('AEGIS_LOCAL_DAY_CALLS', '60'))
LOCAL_DAY_TOKENS = int(os.environ.get('AEGIS_LOCAL_DAY_TOKENS', '120000'))
LOCAL_SESSION_CALLS = int(os.environ.get('AEGIS_LOCAL_SESSION_CALLS', '15'))
if LOCAL_AI and (not 1 <= LOCAL_DAY_CALLS <= 60 or not 20000 <= LOCAL_DAY_TOKENS <= 120000 or not 1 <= LOCAL_SESSION_CALLS <= 30):
    raise ValueError('Local model caps outside safe bounds')

SPEND_CAP_USD = float(os.environ.get("AEGIS_SPEND_CAP_USD", "5.00"))
# rough per-1k-token prices used only for the spending meter (labelled estimate)
PRICE_PER_1K = {"qwen-max": 0.0024, "qwen-plus": 0.0006, "qwen-turbo": 0.0002}

JUDGE_TIMEOUT_S = float(os.environ.get("AEGIS_JUDGE_TIMEOUT_S", "20"))
LIVE_RETRIES = 0 if LOCAL_AI else 2
if LOCAL_AI and not 1 <= JUDGE_TIMEOUT_S <= 20:
    raise ValueError('Local model timeout must be 1..20 seconds')
LIVE_RETRY_PAUSE_S = 1.0
RATE_CALLS_PER_MIN = 40
RATE_SENDS_PER_MIN = 6
LOOP_WINDOW = 5          # identical side-effect calls in a row -> freeze
LOOP_THRESHOLD = 3
REFUND_SESSION_CAP = 500.0
REFUND_CLIENT_DAY_CAP = 1000.0
SEND_SESSION_CAP = 15    # external emails per session
APPROVAL_TTL_S = 600
MAX_CONTENT_BYTES = 200_000   # over cap -> Hold, never skip
MAX_ARG_LEN = 20_000
WORKER_MAX_CALLS_PER_SESSION = LOCAL_SESSION_CALLS if LOCAL_AI else 30
WORKER_MAX_PAYLOAD_BYTES = 200_000  # size limit on what the worker may send
WORKER_MAX_CONCURRENT = 3           # live worker processes at once
ADAPTIVE_SEED = int(os.environ.get("AEGIS_ADAPTIVE_SEED", "20261118"))
ADAPTIVE_SPEND_CAP_USD = float(os.environ.get("AEGIS_ADAPTIVE_SPEND_CAP_USD", "1.00"))

for d in (DATA_DIR, ANCHOR_DIR, RECORD_DIR):
    d.mkdir(parents=True, exist_ok=True)


def live_mode() -> bool:
    return bool(QWEN_API_KEY)