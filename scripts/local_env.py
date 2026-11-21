"""Explicit local literal dotenv reader; credentials never persisted or printed."""
import os
from pathlib import Path
import re
import stat

ALLOWED = {'AEGIS_MODEL_PROVIDER', 'AEGIS_QWEN_API_KEY', 'DEEPSEEK_API_KEY', 'AEGIS_MODEL_API_KEY', 'AEGIS_MODEL_BASE_URL', 'AEGIS_MODEL_NAME', 'AEGIS_LOCAL_SESSION_CALLS', 'AEGIS_LOCAL_DAY_CALLS', 'AEGIS_LOCAL_DAY_TOKENS', 'AEGIS_JUDGE_TIMEOUT_S'}

def load(root):
    try:
        fd = os.open(Path(root) / '.env', os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError:
        raise ValueError('Local .env refused; use chmod 600 .env') from None
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError('Local .env refused; use chmod 600 .env')
        text = stream.read(16385)
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
        if not match:
            raise ValueError('Local .env requires literal KEY=value lines')
        name, value = match.groups()
        if name not in ALLOWED:
            continue
        if name in result or any(c in value for c in ('$', '`', '\\', '\x00')):
            raise ValueError('Local .env expansion or duplicates refused')
        if value[:1] in ('"', "'"):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError('Local .env quoting refused')
            value = value[1:-1]
        result[name] = value
    return result
