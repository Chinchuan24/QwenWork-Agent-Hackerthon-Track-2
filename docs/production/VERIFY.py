"""Read-only current-package inventory and strict candidate scan. No dotenv reads."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'provider-token': re.compile(r'\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,})\b'),
    'credential-literal': re.compile(r'''(?i)(?:api_key|password|secret|access_token)\s*=\s*['"]([^'"\n]{8,})['"]'''),
}

def scan(text):
    return [(name, match.start(), hashlib.sha256(match.group().encode()).hexdigest())
            for name, pattern in PATTERNS.items() for match in pattern.finditer(text)]

def inventory():
    files = []
    candidates = []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if '.git' in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError('Symlink refused: ' + str(relative))
        if not path.is_file():
            continue
        if path.name.startswith('.env') and path.name != '.env.production.example':
            raise ValueError('Forbidden environment file exists; content NOT read')
        if any(part in ('__pycache__', '.pytest_cache', 'fixtures', 'tests', '.venv') for part in relative.parts):
            raise ValueError('Forbidden shipped path: ' + str(relative))
        raw = path.read_bytes()
        files.append({'path': relative.as_posix(), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        for kind, offset, digest in scan(raw.decode('utf-8')):
            candidates.append({'path': relative.as_posix(), 'offset': offset, 'kind': kind, 'candidate_sha256': digest})
    return files, candidates

if __name__ == '__main__':
    files, candidates = inventory()
    # Synthetic scanner self-check, created in memory, never credential output.
    assert scan('token=' + 'sk-' + 'A' * 32)
    assert scan('password="' + 'synthetic-candidate-only' + '"')
    assert scan('-----BEGIN ' + 'PRIVATE KEY-----')
    assert not scan('DEEPSEEK_API_KEY=REPLACE_VIA_PLATFORM_SECRET_STORE')
    print(json.dumps({'files': files, 'file_count': len(files), 'candidates': candidates,
                      'scan_scope': 'current regular package files; .git excluded; forbidden env content never read',
                      'synthetic_self_check': '3 detected; placeholder rejected'}, indent=2))
    raise SystemExit(bool(candidates))
