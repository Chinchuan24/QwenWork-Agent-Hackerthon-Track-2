"""Explicit, offline local setup. No application imports or existing-state reuse.

Run uses localhost port 8080 by default; use run --port 8081 for an alternate
free port without stopping another server. Inherited AEGIS_* settings are
 discarded rather than used to configure this isolated runtime.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


LAYOUT = {
    'AEGIS_DATA_DIR': 'data',
    'AEGIS_SIGNER_STATE': 'signer',
    'AEGIS_ANCHOR_EXTERNAL': 'external/anchor.json',
    'AEGIS_EVIDENCE_KEY_FILE': 'evidence.key',
}


class RuntimeInvalid(RuntimeError):
    pass


def environment(root, inherited):
    runtime = Path(root).resolve() / '.local-runtime'
    try:
        for p in (runtime, runtime / 'data', runtime / 'signer', runtime / 'external'):
            if p.is_symlink() or not p.is_dir() or stat.S_IMODE(p.stat().st_mode) != 0o700:
                raise ValueError()
        for p in runtime.rglob('*'):
            if p.is_symlink() or not (p.is_dir() or p.is_file()):
                raise ValueError()
            if stat.S_IMODE(p.stat().st_mode) != (0o700 if p.is_dir() else 0o600):
                raise ValueError()
        config = runtime / 'environment.json'
        obj = json.loads(config.read_text())
        if set(obj) != {*LAYOUT, 'version', 'evidence_sha256', 'signer_sha256'}:
            raise ValueError()
        if obj['version'] != 1 or any(obj[k] != v for k, v in LAYOUT.items()):
            raise ValueError()
        evidence = base64.b64decode((runtime / 'evidence.key').read_text().strip(), altchars=b'-_', validate=True)
        signer = bytes.fromhex((runtime / 'signer/signing.key').read_text().strip())
        if len(evidence) != 32 or len(signer) != 32:
            raise ValueError()
        if hashlib.sha256(evidence).hexdigest() != obj['evidence_sha256']:
            raise ValueError()
        if hashlib.sha256(signer).hexdigest() != obj['signer_sha256']:
            raise ValueError()
        # After first startup these three stores must travel together.
        stores = [runtime / 'data/aegis.db', runtime / 'signer/records.jsonl', runtime / 'external/anchor.json']
        if any(p.exists() for p in stores) and not all(p.is_file() for p in stores):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError):
        raise RuntimeInvalid('Local runtime is missing, partial, mismatched, or not private; restore a complete backup. No files changed.') from None
    env = {k: v for k, v in inherited.items() if not k.startswith('AEGIS_') and k not in ('DEEPSEEK_API_KEY', 'OPENAI_API_KEY', 'TWINGUARD_OFFLINE')}
    env.update({k: str(runtime / v) for k, v in LAYOUT.items()})
    env.update(AEGIS_EVIDENCE_KEY='', AEGIS_EVIDENCE_KEYRING_FILE='',
               AEGIS_SIGNER_PORT='0', AEGIS_QWEN_API_KEY='', AEGIS_HOST='127.0.0.1')
    return env


def initialize(root):
    runtime = Path(root).resolve() / '.local-runtime'
    if runtime.exists() or runtime.is_symlink():
        environment(root, {})
        return
    # Exclusive mkdir also arbitrates concurrent initializers. Failed creation
    # deliberately leaves a partial runtime, never a resettable key store.
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    for name in ('data', 'signer', 'external'):
        p = runtime / name
        p.mkdir(mode=0o700)
        p.chmod(0o700)
    evidence, signer = os.urandom(32), os.urandom(32)
    obj = dict(LAYOUT, version=1,
               evidence_sha256=hashlib.sha256(evidence).hexdigest(),
               signer_sha256=hashlib.sha256(signer).hexdigest())
    files = {'evidence.key': base64.urlsafe_b64encode(evidence).decode() + '\n',
             'signer/signing.key': signer.hex() + '\n',
             'environment.json': json.dumps(obj, indent=2) + '\n'}
    for name, content in files.items():
        fd = os.open(runtime / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    environment(root, {})


def run(root, port=None, live=False):
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('port must be an integer from 1 to 65535')
    root = Path(root).resolve()
    env = environment(root, os.environ)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from local_env import load
    sys.path.insert(0, str(root))
    from aegis.provider import resolve
    settings = load(root)
    provider, base, model, key = resolve(settings)
    if key and provider != 'scripted':
        env.update(settings)
        env['AEGIS_LOCAL_AI'] = '1'
    if port is not None:
        env['AEGIS_PORT'] = str(port)
    os.umask(0o077)
    os.chdir(root)
    os.execve(sys.executable, [sys.executable, str(root / 'run.py')], env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init')
    start_parser = commands.add_parser('start', help='copy environment inventory, initialize private state and run offline')
    start_parser.add_argument('--port', type=int)
    start_parser.add_argument('--live-ai', action='store_true')
    run_parser = commands.add_parser('run')
    run_parser.add_argument('--live-ai', action='store_true')
    run_parser.add_argument('--port', type=int, help='free localhost port, 1..65535 (default: 8080)')
    args = parser.parse_args()
    if args.command in ('run', 'start') and args.port is not None and not 1 <= args.port <= 65535:
        parser.error('--port must be from 1 to 65535')
    root = Path(__file__).resolve().parents[1]
    try:
        if args.command == 'start':
            target = root / '.env'
            if not target.exists() and not target.is_symlink():
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write((root / '.env.example').read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
            initialize(root)
            run(root, port=args.port, live=args.live_ai)
        elif args.command == 'init':
            initialize(root)
            print('Private local runtime ready; existing keys preserved.')
        else:
            run(root, port=args.port, live=args.live_ai)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (RuntimeInvalid, OSError):
        print('Local setup refused: runtime unavailable or invalid. Restore a complete private backup; no reset performed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
