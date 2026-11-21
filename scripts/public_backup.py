"""Operator-only public-production snapshot and HMAC verification; never starts an app."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3

from cryptography.fernet import Fernet


def layout(root):
    legacy = (root / 'internal.key').exists() or (root / 'public-demo.db').exists()
    return (root / 'internal.key', root / 'public-demo.db') if legacy else (
        root / 'keys/internal.key', root / 'db/public-demo.db')


def readonly(path):
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)


def verify(root):
    keyfile, database = layout(root)
    key = keyfile.read_bytes()
    cipher = Fernet(key)
    counts = {}
    with readonly(database) as connection:
        if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('SQLite integrity failure')
        for table in ('sessions', 'events', 'live_sessions', 'live_attempts'):
            counts[table] = connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
        previous = 'genesis'
        checked = 0
        for visitor, generation, name, prev, signature, encrypted in connection.execute(
                'SELECT visitor,generation,event,previous,signature,evidence FROM events ORDER BY id'):
            payload = json.dumps({'visitor': visitor, 'generation': generation,
                                  'event': name, 'previous': prev}, sort_keys=True)
            expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
            if prev != previous or not hmac.compare_digest(expected, signature):
                raise ValueError('Public HMAC chain failure')
            if cipher.decrypt(encrypted.encode()).decode() != payload:
                raise ValueError('Canonical decrypted payload failure')
            previous = signature
            checked += 1
    for auxiliary in root.rglob('*.db'):
        if auxiliary != database:
            with readonly(auxiliary) as connection:
                if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise ValueError('Auxiliary SQLite integrity failure')
    return {'counts': counts, 'integrity': 'ok', 'verified_events': checked,
            'public_hmac_only': True, 'external_anchor': 'not_verified'}


def snapshot(root, destination):
    keyfile, database = layout(root)
    if root.is_symlink() or root != root.resolve() or destination.exists():
        raise ValueError('Canonical source and new private destination required')
    if destination == root or root in destination.parents:
        raise ValueError('Snapshot must be outside application state')
    files = list(root.rglob('*'))
    if any(path.is_symlink() or (not path.is_file() and not path.is_dir()) for path in files):
        raise ValueError('Unsupported state file')
    if not keyfile.is_file() or not database.is_file():
        raise ValueError('Original database and key required')
    destination.mkdir(mode=0o700)
    with sqlite3.connect(database, timeout=30) as writer:
        writer.execute('BEGIN IMMEDIATE')
        try:
            before = keyfile.read_bytes()
            # A separate reader avoids backing up a connection holding a write transaction.
            for source in [database] + [p for p in files if p.suffix == '.db' and p != database]:
                target = destination / source.relative_to(root)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with readonly(source) as reader, sqlite3.connect(target) as output:
                    reader.backup(output)
                target.chmod(0o600)
            for source in files:
                if source.is_file() and source.suffix != '.db' and not source.name.endswith(('-wal', '-shm', '-journal')) and source.name != 'instance.lock':
                    target = destination / source.relative_to(root)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
                    target.chmod(0o600)
            if before != keyfile.read_bytes() or before != (destination / keyfile.relative_to(root)).read_bytes():
                raise ValueError('Key changed during snapshot')
            result = verify(destination)
        finally:
            writer.rollback()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('snapshot', 'verify'))
    parser.add_argument('root', type=Path)
    parser.add_argument('destination', nargs='?', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.mode == 'snapshot':
            if args.destination is None:
                parser.error('snapshot requires a new destination')
            result = snapshot(args.root, args.destination)
        else:
            if args.destination is not None:
                parser.error('verify takes only the isolated state root')
            result = verify(args.root)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        # Do not expose key bytes, ciphertext, private paths or provider material.
        raise SystemExit('Backup verification failed; preserve partial private state for review')


if __name__ == '__main__':
    main()
