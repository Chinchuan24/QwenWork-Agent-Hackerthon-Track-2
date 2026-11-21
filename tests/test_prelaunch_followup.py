"""Disposable offline launch, audit-command and storage failure acceptance."""
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def test_check_missing_auditor_refuses(tmp_path):
    shutil.copy2(ROOT / 'check.sh', tmp_path / 'check.sh')
    binary = tmp_path / '.venv/bin'
    binary.mkdir(parents=True)
    python = binary / 'python'
    python.write_text('#!/bin/sh\nexit 0\n')
    python.chmod(0o700)
    result = subprocess.run(['/bin/zsh', str(tmp_path / 'check.sh')], capture_output=True, text=True)
    assert result.returncode == 1
    assert 'pip-audit not installed' in result.stdout
    assert 'all checks passed' not in result.stdout


def test_fresh_folder_one_command_no_key(tmp_path):
    clone = tmp_path / 'fresh'
    subprocess.run(['git', 'clone', '--local', str(ROOT), str(clone)], check=True, capture_output=True)
    subprocess.run(['cp', '.env.example', '.env'], cwd=clone, check=True)
    (clone / '.env').chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('AEGIS_')}
    env['AEGIS_QWEN_API_KEY'] = 'dummy-not-real'
    process = subprocess.Popen([sys.executable, 'scripts/local_setup.py', 'start', '--port', str(port)], cwd=clone, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/login', timeout=1) as response:
                    assert response.status == 200
                    break
            except OSError:
                assert process.poll() is None
                time.sleep(.1)
        else:
            raise AssertionError('Fresh-folder launch did not become available')
        assert (clone / '.env').read_bytes() == (clone / '.env.example').read_bytes()
        assert (clone / '.env').stat().st_mode & 0o077 == 0
        assert (clone / '.local-runtime/data/aegis.db').is_file()
    finally:
        process.terminate()
        process.wait(timeout=15)


def test_disk_full_mutation_rolls_back(tmp_path, monkeypatch):
    import re
    from test_production import client
    with client(tmp_path, monkeypatch) as c:
        csrf = re.search('name="csrf" value="([^"]+)"', c.get('/').text)[1]
        c.post('/session', data={'role': 'viewer', 'csrf': csrf})
        database = sqlite3.connect(tmp_path / 'db/public-demo.db')
        database.execute("CREATE TRIGGER disk_full BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'database or disk is full'); END")
        database.commit()
        assert c.post('/reset', data={'csrf': csrf}).status_code == 503
        assert 'World generation 1' in c.get('/world').text
        assert len(c.get('/audit/export').json()['events']) == 1
        database.close()


def test_crash_uncommitted_sqlite_recovers(tmp_path):
    database = tmp_path / 'crash.db'
    child = subprocess.run([sys.executable, '-c', "import sqlite3,os,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE events(id INTEGER)'); c.commit(); c.execute('INSERT INTO events VALUES(1)'); os._exit(9)", str(database)])
    assert child.returncode == 9
    with sqlite3.connect(database) as c:
        assert c.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert c.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0
