"""BUDGET02 offline regression boundaries."""
import json
import os
import sqlite3
import subprocess
import sys
import urllib.error
import pytest
from aegis import config, db, qwen_client as c

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    connection = sqlite3.connect(tmp_path / 'budget.db')
    connection.row_factory = sqlite3.Row
    connection.executescript(db.SCHEMA)
    monkeypatch.setattr(db, 'conn', lambda: connection)
    monkeypatch.setattr(config, 'DB_PATH', tmp_path / 'budget.db')
    monkeypatch.setattr(c.audit, 'record', lambda *a, **k: None)
    monkeypatch.setattr(c.time, 'sleep', lambda seconds: None)
    c._calls_window.clear()
    yield
    connection.close()

class Response:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.body

@pytest.mark.parametrize('failure', ['json', 'schema', 'settlement'])
def test_received_response_never_resends(monkeypatch, failure):
    calls = []
    body = b'not json' if failure == 'json' else json.dumps({
        'choices': [] if failure == 'schema' else [{'message': {'content': 'ok'}}],
        'usage': {'prompt_tokens': 1, 'completion_tokens': 1}}).encode()
    def transport(*args, **kwargs):
        calls.append(1)
        return Response(body)
    monkeypatch.setattr(c.urllib.request, 'urlopen', transport)
    if failure == 'settlement':
        def broken(*args): raise RuntimeError('settlement failed')
        monkeypatch.setattr(c, '_record_spend', broken)
    with pytest.raises(c.JudgeUnavailable):
        c._chat(config.MODEL_WORKER, [{'role': 'user', 'content': 'hi'}])
    assert len(calls) == 1

@pytest.mark.parametrize('limit', ['global', 'adaptive', 'rate'])
def test_retry_rechecks_limits(monkeypatch, limit):
    calls = []
    monkeypatch.setattr(c, 'RATE_PER_MIN', 1 if limit == 'rate' else 30)
    def transport(*args, **kwargs):
        calls.append(1)
        if limit != 'rate':
            amount = config.ADAPTIVE_SPEND_CAP_USD if limit == 'adaptive' else config.SPEND_CAP_USD
            db.conn().execute('INSERT INTO spend(est_usd,mode) VALUES(?,?)', (amount, 'adaptive'))
            db.conn().commit()
        raise urllib.error.URLError('offline failure')
    monkeypatch.setattr(c.urllib.request, 'urlopen', transport)
    with pytest.raises(c.JudgeUnavailable):
        c._chat(config.MODEL_WORKER, [{'role': 'user', 'content': 'hi'}],
                mode='adaptive' if limit == 'adaptive' else 'live')
    assert len(calls) == 1

def test_failed_worker_consumes_admission(monkeypatch):
    monkeypatch.setattr(config, 'WORKER_MAX_CALLS_PER_SESSION', 1)
    calls = []
    def transport(*args, **kwargs):
        row = db.conn().execute('SELECT calls FROM worker_usage').fetchone()
        calls.append(row['calls'] if row else 0)
        raise c.JudgeUnavailable('offline failure')
    monkeypatch.setattr(c, '_chat', transport)
    for _ in range(2):
        with pytest.raises(c.JudgeUnavailable):
            c.worker_chat('BUDGET02', [{'role': 'user', 'content': 'hi'}], [])
    assert calls == [1]

@pytest.mark.parametrize('boundary', ['session', 'rate'])
def test_subprocess_shared_admission(boundary):
    script = '''
import sqlite3, sys, time
from aegis import config, db, qwen_client as c
config.DB_PATH = sys.argv[1]
c.audit.record = lambda *a, **k: None
config.WORKER_MAX_CALLS_PER_SESSION = 1
c.RATE_PER_MIN = 1
config.LIVE_RETRIES = 0
def transport(*a, **k):
    other = sqlite3.connect(config.DB_PATH, timeout=.5)
    other.execute("INSERT INTO settings(key,value) VALUES(?, 'network')", (sys.argv[3],))
    other.commit()
    other.close()
    time.sleep(.1)
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}'
    return R()
c.urllib.request.urlopen = transport
try:
    if sys.argv[2] == 'session':
        c.worker_chat('BUDGET02', [{'role':'user','content':'hi'}], [])
    else:
        c._chat(config.MODEL_WORKER, [{'role':'user','content':'hi'}])
    print('admitted')
except c.JudgeUnavailable:
    print('refused')
'''
    env = {k: v for k, v in os.environ.items() if k != 'AEGIS_QWEN_API_KEY'}
    processes = [subprocess.Popen([sys.executable, '-c', script, str(config.DB_PATH),
                                  boundary, 'BUDGET02-network-' + str(i)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=env) for i in range(4)]
    results = [p.communicate(timeout=20) for p in processes]
    assert all(p.returncode == 0 for p in processes), results
    assert sorted(out.strip() for out, err in results) == ['admitted'] + ['refused'] * 3
    assert db.conn().execute("SELECT COUNT(*) FROM settings WHERE value='network'").fetchone()[0] == 1
