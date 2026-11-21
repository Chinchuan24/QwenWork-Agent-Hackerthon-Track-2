"""Disposable subprocess local AI, no real keys and no external transport."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from aegis import provider

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '192.168.1.1'])
def test_dns_private_refused(monkeypatch, address):
    import socket
    import urllib.request
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))])
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('TCP must not open'))
    with pytest.raises(ValueError, match='Nonpublic'):
        provider.open_pinned(urllib.request.Request('https://owned.example/v1'), 1)

@pytest.mark.parametrize('failure', ['success', 'badkey', 'timeout', 'json', 'cap'])
def test_fake_subprocess_all_local_callers(tmp_path, failure):
    code = '''
import json, os, sqlite3, sys
from aegis import config, db, qwen_client as c, provider
assert config.MODEL_PROVIDER == 'deepseek' and config.live_mode()
assert config.MODEL_JUDGE == config.MODEL_WORKER == config.MODEL_FAST == 'deepseek-chat'
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript(db.SCHEMA)
db.conn = lambda: connection
c.audit.record = lambda *a, **k: None
calls = []
class Response:
 def __enter__(self): return self
 def __exit__(self, *a): pass
 def read(self, limit): return self.body
def fake(request, timeout):
 calls.append(1)
 assert request.full_url == 'https://api.deepseek.com/chat/completions'
 if sys.argv[1] in ('badkey', 'timeout'): raise TimeoutError('fixture-secret-must-not-leak')
 payload = json.loads(request.data)
 system = payload['messages'][0]['content']
 verdict = 'clean' if 'security classifier' in system else 'ok' if 'Derive least' in system else 'safe' if 'safety judge' in system else 'yes'
 content = json.dumps({'verdict': verdict, 'reason': 'fixture', 'limits': {'clients': ['acme'], 'tools': ['read_file'], 'external_send': False, 'refund': False}})
 r = Response()
 r.body = b'bad json' if sys.argv[1] == 'json' else json.dumps({'choices': [{'message': {'content': content}}], 'usage': {'prompt_tokens': 1, 'completion_tokens': 1}}).encode()
 return r
provider.open_pinned = fake
if sys.argv[1] == 'cap': config.LOCAL_DAY_CALLS = 1
operations = [lambda: c.judge('intent', {'task':'read Acme file', 'tool':'read_file', 'args':{}}), lambda: c.judge('injection', {'content':'sample'}), lambda: c.judge('safety_a', {'task':'sample','tool':'send_email','args':{}}), lambda: c.judge('safety_b', {'task':'sample','tool':'send_email','args':{}}), lambda: c.worker_chat('session', [{'role':'user','content':'sample'}], []), lambda: c.generate('generate fake redteam variant', 'sample')]
failures = 0
for operation in operations:
 try: operation()
 except c.JudgeUnavailable as error:
  failures += 1
  assert 'fixture-secret' not in str(error)
if sys.argv[1] == 'success': assert len(calls) == 6 and failures == 0
elif sys.argv[1] == 'cap': assert len(calls) == 1 and failures == 5
else: assert len(calls) == 1 and failures == 6
print('fake local callers passed')
'''
    env = {k:v for k,v in os.environ.items() if not k.startswith('AEGIS_') and k != 'DEEPSEEK_API_KEY'}
    env.update(AEGIS_LOCAL_AI='1', DEEPSEEK_API_KEY='fixture-secret-must-not-leak', AEGIS_DATA_DIR=str(tmp_path/'data'), AEGIS_ANCHOR_EXTERNAL=str(tmp_path/'anchor'), AEGIS_SIGNER_STATE=str(tmp_path/'signer'))
    result = subprocess.run([sys.executable, '-c', code, failure], cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'fixture-secret' not in result.stdout + result.stderr

@pytest.mark.parametrize('mode', ['scripted', 'deepseek'])
def test_same_command_launcher_fake_env_and_stop(tmp_path, mode):
    import tempfile
    clone = Path(tempfile.mkdtemp(prefix='tg-', dir='/var/folders/20/hrrmnm4n4m31m2bn72h7pfzm0000gn/T'))/'source'
    subprocess.run(['git','clone','--quiet','--no-hardlinks',str(ROOT),str(clone)], check=True)
    tracked = subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
    for name in filter(None, tracked):
        if (ROOT/name).is_file(): shutil.copy2(ROOT/name, clone/name)
    # Test-only injection in disposable clone: never available in shipped runtime.
    fixture = '''

def open_pinned(request, timeout):
    import json
    body = json.loads(request.data)
    system = body['messages'][0]['content']
    verdict = 'ok' if 'Derive least' in system else 'clean' if 'security classifier' in system else 'yes' if 'reasonable step' in system else 'unsure'
    content = json.dumps({'verdict': verdict, 'reason': 'synthetic fixture only', 'limits': {'clients': ['acme', 'north', 'lumen', 'cirrus'], 'tools': ['list_inbox', 'read_email', 'search_files', 'read_file', 'get_client', 'find_contact', 'fetch_web', 'issue_refund', 'send_email'], 'external_send': False, 'refund': True}})
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps({'choices':[{'message':{'content':content}}], 'usage':{'prompt_tokens':1,'completion_tokens':1}}).encode()
    return Response()
'''
    with (clone/'aegis/provider.py').open('a') as stream:
        stream.write(fixture)
    fake = clone/'.env'
    fake.write_text('DEEPSEEK_API_KEY=fixture-secret-must-not-leak\n' if mode == 'deepseek' else 'AEGIS_MODEL_PROVIDER=scripted\n')
    fake.chmod(0o600)
    env = {k:v for k,v in os.environ.items() if not k.startswith(('AEGIS_', 'TWINGUARD_')) and k != 'DEEPSEEK_API_KEY'}
    env['TWINGUARD_LOCAL_PYTHON'] = sys.executable
    process = subprocess.Popen([str(clone/'run-local-demo.sh')], cwd=clone, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import time, urllib.request
        deadline = time.monotonic()+30
        while time.monotonic()<deadline:
            control = clone/'.local-demo/control.sock'
            if control.exists(): break
            assert process.poll() is None, process.communicate(timeout=5)
            time.sleep(.1)
        assert control.exists()
        # Wait for actual readiness printed by owned launcher, not an assumed port.
        line = process.stdout.readline()
        assert line.startswith('Ready http://localhost:')
        url = line.split()[1]
        with urllib.request.urlopen(url+'/login',timeout=5) as response:
            html = response.read().decode()
        label = 'Live AI deepseek / deepseek-chat' if mode == 'deepseek' else 'Scripted / no key'
        assert label in html
        output = clone/'browser-evidence'
        output.mkdir()
        subprocess.run([sys.executable, str(clone/'scripts/demo_rehearsal.py'), '--approve-sandbox', '--existing-url', url, '--password-file', str(clone/'.local-demo/passwords.json'), '--output-dir', str(output)], cwd=clone, env=env, check=True, capture_output=True, timeout=120)
        result = subprocess.run([sys.executable, str(clone/'scripts/local_get_smoke.py'), str(output), url, label], cwd=clone, env=env, capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stderr
        assert 'fixture-secret' not in html
        subprocess.run([str(clone/'run-local-demo.sh'),'stop'],cwd=clone,env=env,check=True,capture_output=True,timeout=10)
        out, err = process.communicate(timeout=20)
        assert process.returncode == 0, err
        assert 'Owned server stopped.' in out
        assert 'fixture-secret' not in out+err+(clone/'.local-demo/server.log').read_text()
        subprocess.run([str(clone/'run-local-demo.sh'),'reset'],cwd=clone,env=env,check=True,capture_output=True,timeout=10)
        assert list(clone.glob('.local-demo-archive-*'))
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=20)
