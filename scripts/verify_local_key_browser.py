"""Real Chromium/server gate; fake transport injected in test child only."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright

CHILD = r'''
import sys, json, socket, importlib.util
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root / 'scripts'), str(root)]
from aegis import provider
calls = 0
class Reply:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit):
        return json.dumps({'choices':[{'message':{'content':'OK'}}], 'usage':{'prompt_tokens':4,'completion_tokens':1}}).encode()
def fake(request, timeout):
    global calls
    calls += 1
    mode = json.loads(request.data)['model']
    secret = request.get_header('Authorization')[7:]
    if mode == 'timeout': raise TimeoutError(secret)
    if mode == 'echo':
        reply = Reply()
        reply.read = lambda limit: json.dumps({'choices':[{'message':{'content':secret}}]}).encode()
        return reply
    assert json.loads(request.data)['max_tokens'] == 8
    return Reply()
provider.open_pinned = fake
import local_key_settings
original = local_key_settings.install
def install(app, hard_offline=False):
    original(app, hard_offline)
    @app.get('/test-only/count')
    def count(): return {'calls': calls}
local_key_settings.install = install
import local_demo
local_demo.STATE = root / '.local-demo'
local_demo.child()
'''


def main():
    root = Path(__file__).resolve().parents[1]
    clone = Path(tempfile.mkdtemp(prefix='tg-key-', dir='/tmp')) / 'source'
    subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(root), str(clone)], check=True)
    def inventory():
        paths = subprocess.check_output(['git', 'ls-files', 'aegis', 'run.py', 'fly.toml', 'Dockerfile'], cwd=root).decode().splitlines()
        return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}
    before = inventory()
    sys.path.insert(0, str(clone / 'scripts'))
    import local_setup
    state = clone / '.local-demo'
    state.mkdir(mode=0o700)
    local_setup.initialize(state)
    env = local_setup.environment(state, {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'LANG') if k in os.environ})
    env.update(TWINGUARD_OFFLINE='0', TWINGUARD_HARD_OFFLINE='0')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env['AEGIS_PORT'] = str(port)
    base = 'http://127.0.0.1:' + str(port)
    key = secrets.token_urlsafe(48)
    logpath = state / 'gate-server.log'
    receipts = []
    def require(condition, label):
        if not condition:
            print('Gate failed: ' + label, file=sys.stderr)
            raise RuntimeError('Gate failed')
        receipts.append(label)
    def start():
        log = logpath.open('ab')
        process = subprocess.Popen([sys.executable, '-c', CHILD, str(clone)], cwd=clone, env=env, stdout=log, stderr=log)
        for _ in range(300):
            if process.poll() is not None: raise RuntimeError('Test server startup failed')
            try:
                with urllib.request.urlopen(base + '/login', timeout=.2): return process, log
            except OSError: time.sleep(.1)
        raise RuntimeError('Readiness failed')
    def stop(process, log):
        process.terminate()
        process.wait(timeout=20)
        log.close()
    process, log = start()
    try:
        accounts = json.loads((state / 'passwords.json').read_text())
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            def login(name):
                context = browser.new_context(base_url=base)
                context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
                page = context.new_page()
                page.goto('/login')
                page.get_by_label('Username', exact=True).fill(name)
                page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
                page.get_by_role('button', name='Sign in', exact=True).click()
                return context, page
            context, page = login('dana')
            page.goto('/local-demo/settings')
            csrf = page.locator('[name=csrf]').first.input_value()
            require(context.request.post(base + '/local-demo/settings/paste', form={'key':key}).status == 403, 'Admin CSRF denial')
            page.locator('[name=provider]').select_option('deepseek')
            page.locator('[name=model]').fill('deepseek-chat')
            page.locator('[name=key]').fill(key)
            page.get_by_role('button', name='Use in memory', exact=True).click()
            require(page.locator('[name=key]').input_value() == '', 'Password blank after POST')
            require(key not in page.content() and 'sk-...' + key[-4:] in page.content(), 'Masked hint only')
            page.get_by_role('button', name='Test connection (one capped call)', exact=True).click()
            require('PASS:' in page.content(), 'One tiny fake connection PASS')
            require(context.request.get(base + '/test-only/count').json()['calls'] == 1, 'Exactly one transport call')
            for route in ('/', '/audit', '/present/s13'):
                page.goto(route)
                require('Live AI deepseek / deepseek-chat' in page.content(), 'Runtime badge ' + route)
            storage = page.evaluate('JSON.stringify({local:{...localStorage},session:{...sessionStorage}})')
            require(key not in storage and key not in json.dumps(context.cookies()), 'No key in browser storage or cookies')
            for name in ('ops', 'riley', 'audi', 'view'):
                other, _ = login(name)
                require(other.request.get(base + '/local-demo/settings').status == 403, name + ' GET denied')
                require(other.request.post(base + '/local-demo/settings/forget', form={'csrf':csrf}).status == 403, name + ' POST denied')
                other.close()
            anonymous = browser.new_context()
            require(anonymous.request.get(base + '/local-demo/settings').status == 403, 'Anonymous denied')
            anonymous.close()
            page.goto('/local-demo/settings')
            page.get_by_role('button', name='Forget pasted key', exact=True).click()
            require('disabled / no key' in page.content(), 'Actual Forget disabled fallback')
            # Timeout exception contains the runtime secret, but response and log must not.
            response = context.request.post(base + '/local-demo/settings/paste', form={'csrf':csrf,'provider':'deepseek','model':'timeout','key':key})
            require(key not in response.text(), 'Timeout setup no echo')
            response = context.request.post(base + '/local-demo/settings/test', form={'csrf':csrf})
            require('HOLD:' in response.text() and key not in response.text() and 'Traceback' not in response.text(), 'Timeout sanitized HOLD')
            response = context.request.post(base + '/local-demo/settings/test', form={'csrf':csrf})
            response = context.request.post(base + '/local-demo/settings/test', form={'csrf':csrf})
            require(response.status == 429, 'Settings rate limit')
            context.close()
            stop(process, log)
            process, log = start()
            context, page = login('dana')
            page.goto('/local-demo/settings')
            require('disabled / no key' in page.content() and key[-4:] not in page.content(), 'Actual process restart forgot key')
            csrf = page.locator('[name=csrf]').first.input_value()
            context.request.post(base + '/local-demo/settings/paste', form={'csrf':csrf,'provider':'deepseek','model':'echo','key':key})
            response = context.request.post(base + '/local-demo/settings/test', form={'csrf':csrf})
            require('HOLD:' in response.text() and key not in response.text(), 'Secret echo and missing usage HOLD')
            require(context.request.get(base + '/test-only/count').json()['calls'] == 0, 'Unknown accounting prevents retry after restart')
            context.close()
            browser.close()
    finally:
        stop(process, log)
    require(before == inventory(), 'Production source byte hashes unchanged')
    for target in (root, clone):
        hits = 0
        for path in target.rglob('*'):
            if path.is_file() and not path.is_symlink():
                hits += key.encode() in path.read_bytes()
        require(hits == 0, 'Whole tree canary zero: ' + ('release' if target == root else 'isolated clone including DB/logs'))
    for path in ('.env.localdemo', '.local-demo/.local-runtime/data/aegis.db'):
        require(subprocess.run(['git', 'check-ignore', '--quiet', path], cwd=root).returncode == 0, 'Ignored ' + path)
    # Production import in a clean process without installing local routes.
    check = subprocess.check_output([sys.executable, '-c', 'from aegis.app import app; print(any(getattr(r, "path", "").startswith("/local-demo/settings") for r in app.routes))'], cwd=clone, env=env).decode().strip()
    require(check == 'False', 'Production route inventory absent')
    print(json.dumps({'status':'PASS', 'checks':receipts, 'servers_stopped':True, 'real_provider_calls':0}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('FAIL: local browser gate; secret-bearing exception details suppressed', file=sys.stderr)
        raise SystemExit(1) from None
