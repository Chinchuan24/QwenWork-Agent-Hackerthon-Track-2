"""Private offline launcher; no deployment or provider configuration is loaded."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.local-demo'


def offline_guard():
    def check(event, args):
        if event in ('socket.connect', 'socket.bind'):
            address = args[1]
            if isinstance(address, tuple):
                host = address[0]
                if host != 'localhost':
                    try:
                        allowed = ipaddress.ip_address(host).is_loopback
                    except ValueError:
                        allowed = False
                    if not allowed:
                        raise PermissionError('Offline demo prohibits non-loopback sockets')
        if event == 'socket.getaddrinfo' and args[0] not in ('localhost', '127.0.0.1', '::1', None):
            raise PermissionError('Offline demo prohibits external DNS')
    sys.addaudithook(check)


def child():
    if os.environ.get('TWINGUARD_OFFLINE') == '1':
        offline_guard()
    sys.path.insert(0, str(ROOT))
    from aegis import auth
    def seed():
        from aegis import db
        if db.conn().execute('SELECT COUNT(*) n FROM users').fetchone()['n']:
            return
        accounts = {}
        for name, role in [('dana', 'admin'), ('ops', 'approver'), ('riley', 'approver'), ('audi', 'auditor'), ('view', 'viewer')]:
            password = secrets.token_urlsafe(32)
            auth.create_user(name, password, role)
            accounts[name] = {'role': role, 'password': password}
        target = STATE / 'passwords.json'
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(accounts, stream)
    auth.ensure_demo_users = seed
    from aegis import approvals, db, audit, gateway
    decide = approvals.decide
    @gateway._serialized
    def two_person(approval_id, user, decision, freeze=False, reason=None):
        kwargs = {'freeze': freeze, 'reason': reason}
        if decision != 'approve':
            return decide(approval_id, user, decision, **kwargs)
        row = db.conn().execute('SELECT s.created_by, ap.status FROM approvals ap JOIN actions a ON a.id=ap.action_id JOIN agent_sessions s ON s.id=a.session_id WHERE ap.id=?', (approval_id,)).fetchone()
        if not row or row['status'] != 'pending' or user['role'] != 'approver' or user['username'] not in ('ops', 'riley') or row['created_by'] == user['username']:
            return {'ok': False, 'error': 'Two distinct named approvers required; no self approval'}
        if not (kwargs.get('reason') or '').strip():
            return {'ok': False, 'error': 'Review reason required'}
        setting = 'local-demo-action-review:' + approval_id
        reviews = json.loads(db.get_setting(setting, '[]'))
        if user['username'] in reviews:
            return {'ok': False, 'error': 'Duplicate identity cannot count twice'}
        if not reviews:
            audit.record('local_demo_first_approval', {'approval': approval_id, 'by': user['username'], 'synthetic_only': True})
            db.set_setting(setting, json.dumps([user['username']]), user['username'], 0)
            return {'ok': True, 'status': 'held', 'error': 'First approval saved; second distinct approver required'}
        return decide(approval_id, user, decision, **kwargs)
    approvals.decide = two_person
    import uvicorn
    from aegis.app import app
    from aegis import app as views
    views.demo_result_path = lambda request: STATE / 'saved-rehearsal.json'
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response
    class OfflineBanner(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            if 'text/html' in response.headers.get('content-type', ''):
                body = b''.join([part async for part in response.body_iterator])
                import html
                from aegis import config
                label = ('Live AI ' + config.MODEL_PROVIDER + ' / ' + config.MODEL_JUDGE if config.live_mode() else 'Scripted / no key')
                banner = ('<div role="note">LOCAL DEMO: ' + html.escape(label) + '; simulated sample data and effects only.</div>').encode()
                body = body.replace(b'<body>', b'<body>' + banner, 1) if b'<body>' in body else banner + body
                headers = dict(response.headers)
                headers.pop('content-length', None)
                return Response(body, status_code=response.status_code, headers=headers)
            return response
    app.add_middleware(OfflineBanner)
    sys.path.insert(0, str(ROOT / 'scripts'))
    from local_demo_panel import install
    install(app)
    from presentation import install as install_presentation
    install_presentation(app)
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1'])
    uvicorn.run(app, host='127.0.0.1', port=int(os.environ['AEGIS_PORT']), log_level='warning', proxy_headers=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=['start', 'reset', 'stop', '_child'], default='start')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--live-ai', action='store_true')
    mode.add_argument('--scripted', action='store_true', help='Never read .env or call a real provider')
    args = parser.parse_args()
    if args.command == '_child':
        child()
        return
    # Allowlist rather than attempting to enumerate all provider secrets.
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'LANG') if k in os.environ}
    env.update(PYTHONPATH=str(ROOT), AEGIS_QWEN_API_KEY='', AEGIS_HOST='127.0.0.1')
    os.umask(0o077)
    if sys.version_info[:2] != (3, 12):
        raise SystemExit('Offline demo requires trusted Python 3.12')
    import importlib.metadata
    for line in (ROOT / 'requirements.txt').read_text().splitlines():
        if '==' in line:
            name, version = line.split('==')
            if importlib.metadata.version(name) != version:
                raise SystemExit('Offline prerequisite mismatch: ' + name + ' requires ' + version)
    if STATE.is_symlink():
        raise SystemExit('Refusing symlink demo state')
    STATE.mkdir(mode=0o700, exist_ok=True)
    if STATE.stat().st_uid != os.getuid() or STATE.stat().st_mode & 0o077:
        raise SystemExit('Demo state must be owner-only')
    import fcntl
    if args.command == 'stop':
        with socket.socket(socket.AF_UNIX) as control:
            try:
                control.connect(str(STATE / 'control.sock'))
                control.sendall(b'stop')
                print('Stop requested through owned local control socket.')
            except (FileNotFoundError, ConnectionRefusedError):
                print('No owned demo running.')
        return
    lock = (STATE / 'owner.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Owned demo is running. Stop with Ctrl-C in its terminal; no other process was signaled.')
    if args.command == 'stop':
        print('No owned running server. For an active foreground demo use Ctrl-C in its terminal.')
        return
    if args.command == 'reset':
        archive = ROOT / ('.local-demo-archive-' + str(time.time_ns()))
        STATE.rename(archive)
        print('Demo state archived without deletion: ' + str(archive))
        return
    sys.path.insert(0, str(ROOT / 'scripts'))
    import local_setup
    local_setup.initialize(STATE)
    env = local_setup.environment(STATE, env)
    from local_env import load
    sys.path.insert(0, str(ROOT))
    from aegis.provider import resolve
    try:
        settings = load(ROOT, scripted=args.scripted)
        provider, base, model, key = resolve(settings)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    live = bool(key) and provider != 'scripted'
    if live:
        env.update(settings)
        env['AEGIS_LOCAL_AI'] = '1'
    env.update(TWINGUARD_OFFLINE='0' if live else '1', PYTHONPATH=str(ROOT / 'scripts') + os.pathsep + str(ROOT))
    sock = socket.socket()
    for port in range(8000, 65536):
        try:
            sock.bind(('127.0.0.1', port))
            break
        except OSError:
            continue
    else:
        raise SystemExit('No free loopback port')
    sock.close()
    env['AEGIS_PORT'] = str(port)
    log = (STATE / 'server.log').open('a')
    process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '_child'], cwd=ROOT, env=env, stdout=log, stderr=log)
    def stop(signum=None, frame=None):
        if process.poll() is None:
            process.terminate()
    import threading
    control = socket.socket(socket.AF_UNIX)
    control_path = STATE / 'control.sock'
    if control_path.exists():
        control_path.rename(STATE / ('control-stale-' + str(time.time_ns())))
    control.bind(str(control_path))
    control.listen(1)
    def listen():
        connection, _ = control.accept()
        with connection:
            if connection.recv(4) == b'stop':
                stop()
    threading.Thread(target=listen, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(300):
            if process.poll() is not None:
                raise RuntimeError('Owned demo exited; inspect private .local-demo/server.log')
            try:
                with opener.open(f'http://127.0.0.1:{port}/login', timeout=.3) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('Readiness timeout')
        print(f'Ready http://localhost:{port} child PID {process.pid}', flush=True)
        print('Scripted stand-in, synthetic actions only. Password file: ' + str(STATE / 'passwords.json'), flush=True)
        print('Stop: Ctrl-C in this terminal. Reset after stopping: ./run-local-demo.sh reset', flush=True)
        process.wait()
    finally:
        stop()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()
        control.close()
        if control_path.exists():
            control_path.rename(STATE / ('control-stopped-' + str(time.time_ns())))
        print('Owned server stopped.', flush=True)


if __name__ == '__main__':
    main()
