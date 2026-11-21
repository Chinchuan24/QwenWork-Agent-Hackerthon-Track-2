"""Isolated public simulated demo. Never imports legacy executors or credentials."""
import asyncio
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import re
import sqlite3
import time
from urllib.parse import parse_qs

from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

ROLES = ('viewer', 'approver', 'auditor')
PAGES = {'/': 'Home', '/world': 'Lumen world', '/audit': 'Audit', '/roles': 'Role boundaries'}
from .public_evaluator import CASES, evaluate as evaluate_public
from .mixed_demo import MixedDemo
HEADERS = {
    'Content-Security-Policy': "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}


def create_app():
    if os.getenv('AEGIS_ENV') != 'production' or os.getenv('AEGIS_DEMO_PUBLIC') != '1':
        raise ValueError('This entrypoint requires production public simulated demo')
    if os.getenv('AEGIS_WORKERS', '1') != '1':
        raise ValueError('SQLite production requires single instance and workers=1')
    if any(os.environ.get(k, '').lower() in ('1', 'true', 'yes') for k in ('AEGIS_DEBUG', 'DEBUG')):
        raise ValueError('Production refuses debug mode')
    if any('PASSWORD' in k and v.startswith('demo-') for k, v in os.environ.items() if k.startswith('AEGIS_')):
        raise ValueError('Production refuses fixture passwords')
    root = Path(os.environ['AEGIS_PRODUCTION_DATA_DIR'])
    if not root.is_absolute() or root != root.resolve():
        raise ValueError('Canonical absolute persistent directory required')
    hosts = set(os.getenv('AEGIS_TRUSTED_HOSTS', 'localhost').split(','))
    if '*' in hosts:
        raise ValueError('Explicit trusted hosts required')
    proxies = [ipaddress.ip_network(x.strip()) for x in os.getenv('AEGIS_TRUSTED_PROXY_CIDRS', '').split(',') if x.strip()]
    rates = defaultdict(deque)
    failures = defaultdict(deque)
    state = {}
    max_events = int(os.getenv('AEGIS_DEMO_MAX_EVENTS', '10000'))
    if not 1 <= max_events <= 100000:
        raise ValueError('Event quota must be between 1 and 100000')

    class EventQuotaExceeded(Exception):
        pass

    @contextmanager
    def admission(required=1):
        c = state['db']
        c.execute('BEGIN IMMEDIATE')
        try:
            if c.execute('SELECT COUNT(*) FROM events').fetchone()[0] + required > max_events:
                raise EventQuotaExceeded
            yield
            c.commit()
        except BaseException:
            c.rollback()
            raise

    def event(visitor, generation, name):
        c = state['db']
        previous = c.execute('SELECT signature FROM events ORDER BY id DESC LIMIT 1').fetchone()
        previous = previous[0] if previous else 'genesis'
        payload = json.dumps({'visitor': visitor, 'generation': generation, 'event': name, 'previous': previous}, sort_keys=True)
        signature = hmac.new(state['key'], payload.encode(), hashlib.sha256).hexdigest()
        evidence = state['cipher'].encrypt(payload.encode()).decode()
        c.execute('INSERT INTO events(visitor,generation,event,previous,signature,evidence) VALUES(?,?,?,?,?,?)', (visitor, generation, name, previous, signature, evidence))

    def reset_all():
        c = state['db']
        rows = c.execute('SELECT visitor,generation FROM sessions').fetchall()
        try:
            with admission(len(rows)):
                for visitor, generation in rows:
                    event(visitor, generation + 1, 'nightly_reset')
                c.execute('UPDATE sessions SET generation=generation+1')
                c.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
        except EventQuotaExceeded:
            return False
        return True

    async def maintenance():
        while True:
            now = datetime.now(timezone.utc)
            tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            await asyncio.sleep((tomorrow - now).total_seconds())
            reset_all()

    @asynccontextmanager
    async def lifespan(app):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.stat().st_mode & 0o077:
            raise ValueError('Persistent directory must be owner-only')
        for directory in (root / 'keys', root / 'db', root.parent / 'tmp'):
            if directory.is_symlink():
                raise ValueError('Unsafe persistent subdirectory')
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.stat().st_mode & 0o077:
                raise ValueError('Persistent subdirectories must be owner-only')
        lock = open(root / 'instance.lock', 'a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Preserve shipped first-version storage without rotating existing keys.
            legacy = (root / 'internal.key').exists() or (root / 'public-demo.db').exists()
            keyfile = root / 'internal.key' if legacy else root / 'keys' / 'internal.key'
            database = root / 'public-demo.db' if legacy else root / 'db' / 'public-demo.db'
            if not keyfile.exists() and database.exists():
                raise ValueError('Existing history requires its original internal key')
            if not keyfile.exists():
                fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(Fernet.generate_key()); f.flush(); os.fsync(f.fileno())
            if keyfile.is_symlink() or keyfile.stat().st_nlink != 1 or keyfile.stat().st_mode & 0o077:
                raise ValueError('Unsafe internal key storage')
            state['key'] = keyfile.read_bytes()
            state['cipher'] = Fernet(state['key'])
            if database.is_symlink():
                raise ValueError('Unsafe database storage')
            c = sqlite3.connect(database)
            os.chmod(database, 0o600)
            state['db'] = c
            c.executescript('''
                CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,visitor TEXT,role TEXT,csrf TEXT,generation INTEGER,expires REAL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,visitor TEXT,generation INTEGER,event TEXT,previous TEXT,signature TEXT,evidence TEXT);
                CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'immutable'); END;
            ''')
            state['mixed'] = MixedDemo(database, state['key'])
            # Authenticate and decrypt the full stored chain before admitting traffic.
            previous = 'genesis'
            for visitor, generation, name, prev, sig, encrypted in c.execute('SELECT visitor,generation,event,previous,signature,evidence FROM events ORDER BY id'):
                payload = json.dumps({'visitor': visitor, 'generation': generation, 'event': name, 'previous': prev}, sort_keys=True)
                expected = hmac.new(state['key'], payload.encode(), hashlib.sha256).hexdigest()
                if prev != previous or not hmac.compare_digest(expected, sig) or state['cipher'].decrypt(encrypted.encode()).decode() != payload:
                    raise ValueError('Demo evidence integrity failure')
                previous = sig
            task = asyncio.create_task(maintenance())
            state['ready'] = True
            try:
                yield
            finally:
                state['ready'] = False
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                c.close()
        finally:
            state.clear()
            lock.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.reset_demo_worlds = reset_all

    @app.middleware('http')
    async def boundary(request: Request, call_next):
        peer = request.client.host if request.client else ''
        try:
            trusted = any(ipaddress.ip_address(peer) in network for network in proxies)
        except ValueError:
            trusted = False
        local_probe = ((peer in ('127.0.0.1', '::1', 'testclient') or trusted)
                       and request.method == 'GET' and request.url.path in ('/healthz', '/readyz'))
        if trusted and not local_probe:
            forwarded = request.headers.get('x-forwarded-for', '')
            try:
                # One address only: deployment proxy must replace, not append.
                peer = str(ipaddress.ip_address(forwarded))
            except ValueError:
                return JSONResponse({'error': 'Invalid trusted proxy client'}, 400, headers=HEADERS)
        request.state.client_ip = peer
        scheme = request.url.scheme
        if trusted and request.headers.get('x-forwarded-proto') == 'https':
            scheme = 'https'
        host = request.url.hostname
        response = None
        # Only exact, read-only probes may use transport-local HTTP.
        probe = local_probe
        if (host not in hosts and not (probe and host in ('127.0.0.1', 'localhost'))) or (scheme != 'https' and not probe):
            response = JSONResponse({'error': 'HTTPS and trusted host required'}, 400)
        now = time.monotonic()
        for address in list(rates):
            if not rates[address] or rates[address][-1] < now - 900:
                rates.pop(address, None)
                failures.pop(address, None)
        if len(rates) >= 4096 and peer not in rates:
            response = JSONResponse({'error': 'Capacity limited'}, 429)
        queue = rates[peer] if response is None else deque()
        while queue and queue[0] <= now - 60:
            queue.popleft()
        if len(queue) >= 120:
            response = JSONResponse({'error': 'Rate limited'}, 429, headers={'Retry-After': '60'})
        if response is None:
            queue.append(now)
        if response is None and request.method not in ('GET', 'HEAD', 'POST'):
            response = JSONResponse({'error': 'Method forbidden'}, 405)
        if response is None and request.method == 'POST':
            if 'multipart' in request.headers.get('content-type', '').lower():
                response = JSONResponse({'error': 'Uploads forbidden'}, 415)
            else:
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 16384:
                        response = JSONResponse({'error': 'Body limit'}, 413)
                        break
                if response is None:
                    request._body = bytes(body)
        if response is None:
            try:
                response = await call_next(request)
            except EventQuotaExceeded:
                response = JSONResponse({'error': 'Demo audit capacity reached. Read-only access remains available; operator export and manual volume replacement required.'}, 429)
            except Exception:
                response = JSONResponse({'error': 'Request failed closed'}, 503)
        response.headers.update(HEADERS)
        logging.getLogger('aegis.production').info(json.dumps({'event': 'request', 'method': request.method, 'status': response.status_code}))
        return response

    def session(request):
        token = request.cookies.get('__Host-aegis', '')
        return state['db'].execute('SELECT visitor,role,csrf,generation FROM sessions WHERE token=? AND expires>?', (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()

    def form(csrf, action, controls=''):
        return f'<form method="post" action="{action}"><input type="hidden" name="csrf" value="{csrf}">{controls}</form>'

    @app.get('/healthz')
    async def health():
        return {'live': True}

    @app.get('/readyz')
    async def ready():
        try:
            state['db'].execute('SELECT 1').fetchone()
            probe = b'readiness'
            good = state['cipher'].decrypt(state['cipher'].encrypt(probe)) == probe
            good = good and bool(hmac.new(state['key'], probe, hashlib.sha256).digest())
            capacity = state['db'].execute('SELECT COUNT(*) FROM events').fetchone()[0] < max_events
            ready = bool(state.get('ready') and good and capacity)
            return JSONResponse({'ready': ready, 'database': True, 'signer': False, 'simulated_hmac': good, 'evidence': good, 'capacity': capacity}, 200 if ready else 503)
        except Exception:
            return JSONResponse({'ready': False}, 503)

    @app.get('/audit/export')
    async def export(request: Request):
        s = session(request)
        if not s:
            return JSONResponse({'error': 'Session required'}, 401)
        rows = state['db'].execute('SELECT generation,event FROM events WHERE visitor=? ORDER BY id', (s[0],)).fetchall()
        return {'role': s[1], 'simulated': True, 'outside_effects': 0, 'events': [{'generation': x, 'event': y} for x, y in rows]}

    async def page(request: Request):
        s = session(request)
        candidate = request.cookies.get('__Host-csrf', '')
        csrf = s[2] if s else (candidate if re.fullmatch(r'[A-Za-z0-9_-]{43}', candidate) else secrets.token_urlsafe(32))
        nav = ' '.join(f'<a href="{p}">{name}</a>' for p, name in PAGES.items())
        content = '<p>Public sessions are SCRIPTED. Authorized LIVE sessions use real models on fictional data. No payment, email, upload or real worker execution.</p>'
        if not s:
            content += form(csrf, '/session', '<label for="role">Simulated role</label><select id="role" name="role">' + ''.join(f'<option>{r}</option>' for r in ROLES) + '</select><button>Enter simulated role</button>')
        else:
            content += f'<p>Simulated {s[1]} | World generation {s[3]} | Lumen fictional company</p>'
            mode = 'LIVE: real models, simulated data' if state['mixed'].enabled(s[0]) else 'SCRIPTED'
            content += f'<p>Session mode: {mode}</p>'
            content += form(csrf, '/live/unlock', '<label>Operator-issued live access code <input type="password" name="code" autocomplete="off"></label><button>Unlock model judgments</button>')
            content += '<p>Viewer: observe. Approver: simulate approval. Auditor: inspect scoped metadata. No public administrator.</p>'
            if request.url.path in ('/', '/world'):
                content += '<h2>Twinguard oversight of Lumen Studio</h2><p>Daniel Moss, fictional studio owner. Local simulation only; Allow never dispatches externally.</p>'
                content += '<p>Actual deterministic Lumen policy; semantic checker is an exact-text stand-in, not two live LLM judges.</p>'
                for case, fixture in CASES.items():
                    result = evaluate_public(case)
                    content += f'<section><h3>{html.escape(case.title())}</h3><p>{html.escape(fixture["text"])}</p><p>Twinguard: {result["decision"].upper()}. Rules: {html.escape(", ".join(result["rules"]))}</p><p>Source: {html.escape(fixture["path"])}:1</p>'
                    if s[1] == 'approver':
                        content += form(csrf, '/action', f'<input type="hidden" name="action" value="scenario_{case}"><button>Evaluate {case} locally</button>')
                    content += '</section>'
            content += form(csrf, '/reset', '<button>Reset my simulated world</button>')
            if s[1] == 'approver':
                content += form(csrf, '/action', '<input type="hidden" name="action" value="simulate_approval"><button>Simulate approval</button>')
            rows = state['db'].execute('SELECT generation,event FROM events WHERE visitor=? ORDER BY id DESC LIMIT 20', (s[0],)).fetchall()
            content += '<ul>' + ''.join(f'<li>{g}: {html.escape(e)}</li>' for g, e in rows) + '</ul>'
        response = HTMLResponse(f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Simulated Lumen</title><body><a href="#main">Skip to content</a><header><strong>SIMULATED PUBLIC DEMO. No outside effects. No production admin authority.</strong><nav>{nav}</nav></header><main id="main" tabindex="-1"><h1>{PAGES[request.url.path]}</h1>{content}</main></body></html>')
        if not s:
            response.set_cookie('__Host-csrf', csrf, secure=True, httponly=True, samesite='strict', max_age=3600)
        return response

    for path in PAGES:
        app.add_api_route(path, page, methods=['GET'])

    async def mutate(request: Request):
        s = session(request)
        try:
            fields = parse_qs((await request.body()).decode('utf-8'), strict_parsing=True)
        except (ValueError, UnicodeDecodeError):
            fields = {}
        csrf = fields.get('csrf', [''])[0]
        expected = s[2] if s else request.cookies.get('__Host-csrf', '')
        if not expected or not csrf or not hmac.compare_digest(expected, csrf) or any(len(v) != 1 for v in fields.values()):
            return JSONResponse({'error': 'CSRF refused'}, 403)
        if request.url.path == '/session':
            peer = request.state.client_ip
            q = failures[peer]
            now = time.monotonic()
            while q and q[0] < now - 900:
                q.popleft()
            if len(q) >= 5:
                return JSONResponse({'error': 'Role login locked'}, 429)
            role = fields.get('role', [''])[0]
            if role not in ROLES or set(fields) != {'role', 'csrf'}:
                q.append(now)
                return JSONResponse({'error': 'Public role refused'}, 403)
            count = state['db'].execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
            if count >= 1000:
                return JSONResponse({'error': 'Demo session capacity reached'}, 429)
            token, visitor = secrets.token_urlsafe(32), secrets.token_hex(16)
            with admission():
                state['db'].execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), visitor, role, csrf, 1, time.time() + 3600))
                event(visitor, 1, 'session_started')
            response = RedirectResponse('/', 303)
            response.set_cookie('__Host-aegis', token, secure=True, httponly=True, samesite='strict', max_age=3600)
            return response
        if not s:
            return JSONResponse({'error': 'Session required'}, 401)
        if request.url.path == '/live/unlock' and set(fields) == {'csrf', 'code'}:
            peer = request.state.client_ip
            while failures[peer] and failures[peer][0] < time.monotonic() - 900:
                failures[peer].popleft()
            if len(failures[peer]) >= 5:
                return JSONResponse({'error': 'Unlock locked'}, 429)
            if not state['mixed'].unlock(s[0], fields['code'][0]):
                failures[peer].append(time.monotonic())
                return JSONResponse({'error': 'Access refused'}, 403)
            return RedirectResponse('/world', 303)
        if request.url.path == '/reset' and set(fields) == {'csrf'}:
            with admission():
                event(s[0], s[3] + 1, 'visitor_reset')
                state['db'].execute('UPDATE sessions SET generation=generation+1 WHERE visitor=?', (s[0],))
            return RedirectResponse('/world', 303)
        action = fields.get('action', [''])[0]
        if request.url.path == '/action' and s[1] == 'approver' and action.startswith('scenario_') and set(fields) == {'csrf', 'action'}:
            case = action.removeprefix('scenario_')
            if case in CASES:
                result = evaluate_public(case)
                result = await asyncio.to_thread(state['mixed'].evaluate, s[0],
                    request.state.client_ip, CASES[case], result)
                if session(request) != s:
                    return JSONResponse({'error': 'Session changed; held safely'}, 409)
                with admission():
                    event(s[0], s[3], 'lumen_' + case + '_' + result['decision'])
                return JSONResponse(result)
        if request.url.path == '/action' and s[1] == 'approver' and fields.get('action') == ['simulate_approval'] and set(fields) == {'csrf', 'action'}:
            with admission():
                event(s[0], s[3], 'simulated_approval')
            return RedirectResponse('/audit', 303)
        return JSONResponse({'error': 'Action not allowlisted'}, 403)

    for path in ('/session', '/reset', '/action', '/live/unlock'):
        app.add_api_route(path, mutate, methods=['POST'])
    return app


if __name__ == '__main__':
    import uvicorn
    logger = logging.getLogger('aegis.production')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    # Uvicorn must not reinterpret forwarded headers before our CIDR boundary.
    uvicorn.run(create_app(), host=os.getenv('AEGIS_PRODUCTION_HOST', '127.0.0.1'), port=int(os.getenv('PORT', os.getenv('AEGIS_PRODUCTION_PORT', '8443'))), workers=1, proxy_headers=False, access_log=False, ssl_keyfile=os.getenv('AEGIS_TLS_KEY_FILE'), ssl_certfile=os.getenv('AEGIS_TLS_CERT_FILE'))
