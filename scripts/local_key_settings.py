"""Installed only by the loopback launcher. No credential persistence."""
import html
import threading
import time
import contextvars
from aegis.provider import resolve

_transport_allowed = contextvars.ContextVar('local_provider_transport', default=False)


def network_guard():
    import ipaddress
    import sys
    def check(event, args):
        if event == 'socket.getaddrinfo':
            host = args[0]
            if host not in ('localhost', '127.0.0.1', '::1', None) and not _transport_allowed.get():
                raise PermissionError('Local provider transport required')
        if event in ('socket.connect', 'socket.bind') and isinstance(args[1], tuple):
            host = args[1][0]
            try:
                loopback = host == 'localhost' or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not loopback and (event == 'socket.bind' or not _transport_allowed.get()):
                raise PermissionError('Local provider transport required')
    sys.addaudithook(check)


class SecretStore:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.RLock()
        self.value = None
        self.deadline = 0

    def paste(self, provider, base, model, key):
        if not 8 <= len(key) <= 512:
            raise ValueError('Credential unavailable')
        try:
            value = resolve({'AEGIS_MODEL_PROVIDER': provider,
                             'AEGIS_MODEL_BASE_URL': base,
                             'AEGIS_MODEL_NAME': model,
                             'DEEPSEEK_API_KEY': key, 'AEGIS_QWEN_API_KEY': key,
                             'AEGIS_MODEL_API_KEY': key})
            if value[0] == 'scripted':
                raise ValueError
        except Exception:
            raise ValueError('Provider configuration refused') from None
        with self.lock:
            self.value = value
            self.deadline = self.clock() + 28800

    def snapshot(self):
        with self.lock:
            if self.clock() >= self.deadline:
                self.value = None
            return self.value

    def forget(self):
        with self.lock:
            self.value = None
            self.deadline = 0

    def metadata(self):
        value = self.snapshot()
        return {'source': 'pasted memory' if value else 'environment fallback',
                'provider': value[0] if value else '',
                'model': value[2] if value else '',
                'hint': 'sk-...' + value[3][-4:] if value else ''}


def install(app, hard_offline=False):
    from fastapi import Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    from aegis import app as views, config, qwen_client
    store = SecretStore()
    app.state.local_secret_store = store
    from aegis import provider
    original_transport = provider.open_pinned
    def scoped_transport(request, timeout):
        token = _transport_allowed.set(True)
        try:
            return original_transport(request, timeout)
        finally:
            _transport_allowed.reset(token)
    provider.open_pinned = scoped_transport
    fallback = (config.MODEL_PROVIDER, config.QWEN_BASE_URL,
                config.MODEL_JUDGE, config.QWEN_API_KEY)
    config.provider_snapshot = lambda: store.snapshot() or fallback
    qwen_client._cache.clear()
    config.live_mode = lambda: bool(config.provider_snapshot()[3])
    config.LOCAL_AI = True
    config.LIVE_RETRIES = 0
    config.WORKER_MAX_CALLS_PER_SESSION = config.LOCAL_SESSION_CALLS
    views.templates.env.globals['provider_label'] = lambda: (
        'Live AI ' + config.provider_snapshot()[0] + ' / ' + config.provider_snapshot()[2]
        if config.live_mode() else 'Scripted / no key')
    attempts = {}
    lock = threading.RLock()

    def page(user, message=''):
        info = store.metadata()
        if not store.snapshot():
            info.update(provider=fallback[0], model=fallback[2],
                        source='environment fallback (live)' if fallback[3] else 'disabled / no key')
        body = '<main><h1>Local Provider Settings</h1><p>Memory only. Expires after eight hours; restart forgets pasted keys.</p>'
        body += '<p>' + html.escape(message) + '</p><p>' + html.escape(str(info)) + '</p>'
        body += '<p>Forget removes the pasted override only. An existing environment credential may remain live.</p>'
        if hard_offline:
            body += '<p>Explicit --scripted mode: Settings disabled. Restart normally to enable paste.</p>'
        else:
            csrf = html.escape(user['csrf'], quote=True)
            body += '<form method="post" action="/local-demo/settings/paste" autocomplete="off"><input type="hidden" name="csrf" value="' + csrf + '">'
            body += '<label>Provider <select name="provider"><option>deepseek</option><option>qwen</option><option>openai-compatible</option></select></label>'
            body += '<label>HTTPS base URL <input name="base" type="url"></label><label>Model <input name="model"></label>'
            body += '<label>API key <input name="key" type="password" autocomplete="off" required maxlength="512" value=""></label><button>Use in memory</button></form>'
            for action, label in [('test', 'Test connection (one capped call)'), ('forget', 'Forget pasted key')]:
                body += '<form method="post" action="/local-demo/settings/' + action + '"><input type="hidden" name="csrf" value="' + csrf + '"><button>' + label + '</button></form>'
        return HTMLResponse(body + '</main>', headers={'Cache-Control': 'no-store'})

    @app.get('/local-demo/settings')
    async def settings(request: Request):
        user = views.current_user(request)
        if not user or user['role'] != 'admin':
            return HTMLResponse('Admin required', status_code=403)
        return page(user)

    @app.post('/local-demo/settings/{action}')
    async def change(request: Request, action: str):
        user = views.current_user(request)
        if not user or user['role'] != 'admin' or hard_offline:
            return HTMLResponse('Admin local mode required', status_code=403)
        if int(request.headers.get('content-length', '0')) > 4096:
            return HTMLResponse('Request refused', status_code=413)
        form = await request.form()
        if not views.csrf_ok(request, user, str(form.get('csrf', ''))):
            return HTMLResponse('CSRF required', status_code=403)
        with lock:
            now = time.monotonic()
            recent = [t for t in attempts.get(user['username'], []) if now - t < 60]
            if len(recent) >= 6:
                return HTMLResponse('Settings rate limit', status_code=429)
            attempts[user['username']] = recent + [now]
        message = 'Pasted key forgotten; environment fallback restored.'
        try:
            if action == 'paste':
                store.paste(str(form.get('provider', '')), str(form.get('base', '')),
                            str(form.get('model', '')), str(form.get('key', '')))
                message = 'Pasted override active in server memory.'
            elif action == 'forget':
                store.forget()
            elif action == 'test':
                await __import__('starlette.concurrency', fromlist=['run_in_threadpool']).run_in_threadpool(
                    qwen_client._chat, config.provider_snapshot()[2],
                    [{'role': 'user', 'content': 'Reply OK.'}], None, 0.0, 'local-test')
                message = 'PASS: one capped provider response received.'
            else:
                return HTMLResponse('Unknown action', status_code=404)
        except Exception:
            message = 'HOLD: configuration or provider response unavailable. No details echoed.'
        qwen_client._cache.clear()
        return page(user, message)
