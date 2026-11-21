"""Aegis web app: dashboard + gateway API. Server-rendered, strict CSP,
no inline scripts, all untrusted text escaped. One command starts it: run.py"""
import csv
import io
import json
import os
import subprocess
import sys
import time
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Request, Response, Form
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from starlette.exceptions import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from . import (approvals, audit, auth, config, db, evidence, gateway, policy, qwen_client,
               redteam, suites, world)

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="Twinguard", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")  # Jinja2 autoescape on by default

LAST_SCOREBOARDS = {}
SIGNER_MANAGER = None


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp


app.add_middleware(SecurityHeaders)


def startup():
    # Refuse missing encryption authority before users/policy/signer mutations.
    if evidence._load_key() is None:
        raise evidence.EvidenceKeyError('startup evidence key unavailable')
    db.init_db()
    auth.ensure_demo_users()
    policy.ensure_default(str(ROOT / "policies" / "default.yaml"))
    policy.ensure_security_rules(str(ROOT / "policies" / "default.yaml"))
    # R3: launch the separate signer unless one is already configured (tests)
    global SIGNER_MANAGER
    if config.AEGIS_SIGNER_PORT <= 0:
        from . import signer_client
        SIGNER_MANAGER = signer_client.SignerManager(config.AEGIS_SIGNER_STATE)
        config.AEGIS_SIGNER_PORT = SIGNER_MANAGER.port
    audit.migrate_to_signer()
    evidence.require_key_for_startup()
    evidence.migrate_once()
    audit.record("server_started", {"live_mode": config.live_mode()})
    if config.live_mode():
        # confirm the endpoint and model names against the account's model list
        res = qwen_client.verify_models()
        audit.record("models_verified", {"ok": res["ok"], "missing": res["missing"],
                                         "error": res.get("error", "")})


@app.on_event("startup")
def _startup():
    startup()


# ---------------------------------------------------------------- helpers
def current_user(request: Request):
    return auth.user_by_token(request.cookies.get("aegis_session", ""))


def render(request, name, user=None, status_code=200, **ctx):
    ctx.setdefault("request", request)
    ctx["user"] = user
    ctx["csrf"] = user["csrf"] if user else ""
    ctx["live_mode"] = config.live_mode()
    ctx["kill_switch"] = gateway.kill_switch_on()
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def need_login(request):
    user = current_user(request)
    if user is None:
        return None, RedirectResponse("/login", status_code=303)
    return user, None


def csrf_ok(request, user, token) -> bool:
    return auth.check_csrf(user, token or "")


from .breach_views import make_router

app.include_router(make_router(render))


async def demo_access(request: Request):
    user = current_user(request)
    if user is None:
        raise HTTPException(401, 'Sign in required')
    if (request.headers.get('X-Agent-Token') or user['role'] != 'admin'
            or user.get('must_change')):
        raise HTTPException(403, 'Human administrator required')
    if request.method == 'POST':
        form = await request.form()
        if not csrf_ok(request, user, str(form.get('csrf', ''))):
            raise HTTPException(403, 'Bad CSRF token')
        if set(form) != {'csrf'} or request.query_params:
            raise HTTPException(422, 'No paths or manifest inputs accepted')
    return user


def demo_result_path(request):
    import hashlib
    # Private OS-user temp storage, further scoped to this authenticated session.
    scope = hashlib.sha256(request.cookies['aegis_session'].encode()).hexdigest()
    root = Path(tempfile.gettempdir()) / ('twinguard-demo-web-' + str(os.getuid()))
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Unsafe demo storage')
    return root / (scope + '.json')


@app.get('/admin/tools/review', response_class=HTMLResponse)
@app.post('/admin/tools/review', response_class=HTMLResponse)
async def operator_tool_review(request: Request):
    import hashlib
    import hmac
    import time
    from .tool_passport import ToolPassport

    user = current_user(request)
    if (user is None or request.headers.get('X-Agent-Token')
            or user['role'] != 'admin' or user.get('must_change')):
        raise HTTPException(403, 'Human administrator required')
    form = await request.form() if request.method == 'POST' else None
    if form is not None:
        if (not csrf_ok(request, user, str(form.get('csrf', '')))
                or form.get('confirm') != 'approve'):
            raise HTTPException(403, 'CSRF and explicit confirmation required')
        if set(form) != {'csrf', 'password', 'confirm', 'snapshot_digest'} or request.query_params:
            raise HTTPException(422, 'Only displayed snapshot confirmation accepted')
        row = db.conn().execute('SELECT * FROM users WHERE username=?',
                                (user['username'],)).fetchone()
        if (auth._throttled(user['username']) or row is None
                or not auth._verify_pw(str(form.get('password', '')),
                                       bytes.fromhex(row['salt']), row['pw_hash'])):
            auth._login_fails.setdefault(user['username'], []).append(time.time())
            raise HTTPException(403, 'Password reauthentication required')
        auth._login_fails.pop(user['username'], None)
    receipt = None
    with gateway._PIPELINE_LOCK, audit.publication_lock(), db.conn():
        c = db.conn()
        if form is not None:
            # Reserve the writer before reading the baseline, across processes.
            c.execute('BEGIN IMMEDIATE')
        try:
            saved = db.get_setting('sandbox_tool_approvals', '')
            baseline = json.loads(saved) if saved else None
            if baseline is None:
                version = 0
            else:
                if (type(baseline) is not dict or set(baseline) != {'version', 'approved_records'}
                        or type(baseline['version']) is not int or baseline['version'] < 1):
                    raise ValueError('Invalid baseline')
                ToolPassport(baseline['approved_records'])
                version = baseline['version']
            records = [{'name': tool['function']['name'],
                        'description': tool['function']['description'],
                        'input_schema': tool['function']['parameters']}
                       for tool in gateway._current_tool_schemas()]
            records = json.loads(json.dumps(records, allow_nan=False))
            passport = ToolPassport(records)
            if not records or any(passport.check(record).status != 'allow' for record in records):
                raise ValueError('Unsafe catalog')
            snapshot = {'version': version + 1, 'approved_records': records,
                        'previous_baseline': saved}
            digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True,
                separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        except (ValueError, TypeError, KeyError):
            raise HTTPException(409, 'Invalid sandbox catalog; review refused') from None
        if form is not None:
            if not hmac.compare_digest(str(form.get('snapshot_digest', '')), digest):
                raise HTTPException(409, 'Snapshot changed; reload and review again')
            if audit.verify()['ok'] is not True:
                raise HTTPException(503, 'Audit verification failed; review refused')
            now = time.time()
            approved_value = json.dumps({
                'version': version + 1, 'approved_records': records}, allow_nan=False)
            baseline_hash = hashlib.sha256(approved_value.encode()).hexdigest()
            try:
                c.execute(
                    'INSERT INTO settings(key,value,changed_by,ts) VALUES(?,?,?,?) '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value, '
                    'changed_by=excluded.changed_by, ts=excluded.ts',
                    ('sandbox_tool_approvals', approved_value, user['username'], now))
                # One local commit; checkpoint failure retains both durable rows.
                recorded = audit.record_decision('sandbox_tools_reviewed', {
                    'by': user['username'], 'version': version + 1,
                    'snapshot_digest': digest, 'fingerprints': dict(passport.approved),
                    'baseline_hash': baseline_hash}, trusted_ts=now)
                if recorded['checkpoint_ok'] is not True:
                    raise HTTPException(503, 'Review saved but audit checkpoint unavailable; no success receipt')
                # A separate promotion receipt exists only after durable checkpoint
                # acknowledgement. Later checkpoint recovery cannot promote a review.
                if audit.verify()['ok'] is not True:
                    raise HTTPException(503, 'Review saved but audit verification failed; no authority')
                c.execute('BEGIN IMMEDIATE')
                authority = audit.record_decision('sandbox_tools_authorized', {
                    'review_event_id': recorded['event_id'], 'baseline_hash': baseline_hash,
                    'by': user['username']}, trusted_ts=time.time())
                if authority['checkpoint_ok'] is not True or audit.verify()['ok'] is not True:
                    raise HTTPException(503, 'Review saved but authority checkpoint unavailable')
                db.set_setting('sandbox_tool_authority', json.dumps({
                    'event_id': authority['event_id'], 'baseline_hash': baseline_hash}),
                    user['username'], now)
                gateway._sandbox_tool_registry(remember_only=True)
                receipt = recorded['event_id']
            except BaseException:
                c.rollback()
                raise
    template = templates.env.from_string("""
{% extends 'base.html' %}
{% block content %}
<h1>Review sandbox tools</h1>
<p>Sandbox only. This is not authorization to execute live tools.</p>
<p>Approval version {{ version }}. Snapshot digest: <code>{{ digest }}</code></p>
{% for record in records %}
<h2>{{ record.name }}</h2><p>{{ record.description }}</p>
<pre>{{ record.input_schema | tojson(indent=2) }}</pre>
<p>Fingerprint: <code>{{ fingerprints[record.name] }}</code></p>
{% endfor %}
{% if receipt %}<p>Saved approval audit receipt: {{ receipt }}</p>
<a href="/admin/demo">Return to demo</a>
{% else %}
<form method="post" action="/admin/tools/review">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="snapshot_digest" value="{{ digest }}">
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<label><input type="checkbox" name="confirm" value="approve" required> I explicitly approve this exact displayed sandbox snapshot.</label>
<button type="submit">Approve reviewed snapshot</button>
</form>{% endif %}
{% endblock %}
""")
    return HTMLResponse(template.render(request=request, user=user, csrf=user['csrf'],
        live_mode=False, kill_switch=gateway.kill_switch_on(), records=records,
        fingerprints=dict(passport.approved), version=version + 1, digest=digest, receipt=receipt),
        headers={'Cache-Control': 'no-store'})


@app.get('/admin/demo', response_class=HTMLResponse)
async def demo_page(request: Request):
    user = await demo_access(request)
    result = None
    try:
        path = demo_result_path(request)
        if path.exists():
            if path.is_symlink():
                raise ValueError('Unsafe result')
            result = json.loads(path.read_text())
    except (OSError, ValueError):
        raise HTTPException(503, 'Demo result unavailable') from None
    template = templates.env.from_string("""
{% extends 'base.html' %}
{% block title %}Isolated demo | Twinguard{% endblock %}
{% block content %}
<h1>Isolated demo</h1>
<p>Scripted stand-in only, not live evidence. Each reset or run uses a fresh child.
Production history is never reset. Saved operator tool approvals are required.</p>
<p><a href="/breach-clock">Breach clocks and human incident log</a></p>
{% for action, label in [('reset', 'Reset demo'), ('run', 'Run five stories')] %}
<form method="post" action="/admin/demo/{{ action }}">
<input type="hidden" name="csrf" value="{{ csrf }}"><button>{{ label }}</button></form>
{% endfor %}
<p>Backend timing is not browser timing. Exact story outcomes and source coverage
remain unverified; HOLD is not BLOCK. Guard disagreements must come from saved answers.</p>
{% if result %}<h2>Saved isolated result</h2>
<p>Run ID: {{ result.get('run_id', 'Not recorded') }}. Saved at: {{ result.get('saved_at', 'Not recorded') }}.</p>
<p>Links refer to the latest session result, not an immutable signed export.</p>
<nav>{% for view in ['source', 'guard', 'briefing', 'results'] %}
<a href="/admin/demo/{{ view }}">{{ view | title }}</a> {% endfor %}</nav>
{% for record in result.get('result', {}).get('record_projection', []) %}
<a href="/admin/demo/proof/{{ record.record_ref | urlencode }}">Proof {{ record.record_ref }}</a>
{% endfor %}<pre>{{ result | tojson(indent=2) }}</pre>
{% else %}<p>No isolated result for this session.</p>{% endif %}
{% endblock %}
""")
    return HTMLResponse(template.render(request=request, user=user, csrf=user['csrf'],
        live_mode=False, kill_switch=gateway.kill_switch_on(), result=result),
        headers={'Cache-Control': 'no-store'})


@app.get('/admin/demo/proof/{proof_ref}', response_class=HTMLResponse)
@app.get('/admin/demo/source', response_class=HTMLResponse)
@app.get('/admin/demo/guard', response_class=HTMLResponse)
@app.get('/admin/demo/briefing', response_class=HTMLResponse)
@app.get('/admin/demo/results', response_class=HTMLResponse)
async def demo_proof_view(request: Request, proof_ref: str = None):
    user = await demo_access(request)
    try:
        path = demo_result_path(request)
        if not path.exists():
            raise HTTPException(404, 'No isolated result for this session')
        if path.is_symlink():
            raise ValueError('Unsafe result')
        saved = json.loads(path.read_text())
        result = saved['result']
        if not isinstance(result, dict):
            raise ValueError('Invalid result')
        view = request.url.path.rsplit('/', 1)[-1]
        if proof_ref is not None:
            matches = [record for record in result.get('record_projection', [])
                       if record.get('record_ref') == proof_ref]
            if len(matches) != 1:
                raise HTTPException(404, 'Unknown isolated proof')
            data = {'record': matches[0], 'bindings': [binding for binding in
                    result.get('bindings', []) if binding.get('record_ref') == proof_ref]}
            view = 'proof'
        else:
            field = {'source': 'scenarios', 'guard': 'guards',
                     'briefing': 'briefing', 'results': 'scenarios'}[view]
            if field not in result:
                raise HTTPException(404, 'View not recorded in this isolated result')
            data = result[field]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(503, 'Demo result unavailable') from None
    references = set()
    valid_refs = {record.get('record_ref') for record in result.get('record_projection', [])}
    def collect_refs(value):
        if isinstance(value, dict):
            for item in value.values():
                collect_refs(item)
        elif isinstance(value, list):
            for item in value:
                collect_refs(item)
        elif isinstance(value, str) and value in valid_refs:
            references.add(value)
    collect_refs(data)
    template = templates.env.from_string("""
{% extends 'base.html' %}
{% block title %}Isolated {{ view }} | Twinguard{% endblock %}
{% block content %}
<h1>Isolated {{ view | title }}</h1>
<p>Run ID: {{ saved.get('run_id', 'Not recorded') }}. Saved at: {{ saved.get('saved_at', 'Not recorded') }}.</p>
<p>This URL refers to the latest session result, not an immutable signed export.</p>
<p>Saved scripted stand-in only, not live evidence. Missing facts remain unknown.
HOLD is not BLOCK. Source text is only what the child recorded.</p>
<p><a href="/admin/demo">Back to isolated demo</a></p>
<pre>{{ data | tojson(indent=2) }}</pre>
{% if references %}<nav aria-label="Saved evidence links"><ul>{% for ref in references %}<li><a href="/admin/demo/proof/{{ ref | urlencode }}">Open proof {{ ref }}</a></li>{% endfor %}</ul></nav>{% endif %}
{% endblock %}
""")
    return HTMLResponse(template.render(request=request, user=user, csrf=user['csrf'],
        live_mode=False, kill_switch=gateway.kill_switch_on(), view=view, data=data, saved=saved, references=sorted(references)),
        headers={'Cache-Control': 'no-store'})


@app.post('/admin/demo/reset')
@app.post('/admin/demo/run')
async def demo_execute(request: Request):
    user = await demo_access(request)
    from . import demo_repeatability
    from .tool_passport import ToolPassport
    from starlette.concurrency import run_in_threadpool
    def execute():
        import fcntl
        path = demo_result_path(request)
        # OS lock also serializes sessions across server workers.
        with open(path.with_suffix('.lock'), 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            path.unlink(missing_ok=True)
            return attempt(path)

    def attempt(path):
        try:
            manifest = json.loads(db.get_setting('sandbox_tool_approvals', 'null'))
            if (type(manifest) is not dict or set(manifest) != {'version', 'approved_records'}
                    or type(manifest['version']) is not int or manifest['version'] < 1
                    or type(manifest['approved_records']) is not list or not manifest['approved_records']):
                raise ValueError('Missing approvals')
            passport = ToolPassport(manifest['approved_records'])
            if any(passport.check(record).status != 'allow' for record in manifest['approved_records']):
                raise ValueError('Invalid approvals')
        except (ValueError, TypeError, KeyError):
            return HTMLResponse('Explicit saved operator approvals required. '
                '<a href="/admin/tools/review">Review current sandbox tools</a>', status_code=409)
        from uuid import uuid4
        result, seconds = demo_repeatability._launch(
            request.url.path.endswith('/run'), manifest)
        saved = demo_repeatability.normalize({'mode': 'scripted stand-in',
            'result': result, 'backend_seconds': seconds, 'browser_seconds': None})
        saved.update(run_id=str(uuid4()), saved_at=datetime.now(ZoneInfo('UTC')).isoformat())
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
                temporary = Path(output.name)
                json.dump(saved, output, allow_nan=False)
            temporary.replace(path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return RedirectResponse('/admin/demo', status_code=303)

    try:
        return await run_in_threadpool(execute)
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired):
        raise HTTPException(503, 'Isolated demo failed; no success confirmed') from None


CLEAR_ROLES = ("admin", "approver", "auditor")


def dec_for(user, text):
    """Stored evidence decrypts only for the right roles; everyone else sees
    a placeholder, never clear text."""
    if user and user.get("role") in CLEAR_ROLES:
        return evidence.dec_json(text) if text else None
    return {"encrypted": "clear text withheld for your role"} if text else None


def forbidden(request, user, msg="Your role cannot do that"):
    return render(request, "error.html", user, message=msg, status_code=403)


@app.exception_handler(HTTPException)
async def html_not_found(request: Request, exc: HTTPException):
    if (exc.status_code == 404 and 'text/html' in request.headers.get('accept', '')
            and not request.url.path.startswith('/api/')):
        return render(request, 'error.html', current_user(request), status_code=404,
                      title='Page not found', message='This page does not exist.')
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def html_record_validation(request: Request, exc: RequestValidationError):
    if (request.method == 'GET' and 'text/html' in request.headers.get('accept', '')
            and request.url.path.startswith('/audit/record/')
            and any(error['loc'] == ('path', 'rid') for error in exc.errors())):
        return render(request, 'error.html', current_user(request), status_code=422,
                      title='Invalid record ID', message='Use a numeric audit record ID.')
    return await request_validation_exception_handler(request, exc)


# ---------------------------------------------------------------- auth
@app.get("/healthz")
def healthz():
    """Unauthenticated liveness probe for containers/proxies. No sensitive data."""
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    result = auth.login(username.strip(), password)
    if result is None:
        return render(request, "login.html", error="Invalid username or password")
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("aegis_session", result["token"], httponly=True, samesite="strict",
                    secure=os.environ.get("AEGIS_HTTPS") == "1",
                    max_age=auth.SESSION_TTL)
    return resp


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    user = current_user(request)
    if user and csrf_ok(request, user, csrf):
        auth.logout(request.cookies.get("aegis_session", ""))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("aegis_session")
    return resp


@app.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    return render(request, "change_password.html", user, error=None)


@app.post("/change-password")
def change_password_submit(request: Request, current: str = Form(...), new: str = Form(...),
                           csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, "Bad CSRF token")
    res = auth.change_password(user["username"], current, new,
                               session_token=request.cookies.get('aegis_session', ''))
    if not res["ok"]:
        return render(request, "change_password.html", user, error=res["error"])
    return RedirectResponse("/", status_code=303)


def must_change_blocked(request, user):
    """Fixed demo passwords must be replaced before privileged actions."""
    if user.get("must_change"):
        return forbidden(request, user,
                         "Change your password first — the published demo password must be "
                         "replaced before privileged actions (Password page)")
    return None


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    from .briefing import build_briefing
    now = time.time()
    day = datetime.fromtimestamp(now, ZoneInfo('Asia/Singapore')).replace(
        hour=0, minute=0, second=0, microsecond=0)
    start, end = day.timestamp(), (day + timedelta(days=1)).timestamp()
    note = None
    records = []
    if user['role'] in CLEAR_ROLES:
        rows = db.conn().execute('SELECT * FROM audit WHERE ts < ? ORDER BY ts, id',
                                 (end,)).fetchall()
        try:
            for row in rows:
                record = dict(row)
                record['detail_json'] = json.dumps(dec_for(user, row['detail_json']))
                records.append(record)
        except (evidence.EvidenceKeyError, ValueError):
            records = []
        else:
            note = build_briefing(records, start=start, end=end)
            if not any(start <= row['ts'] < end for row in records):
                note['headline']['text'] = 'No events were recorded today.'
    # Only project safe metadata. The queue contains encrypted reasons and task text.
    queue = [dict(id=item['id'], status=item['status'], expired=item['expired'],
                  created_by=item['created_by'], decision='HOLD',
                  proof_ids=[row['id'] for row in records
                             if row['event'] == 'approval_requested'
                             and json.loads(row['detail_json']).get('approval') == item['id']])
             for item in approvals.queue()]
    return render(request, 'owner_home.html', user, briefing=note, approvals=queue,
                  review_metrics=approvals.review_metrics() if user['role'] in CLEAR_ROLES else None)


@app.get('/attack-board', response_class=HTMLResponse)
@app.get('/helper-cards', response_class=HTMLResponse)
@app.get('/rule-match', response_class=HTMLResponse)
@app.get('/incident-report', response_class=HTMLResponse)
@app.get('/alarm', response_class=HTMLResponse)
def governance_view(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    page = request.url.path
    if page != '/rule-match' and not auth.require_role(user, 'admin', 'approver', 'auditor'):
        return forbidden(request, user)
    from . import attack_board, card_view, rule_match
    if page == '/attack-board':
        return render(request, 'attack_board.html', user, board=attack_board.load_attack_board(user))
    if page == '/helper-cards':
        view = card_view.load_stored_cards(role=user['role'])
        template = templates.env.from_string("""
{% extends 'base.html' %}
{% block title %}Helper ID cards | Twinguard{% endblock %}
{% block content %}
<h1>Helper ID cards</h1>
<p>These cards do not authorize actions. The gateway must check each action separately.</p>
<p>No helper can edit cards through this view. Administrators can freeze or release one helper.</p>
<p role="status">Missing normal calibration samples remain unknown.</p>
{% for warning in card_view.warnings %}
<p class="banner danger" role="status">{{ warning }}</p>
{% endfor %}
{% for card in card_view.cards %}
<section class="card">
<h2>Card ID: <code>{{ card.helper_id }}</code> | Version {{ card.version }}</h2>
<dl>
<dt>Job (stored session task)</dt><dd>{{ card.job if card.job is not none else 'Not recorded' }}</dd>
{% for key, label in [('tools', 'Stored tools'), ('read_folders', 'Folders it may read'),
 ('read_sensitivity', 'Data levels it may read'), ('never_read', 'Must not read'),
 ('alone', 'May do alone'), ('ask', "Needs the owner's yes"), ('never', 'May never do')] %}
<dt>{{ label }}</dt><dd>
{% if card[key] is none %}Not recorded{% else %}<ul>
{% for value in card[key] %}<li>{{ 'All paths (stored empty prefix)' if key == 'read_folders' and value == '' else value }}</li>
{% else %}<li>None recorded</li>{% endfor %}</ul>{% endif %}
</dd>{% endfor %}
<dt>Frozen</dt><dd>{{ 'Not recorded' if card.frozen is none else 'Yes' if card.frozen else 'No' }}</dd>
<dt>Expiry</dt><dd>{{ card.expiry if card.expiry is not none else 'Not recorded' }}</dd>
<dt>Money limits</dt><dd>{% if card.money_limits is none %}Not recorded{% else %}
{{ card.money_limits.currency }} {{ card.money_limits.per_action }} per action;
{{ card.money_limits.currency }} {{ card.money_limits.per_day }} per day{% endif %}</dd>
</dl>
{% if user.role == 'admin' %}
<form method="post" action="/admin/helpers/{{ card.helper_id }}/freeze">
<input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit">Freeze helper</button></form>
<form method="post" action="/admin/helpers/{{ card.helper_id }}/release">
<input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit">Release helper</button></form>
{% endif %}</section>
{% else %}<p class="banner danger" role="status">No usable card to display.</p>{% endfor %}
<p>Missing metadata is not permission to act. Stored tools and scopes are not task authorization.</p>
{% endblock %}
""")
        return HTMLResponse(template.render(request=request, user=user, csrf=user['csrf'],
                            live_mode=config.live_mode(), kill_switch=gateway.kill_switch_on(),
                            card_view=view))
    if page == '/rule-match':
        return render(request, 'rule_match.html', user, table=rule_match.rule_match_table(),
                      notice=rule_match.NOTICE, sources=rule_match.SOURCES)
    if page == '/incident-report':
        return render(request, 'incident_report.html', user, report=None)
    return render(request, 'alarm.html', user, helpers=[], alarm=None)


@app.post('/admin/helpers/{helper_id}/freeze')
@app.post('/admin/helpers/{helper_id}/release')
def admin_helper_transition(request: Request, helper_id: str, csrf: str = Form('')):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user['role'] != 'admin' or not csrf_ok(request, user, csrf):
        return forbidden(request, user)
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    with gateway._PIPELINE_LOCK:
        if not db.conn().execute('SELECT 1 FROM agent_sessions WHERE id=?', (helper_id,)).fetchone():
            return JSONResponse({'error': 'unknown helper'}, status_code=404)
        try:
            card = gateway._load_card(helper_id)
            gateway._persist_helper_freeze(helper_id, card,
                request.url.path.endswith('/freeze'), user['username'])
        except Exception:
            return JSONResponse({'error': 'helper transition failed closed'}, status_code=503)
    return RedirectResponse('/helper-cards', status_code=303)


@app.post('/admin/helpers/{helper_id}/source-message-scope')
def authorize_source_message_scope(request: Request, helper_id: str,
                                   scope: str = Form(...), csrf: str = Form('')):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user['role'] != 'admin' or not csrf_ok(request, user, csrf):
        return forbidden(request, user)
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    try:
        gateway.publish_source_message_scope(helper_id, json.loads(scope), user['username'])
    except PermissionError:
        return forbidden(request, user)
    except (ValueError, KeyError, TypeError):
        return JSONResponse({'error': 'invalid explicit source message scope'}, status_code=422)
    except Exception:
        return JSONResponse({'error': 'source scope failed closed'}, status_code=503)
    return JSONResponse({'status': 'authorized', 'intent': 'quote-only'})


# ---------------------------------------------------------------- agent API
def _agent_sess(request):
    return gateway.session_by_token(request.headers.get("X-Agent-Token", ""))


@app.post("/api/agent/session")
def agent_session(request: Request):
    sess = _agent_sess(request)
    if sess is None:
        return JSONResponse({"error": "invalid token"}, status_code=401)
    return {"task": sess["task_text"], "limits": json.loads(sess["limits_json"]),
            "session_id": sess["id"]}


@app.post("/api/agent/call")
async def agent_call(request: Request):
    sess = _agent_sess(request)
    if sess is None:
        return JSONResponse({"verdict": "block", "reasons": [
            {"rule": "GATE-TOKEN", "reason": "invalid or missing agent token"}]}, status_code=401)
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    out = gateway.handle_call(request.headers.get("X-Agent-Token", ""),
                              body.get("tool", ""), body.get("args") or {},
                              body.get("idem_key"))
    return out


@app.post("/api/agent/model")
async def agent_model(request: Request):
    """The worker's model calls go through Aegis — it never holds the key.
    One capped client path: spend cap, rate limit, per-session budget, size limit."""
    sess = _agent_sess(request)
    if sess is None:
        return JSONResponse({"error": "invalid token"}, status_code=401)
    if not config.live_mode():
        return JSONResponse({"error": "live model unavailable (no API key configured); use the Scripted agent"})
    try:
        body = await request.json()
    except ValueError:
        body = {}
    messages = body.get("messages", []) if isinstance(body, dict) else []
    try:
        card = gateway._load_card(sess['id'])
        if not card or card.get('frozen') or sess['frozen'] or gateway.kill_switch_on(sess['run_id']):
            return JSONResponse({'error': 'helper authorization refused model egress'})
        payload = {'task': sess['task_text'], 'tool': 'worker_model',
                   'args': {'messages': messages}}
        reviews = {}
        for guard, kind in (('aegis', 'safety_a'), ('delta', 'safety_b')):
            reviews[guard] = qwen_client.judge(kind, payload)
        audit.record('model_egress_review', {'guards': reviews},
                     run_id=sess['run_id'], session_id=sess['id'])
        if any(answer.get('verdict') != 'safe' for answer in reviews.values()):
            return JSONResponse({'error': 'model egress held for review'})
        card = gateway._load_card(sess['id'])
        if not card or card.get('frozen') or not audit.signer_healthy():
            return JSONResponse({'error': 'model egress authorization changed or proof unavailable'})
        msg = qwen_client.worker_chat(sess["id"], messages, gateway.tool_schemas())
        return {"message": msg}
    except qwen_client.JudgeUnavailable as e:
        return JSONResponse({"error": f"model call refused: {e}"})
    except Exception as e:
        return JSONResponse({"error": f"model call failed: {e}"})


# ---------------------------------------------------------------- Live
def _scenario_catalog():
    items = []
    for s in suites.DEMO_SCENARIOS:
        items.append({"key": "demo:" + s["id"], "name": f"Demo {s['id']} — {s['name']}", "scen": s})
    for a in suites.ATTACKS:
        items.append({"key": "attack:" + a["id"], "name": f"{a['id']} — {a['name']} ({a['threat']})", "scen": a})
    for n in suites.NORMAL:
        items.append({"key": "normal:" + n["id"], "name": f"{n['id']} — {n['name']} (normal)", "scen": n})
    return items


def _find_scenario(key):
    for item in _scenario_catalog():
        if item["key"] == key:
            return item["scen"]
    return None


@app.get("/live", response_class=HTMLResponse)
def live(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    runs = db.conn().execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT 12").fetchall()
    return render(request, "live.html", user, catalog=_scenario_catalog(), runs=runs)


@app.post("/live/run")
def live_run(request: Request, scenario: str = Form(...), mode: str = Form("both"),
             csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, "Bad CSRF token")
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    scen = _find_scenario(scenario)
    if scen is None:
        return forbidden(request, user, "Unknown scenario")
    if user["role"] not in ("admin", "approver"):
        return forbidden(request, user)
    results = {}
    modes = ["off", "enforce"] if mode == "both" else [mode]
    for m in modes:
        if m in ("off", "monitor") and user["role"] != "admin":
            continue  # unprotected baseline AND monitor mode are admin-only
        results[m] = redteam.run_scenario(m, scen, created_by=user["username"],
                                          approve_held=False)  # humans approve on screen
    return render(request, "run.html", user, scen=scen, results=results, mode=mode)


WORKER_PROCS = []   # (Popen, run_id) of live workers started by this server


def _prune_workers():
    WORKER_PROCS[:] = [(p, rid) for p, rid in WORKER_PROCS if p.poll() is None]


@app.on_event("shutdown")
def _stop_workers():
    for p, _ in WORKER_PROCS:
        try:
            p.terminate()
        except Exception:
            pass
    WORKER_PROCS.clear()
    if SIGNER_MANAGER is not None:
        SIGNER_MANAGER.stop()


@app.post("/live/agent-run")
def live_agent_run(request: Request, scenario: str = Form(...), csrf: str = Form("")):
    """Launch the real worker as a SEPARATE PROCESS with a clean environment:
    only the gateway address and its one-session token (via ENV, never argv).
    POST + CSRF because it changes state; concurrency is bounded and finished
    processes are cleaned up."""
    user = current_user(request)
    if user is None or user["role"] not in ("admin", "approver"):
        return JSONResponse({"error": "not allowed"}, status_code=403)
    if not csrf_ok(request, user, csrf):
        return JSONResponse({"error": "bad CSRF token"}, status_code=403)
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    if not config.live_mode():
        return JSONResponse({"error": "live agent needs AEGIS_QWEN_API_KEY; use the Scripted run"})
    scen = _find_scenario(scenario)
    if scen is None:
        return JSONResponse({"error": "unknown scenario"}, status_code=400)
    _prune_workers()
    if len(WORKER_PROCS) >= config.WORKER_MAX_CONCURRENT:
        return JSONResponse({"error": "too many live workers running; wait for one to finish"},
                            status_code=429)
    rid = gateway.create_run("enforce", user["username"], scenario=scen.get("id"))
    sess = gateway.start_session(rid, scen["task"], user["username"])
    port = os.environ.get("AEGIS_PORT", "8080")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "AEGIS_GATEWAY_URL": f"http://127.0.0.1:{port}",
           "AEGIS_AGENT_TOKEN": sess["token"]}
    proc = subprocess.Popen(
        [sys.executable, "-m", "aegis.worker", "--gateway", env["AEGIS_GATEWAY_URL"]],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    WORKER_PROCS.append((proc, rid))
    audit.record("worker_launched", {"run": rid, "pid": proc.pid, "by": user["username"]},
                 run_id=rid)
    return JSONResponse({"run_id": rid, "session_id": sess["session_id"], "pid": proc.pid,
                         "note": "worker launched in its own process; poll /api/run/" + rid})


@app.get("/run/{run_id}", response_class=HTMLResponse)
def run_view(request: Request, run_id: str):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    run = db.conn().execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if run is None:
        return forbidden(request, user, "Unknown run")
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE run_id=? ORDER BY created_at", (run_id,)).fetchall()
    actions = db.conn().execute(
        "SELECT * FROM actions WHERE session_id IN (SELECT id FROM agent_sessions WHERE run_id=?) "
        "ORDER BY created_at", (run_id,)).fetchall()
    w = gateway.WORLDS.get(run_id)
    leaks = w.leaks() if w else []
    if user['role'] not in CLEAR_ROLES:
        leaks = [{'kind': leak.get('kind'), 'sink': leak.get('sink')} for leak in leaks]
    steps = []
    for a in actions:
        ap = db.conn().execute("SELECT id FROM approvals WHERE action_id=?", (a["id"],)).fetchone()
        steps.append({"tool": a["tool"], "args": dec_for(user, a["args_json"]),
                      "verdict": a["verdict"], "status": a["status"],
                      "reasons": (dec_for(user, a["reasons_json"]) or []) if user['role'] in CLEAR_ROLES else [
                           {'rule': 'WITHHELD', 'reason': 'clear text withheld for your role'}],
                      "approval_id": ap["id"] if ap else None,
                      "result": dec_for(user, a["result_json"])})
    return render(request, "run.html", user, scen={"id": run["scenario"], "name": run["label"]},
                  results={run["mode"]: {"run_id": run_id, "steps": steps, "leaks": leaks,
                                          "sent_count": len(w.sent) if w else 0}},
                  mode=run["mode"], task=(sess[0]["task_text"] if sess else "") if user['role'] in CLEAR_ROLES
                   else 'clear text withheld for your role')


@app.get("/api/run/{run_id}")
def api_run(run_id: str, request: Request):
    user = current_user(request)
    if user is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    actions = db.conn().execute(
        "SELECT tool, verdict, status, reasons_json, created_at FROM actions "
        "WHERE session_id IN (SELECT id FROM agent_sessions WHERE run_id=?) ORDER BY created_at",
        (run_id,)).fetchall()
    w = gateway.WORLDS.get(run_id)
    steps = []
    for a in actions:
        d = dict(a)
        reasons = dec_for(user, d.pop("reasons_json")) or []
        if user["role"] not in CLEAR_ROLES:
            reasons = [{'rule': 'WITHHELD', 'reason': 'clear text withheld for your role'}]
        d["reasons"] = reasons
        steps.append(d)
    leaks = w.leaks() if w else []
    if user['role'] not in CLEAR_ROLES:
        leaks = [{'kind': leak.get('kind'), 'sink': leak.get('sink')} for leak in leaks]
    return {"steps": steps, "leaks": leaks}


# ---------------------------------------------------------------- Approvals
@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    return render(request, "approvals.html", user, queue=approvals.queue(),
                  review_metrics=approvals.review_metrics())


@app.get("/approvals/{approval_id}", response_class=HTMLResponse)
def approval_detail(request: Request, approval_id: str):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    ap = approvals.get(approval_id)
    if ap is None:
        return forbidden(request, user, "Unknown approval")
    action = db.conn().execute("SELECT * FROM actions WHERE id=?", (ap["action_id"],)).fetchone()
    sess = db.conn().execute("SELECT * FROM agent_sessions WHERE id=?", (action["session_id"],)).fetchone()
    reasons = (dec_for(user, action["reasons_json"]) or []) if user['role'] in CLEAR_ROLES else [
        {'rule': 'Withheld', 'reason': 'clear text withheld for your role'}]
    facts = [r for r in reasons if not r.get("ai_written")]
    ai_notes = [r for r in reasons if r.get("ai_written")]
    w = gateway.get_world(sess["run_id"])
    if user["role"] in CLEAR_ROLES:
        review_facts = gateway.approval_facts(action, sess, w)
        shown_args = evidence.dec_json(action["args_json"])
    else:
        review_facts = {"tool": action["tool"], "args": {}, "attachments": [],
                        "redaction_preview": [], "exposures": [],
                        "encrypted": "clear text withheld for your role"}
        shown_args = review_facts
    return render(request, "approval_detail.html", user, ap=ap, action=action, sess=sess,
                  args=shown_args, facts=facts, ai_notes=ai_notes,
                  review_facts=review_facts,
                  expired=time.time() > ap["expires_at"])


@app.post('/approvals/{approval_id}/view')
def approval_view(request: Request, approval_id: str, csrf: str = Form('')):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, 'Bad CSRF token')
    ap = approvals.get(approval_id)
    if not ap:
        return JSONResponse({'ok': False}, status_code=404)
    action = db.conn().execute('SELECT session_id FROM actions WHERE id=?', (ap['action_id'],)).fetchone()
    sess = db.conn().execute('SELECT created_by FROM agent_sessions WHERE id=?', (action['session_id'],)).fetchone()
    if user['role'] not in ('admin', 'approver') or user['username'] == sess['created_by']:
        return forbidden(request, user)
    if ap['status'] != 'pending' or ap['expires_at'] < time.time():
        return JSONResponse({'ok': False}, status_code=409)
    return approvals.mark_view(approval_id, user)


@app.post("/approvals/{approval_id}/decide")
def approval_decide(request: Request, approval_id: str, decision: str = Form(...),
                    freeze: str = Form(""), csrf: str = Form(""), reason: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, "Bad CSRF token")
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    res = approvals.decide(approval_id, user, decision, freeze=bool(freeze), reason=reason)
    if res.get('error') == 'type one short reason before approving':
        return RedirectResponse(f'/approvals/{approval_id}', status_code=303)
    return render(request, "approval_result.html", user, res=res, approval_id=approval_id)


# ---------------------------------------------------------------- Audit
@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, verify: str = ""):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    rows = db.conn().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    v = audit.verify() if verify else None
    return render(request, "audit.html", user, rows=rows, verify_result=v)


@app.get("/audit/record/{rid}", response_class=HTMLResponse)
def audit_record(request: Request, rid: int):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    row = db.conn().execute("SELECT * FROM audit WHERE id=?", (rid,)).fetchone()
    if row is None:
        return forbidden(request, user, "Unknown record")
    return render(request, "audit_record.html", user, row=row,
                  detail=json.dumps(dec_for(user, row["detail_json"]), indent=2))


@app.get("/audit/export.json")
def audit_export_json(request: Request):
    user = current_user(request)
    if user is None or user["role"] not in ("admin", "auditor"):
        return JSONResponse({"error": "not allowed"}, status_code=403)
    return JSONResponse(audit.export_records())


@app.get("/audit/export.csv")
def audit_export_csv(request: Request):
    user = current_user(request)
    if user is None or user["role"] not in ("admin", "auditor"):
        return PlainTextResponse("not allowed", status_code=403)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "run_id", "session_id", "event", "detail_json", "prev_hash", "hash"])
    for r in audit.export_records():
        w.writerow([r["id"], r["ts"], r["run_id"], r["session_id"], r["event"],
                    r["detail_json"], r["prev_hash"], r["hash"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


# ---------------------------------------------------------------- Policies
@app.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    versions = db.conn().execute("SELECT version, activated_by, ts, note FROM policy_versions ORDER BY version DESC").fetchall()
    return render(request, "policies.html", user, rules=policy.active_rules(),
                  versions=versions, active=policy.active_version(), error=None, content="")


@app.post("/policies/activate")
def policies_activate(request: Request, content: str = Form(...), password: str = Form(""),
                      csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, "Bad CSRF token")
    if user["role"] != "admin":
        return forbidden(request, user)
    versions = db.conn().execute("SELECT version, activated_by, ts, note FROM policy_versions ORDER BY version DESC").fetchall()

    def policy_error(msg):
        return render(request, "policies.html", user, rules=policy.active_rules(),
                      versions=versions, active=policy.active_version(),
                      error=msg, content=content)

    # changing the rules requires a second login, like the kill switch
    if auth.login(user["username"], password) is None:
        return policy_error("Policy change refused: re-authentication failed; previous version stays active")
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    try:
        v = policy.activate(content, user["username"], "dashboard edit")
        return RedirectResponse("/policies", status_code=303)
    except Exception as e:
        return policy_error(f"Policy refused, previous version stays active: {e}")


# ---------------------------------------------------------------- Red Team
@app.get("/redteam", response_class=HTMLResponse)
def redteam_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    return render(request, "redteam.html", user, boards=LAST_SCOREBOARDS,
                  attacks=suites.ATTACKS, normals=suites.NORMAL, evasions=suites.EVASION)


@app.post("/redteam/run")
def redteam_run(request: Request, subset: str = Form("smoke"), csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if not csrf_ok(request, user, csrf):
        return forbidden(request, user, "Bad CSRF token")
    if user["role"] not in ("admin", "approver"):
        return forbidden(request, user)
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    subset = subset if subset in ("smoke", "full") else "smoke"
    cmp = redteam.comparison(subset=subset, created_by=user["username"])
    LAST_SCOREBOARDS["latest"] = cmp
    db.set_setting("scoreboard_last",
                   json.dumps({k: cmp[k] for k in ("off", "on", "evasion_off", "evasion_on", "live")},
                              default=str),
                   user["username"], time.time())
    audit.record("redteam_run", {"subset": subset, "by": user["username"],
                                 "off_leak_runs": cmp["off"]["attack_leak_runs"],
                                 "on_stopped": cmp["on"]["attacks_stopped"],
                                 "evasion_on_stopped": cmp["evasion_on"]["attacks_stopped"],
                                 "live": "waiting-for-key" if cmp["live"].get("waiting_for_key") else "ran"})
    return render(request, "redteam.html", user, boards=LAST_SCOREBOARDS,
                  attacks=suites.ATTACKS, normals=suites.NORMAL, evasions=suites.EVASION)


# ---------------------------------------------------------------- Compliance
# References verified against official sources on 2026-11-17 (see
# docs/decisions.md D20): EU AI Act Chapter III article titles, OWASP LLM
# Top 10 2025, OWASP Agentic Threats & Mitigations v1.0 T-codes, NIST AI RMF
# 1.0 subcategory texts. ISO/IEC 42001 clause numbers are not publicly
# verifiable, so only the standard-level reference is claimed. Mappings are
# best-effort alignments, NOT a compliance certification.
COMPLIANCE = [
    ("Task limits + least privilege", "OWASP LLM06 Excessive Agency; Agentic T2 Tool Misuse, T3 Privilege Compromise", "NIST AI RMF GOVERN 1.2, MANAGE 2.2", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 9 (risk management)"),
    ("Injection Shield (content cleaning + judges)", "OWASP LLM01 Prompt Injection; Agentic T2 Tool Misuse, T6 Intent Breaking & Goal Manipulation", "NIST AI RMF MEASURE 2.7", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (accuracy, robustness, cybersecurity)"),
    ("Data Firewall (outgoing data checks, redaction)", "OWASP LLM02 Sensitive Information Disclosure", "NIST AI RMF MEASURE 2.10, MANAGE 2.2", "ISO/IEC 42001 (AI management system)", "No direct article claimed (the data-governance article concerns training data, not outgoing data)"),
    ("Client scope lock + session rules", "OWASP Agentic T3 Privilege Compromise; LLM06 Excessive Agency", "NIST AI RMF MANAGE 2.2", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (cybersecurity)"),
    ("Human approval, fingerprint-bound, no self-approval", "OWASP LLM06 Excessive Agency; Agentic T10 Overwhelming Human-in-the-Loop (mitigated)", "NIST AI RMF GOVERN 3.2", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 14 (human oversight)"),
    ("Tamper-evident audit + outside checkpoints", "OWASP Agentic T8 Repudiation & Untraceability (no direct LLM Top 10 item)", "NIST AI RMF MEASURE 2.8, MANAGE 4.1", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 12 (record-keeping)"),
    ("Explainable decisions (rule ID, reason, evidence)", "OWASP Agentic T8 Repudiation & Untraceability (traceability; no direct LLM Top 10 item)", "NIST AI RMF MEASURE 2.9", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 13 (transparency)"),
    ("Fail-closed pipeline, hard rules", "OWASP LLM06 Excessive Agency; Agentic T2 Tool Misuse", "NIST AI RMF MANAGE 2.4", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (robustness)"),
    ("Rate limits, spending cap, loop detection, freeze", "OWASP LLM10 Unbounded Consumption; Agentic T4 Resource Overload", "NIST AI RMF MANAGE 2.4", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (robustness)"),
    ("Logins, roles, CSRF, CSP, escaping", "OWASP LLM05 Improper Output Handling; Agentic T9 Identity Spoofing & Impersonation", "NIST AI RMF MANAGE 4.1", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (cybersecurity)"),
    ("Red Team suites + honest scoreboard", "OWASP LLM01 Prompt Injection; Agentic threats (general)", "NIST AI RMF MEASURE 2.7", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (robustness)"),
    ("Sandbox-only, reserved domains, fresh world per run", "OWASP LLM06 Excessive Agency; Agentic T2 Tool Misuse", "NIST AI RMF MANAGE 2.2", "ISO/IEC 42001 (AI management system)", "EU AI Act Art. 15 (cybersecurity)"),
]


@app.get("/compliance", response_class=HTMLResponse)
def compliance_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    return render(request, "compliance.html", user, table=COMPLIANCE)


@app.get("/compliance/trust-report.json")
def trust_report(request: Request):
    user = current_user(request)
    if user is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    return JSONResponse({
        "generated_at": time.time(), "aegis_version": __import__("aegis").__version__,
        "built_by": "Qwen — everything in this project was built by Qwen",
        "judge_mode": "live" if config.live_mode() else "standin (labelled, deterministic)",
        "audit_verify": audit.verify(), "policy_version": policy.active_version(),
        "controls": [{"control": c[0], "owasp": c[1], "nist": c[2], "iso": c[3], "eu": c[4]}
                     for c in COMPLIANCE],
        "scoreboard": json.loads(db.get_setting("scoreboard_last", "{}")),
        "spend": qwen_client.spend_meter(),
        "stated_limits": [
            "Reworded leaks are stopped by scope/session rules in most cases; where those allow the send, only the AI judge remains (best-effort).",
            "Running totals limit slow money/volume leaks; slow information leaks in small pieces are only partly covered.",
            "The user's typed task is treated as trusted.",
            "Email sender identity comes from the sandbox mail system's sender field.",
            "Agent separation is process-level on one machine; stronger isolation needs containers.",
            "A coordinated rollback of the data folder (newest records AND newest checkpoint lines together) is detected by the external anchor kept outside that folder. Not detected: an attacker controlling database + signing key + checkpoint file + external anchor location together, or a rollback predating the external anchor's creation.",
        ]})


# ---------------------------------------------------------------- Admin
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user["role"] != "admin":
        return forbidden(request, user)
    return render(request, "admin.html", user, users=auth.list_users(),
                  spend=qwen_client.spend_meter(),
                  default_mode=db.get_setting("default_mode", "enforce"),
                  bench=json.loads(db.get_setting("bench_last", "null")),
                  error=None)


@app.post("/admin/bench")
def admin_bench(request: Request, csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user["role"] != "admin" or not csrf_ok(request, user, csrf):
        return forbidden(request, user)
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    from . import bench as bench_mod
    result = bench_mod.measure(n=1000)
    db.set_setting("bench_last", json.dumps(result), user["username"], time.time())
    audit.record("benchmark_run", {"by": user["username"], "n": result["n"],
                                   "judge_mode": result["judge_mode"]})
    return render(request, "admin.html", user, users=auth.list_users(),
                  spend=qwen_client.spend_meter(),
                  default_mode=db.get_setting("default_mode", "enforce"),
                  bench=result, error=None)


@app.post("/admin/kill")
def admin_kill(request: Request, value: str = Form(...), password: str = Form(...),
               csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user["role"] != "admin" or not csrf_ok(request, user, csrf):
        return forbidden(request, user)
    if auth.login(user["username"], password) is None:
        return render(request, "admin.html", user, users=auth.list_users(),
                      spend=qwen_client.spend_meter(),
                      default_mode=db.get_setting("default_mode", "enforce"),
                      error="Re-authentication failed; nothing changed")
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    if value not in ("on", "off"):
        return forbidden(request, user, "Bad value")
    db.set_setting("kill_switch", value, user["username"], time.time())
    audit.record("kill_switch_changed", {"value": value, "by": user["username"]})
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/default-mode")
def admin_default_mode(request: Request, value: str = Form(...), password: str = Form(...),
                       csrf: str = Form("")):
    user, redirect = need_login(request)
    if redirect:
        return redirect
    if user["role"] != "admin" or not csrf_ok(request, user, csrf):
        return forbidden(request, user)
    if auth.login(user["username"], password) is None:
        return render(request, "admin.html", user, users=auth.list_users(),
                      spend=qwen_client.spend_meter(),
                      default_mode=db.get_setting("default_mode", "enforce"),
                      error="Re-authentication failed; nothing changed")
    blocked = must_change_blocked(request, user)
    if blocked:
        return blocked
    if value not in ("enforce", "monitor"):
        return forbidden(request, user, "Default mode can only be enforce or monitor; 'off' exists only inside labelled baseline runs")
    db.set_setting("default_mode", value, user["username"], time.time())
    audit.record("default_mode_changed", {"value": value, "by": user["username"]})
    return RedirectResponse("/admin", status_code=303)


@app.get("/error", response_class=HTMLResponse)
def error_page(request: Request):
    return render(request, "error.html", current_user(request), message="Error")