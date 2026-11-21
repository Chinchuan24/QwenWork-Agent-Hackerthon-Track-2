"""Enumerated negative router matrix; never claims authorized POST workflows."""
import json
import os
import re
from pathlib import Path

from playwright.sync_api import sync_playwright
from aegis import auth, db, gateway
from aegis.app import app
from test_r12_browser import local_server  # noqa: F401


def test_every_router_method_role_viewport(local_server, tmp_path):
    registered = list(app.routes)
    for route in list(registered):
        if hasattr(route, 'original_router'):
            registered.extend(route.original_router.routes)
    routes = [(r, m) for r in registered if hasattr(r, 'methods') for m in sorted(r.methods)]
    run = gateway.create_run('enforce', 'matrix-fixture')
    rid = db.conn().execute('SELECT MAX(id) AS id FROM audit').fetchone()['id']
    rows, failures = [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for role in ['anonymous'] + sorted(auth.ROLES):
            session = None
            if role != 'anonymous':
                username = 'matrix_' + role
                auth.create_user(username, 'synthetic-matrix-password', role)
                session = auth.login(username, 'synthetic-matrix-password')
            for width in (1440, 390):
                context = browser.new_context(base_url=local_server, viewport={'width': width, 'height': 900})
                if session:
                    context.add_cookies([{'name': 'aegis_session', 'value': session['token'], 'url': local_server}])
                external, errors = [], []
                def guard(route):
                    if not route.request.url.startswith(local_server + '/'):
                        external.append('off-host request')
                        route.abort()
                    else:
                        route.continue_()
                context.route('**/*', guard)
                page = context.new_page()
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.on('console', lambda msg: errors.append(msg.text) if msg.type == 'error'
                        and not msg.text.startswith('Failed to load resource:') else None)
                for route, method in routes:
                    if session:
                        context.add_cookies([{'name': 'aegis_session', 'value': session['token'], 'url': local_server}])
                    path = route.path
                    for param in re.findall(r'\{([^}:]+)(?::[^}]+)?\}', path):
                        path = re.sub(r'\{' + param + r'(?::[^}]+)?\}',
                            {'run_id': run, 'rid': str(rid)}.get(param, 'matrix-missing'), path)
                    if method not in ('GET', 'HEAD'):
                        response = context.request.fetch(path, method=method, form={
                            'csrf': 'matrix-invalid', 'scenario': 'matrix-missing', 'decision': 'deny',
                            'content': '', 'current': '', 'new': '', 'username': 'matrix-missing',
                            'password': 'synthetic-invalid', 'value': 'matrix-invalid'}, max_redirects=0)
                        expected = [200, 303, 401, 403, 422]
                        kind = 'negative method probe, invalid CSRF; not authorized workflow'
                    else:
                        response = context.request.fetch(path, method=method, max_redirects=0)
                        if path == '/admin/tools/review' and role == 'anonymous':
                            expected = [403]
                        elif path.startswith('/admin/demo') or path.startswith('/breach-clock') or path == '/admin/tools/review':
                            expected = [401] if role == 'anonymous' else ([403] if
                                (role != 'admin' and (path.startswith('/admin/') or role == 'viewer')) else
                                ([404] if 'matrix-missing' in path or path in (
                                    '/admin/demo/source', '/admin/demo/guard', '/admin/demo/briefing', '/admin/demo/results') else [200]))
                        elif path.startswith('/audit/export.'):
                            expected = [200] if role in ('admin', 'auditor') else [403]
                        elif path.startswith('/api/') or path == '/compliance/trust-report.json':
                            expected = [401] if role == 'anonymous' else [200]
                        elif path in ('/login', '/error', '/healthz', '/openapi.json', '/docs', '/docs/oauth2-redirect', '/redoc'):
                            expected = [200]
                        elif role == 'anonymous':
                            expected = [303]
                        elif path == '/admin' or (role == 'viewer' and path in
                                ('/attack-board', '/helper-cards', '/incident-report', '/alarm')):
                            expected = [200] if role == 'admin' else [403]
                        elif 'matrix-missing' in path:
                            expected = [403, 404, 422]
                        else:
                            expected = [200]
                        kind = 'browser GET' if method == 'GET' else 'HTTP HEAD'
                        if method == 'GET' and 'text/html' in response.headers.get('content-type', ''):
                            page.goto(path, wait_until='load')
                    row = dict(route=route.path, method=method, role=role, width=width,
                        expected_statuses=expected, actual_status=response.status, coverage=kind,
                        parameter_case='missing' if 'matrix-missing' in path else 'existing or static')
                    rows.append(row)
                    if response.status not in expected:
                        failures.append(row)
                if errors or external:
                    failures.append(dict(role=role, width=width, errors=errors, external=external))
                context.close()
        browser.close()
    output = Path(os.environ.get('TWINGUARD_MATRIX_RESULTS', str(tmp_path / 'matrix.json')))
    output.write_text(json.dumps(dict(router_method_count=len(routes), roles=5, widths=[1440, 390],
        rows=rows, failures=failures, limitations=[
            'Writes probe rejection only, not valid authorized workflows.',
            'Missing approval/incident/proof/helper cases do not prove existing-record rendering.',
            'Expected HTTP resource errors excluded from JavaScript console errors.']), indent=2) + '\n')
    assert not failures, failures
