"""Real synthetic writes, seeded detail views, and explicit role denials."""
import json
import os
import secrets
from pathlib import Path
import pytest

from playwright.sync_api import sync_playwright
from aegis import approvals, auth, db, gateway, incident_store, policy
from aegis.app import app
from test_r12_browser import local_server  # noqa: F401
from test_approvals import held_refund


@pytest.mark.parametrize('role', ['anonymous'] + sorted(auth.ROLES))
@pytest.mark.parametrize('width', [1440, 390])
def test_valid_post_and_seeded_details(local_server, tmp_path, reviewed14_sandbox_tools, monkeypatch, role, width):
    from aegis import config
    monkeypatch.setattr(config, 'live_mode', lambda: False)
    rows = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for role in [role]:
            for width in [width]:
                name = 'valid-matrix-' + secrets.token_hex(8)
                password = secrets.token_urlsafe(24)
                auth.create_user(name, password, role if role != 'anonymous' else 'viewer')
                session = auth.login(name, password)
                context = browser.new_context(base_url=local_server, viewport={'width': width, 'height': 900})
                context.set_default_timeout(180000)
                page = context.new_page()
                errors, outside = [], []
                def guard(route):
                    if not route.request.url.startswith(local_server + '/'):
                        outside.append('off-host request')
                        route.abort()
                    else:
                        route.continue_()
                context.route('**/*', guard)
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.on('console', lambda m: errors.append(m.text) if m.type == 'error'
                        and not m.text.startswith('Failed to load resource:') else None)
                def cookies():
                    context.clear_cookies()
                    if role != 'anonymous':
                        context.add_cookies([dict(name='aegis_session', value=session['token'], url=local_server)])
                def check(path, method, expected, form=None, marker=None):
                    cookies()
                    response = context.request.fetch(path, method=method, form=form, max_redirects=0, timeout=180000)
                    rows.append(dict(path=path, method=method, role=role, width=width,
                        expected_status=expected, actual_status=response.status,
                        evidence='valid synthetic form and state assertions' if method == 'POST' else 'seeded browser detail'))
                    assert response.status == expected, rows[-1]
                    if marker:
                        assert marker in response.text(), (path, role, response.text()[:200])
                    if method == 'GET' and 'text/html' in response.headers.get('content-type', ''):
                        page.goto(path)
                    return response
                admin = role == 'admin'
                writer = role in ('admin', 'approver')
                anon = role == 'anonymous'
                csrf = session['csrf']
                run, helper, hold = held_refund()
                # A fresh held action per identity ensures no prior decision masks authorization.
                helper_run = gateway.create_run('enforce', name)
                own = gateway.start_session(helper_run, 'Email Rosa a public brochure.', name)
                scope_run = gateway.create_run('enforce', name)
                scope_helper = gateway.start_session(scope_run, 'Quote published prices.', name)
                from aegis import lumen_world
                gateway.WORLDS[scope_run] = lumen_world.fresh()
                from aegis import breach_incident
                seed_name = 'incident-seed-' + secrets.token_hex(8)
                auth.create_user(seed_name, password, 'admin')
                seed_session = auth.login(seed_name, password)
                incident = breach_incident.create_incident(seed_session['token'], seed_session['csrf'],
                    title='Synthetic matrix incident', facts={}, timestamp=__import__('time').time())['id']
                check('/run/' + run, 'GET', 303 if anon else 200)
                check('/approvals/' + hold['approval_id'], 'GET', 303 if anon else 200)
                check('/breach-clock/' + incident, 'GET', 401 if anon else (403 if role == 'viewer' else 200))
                # Every registered POST is exercised, without CSRF bypass or mocked handlers.
                forms = {
                    '/login': dict(username=name, password=password),
                    '/logout': dict(csrf=csrf),
                    '/change-password': dict(csrf=csrf, current=password, new=password + '-changed'),
                    '/breach-clock': dict(csrf=csrf, text='Synthetic matrix write', count='1', harm='no'),
                    '/breach-clock/{incident_id}/steps': dict(csrf=csrf, text='Synthetic follow-up'),
                    '/admin/tools/review': dict(csrf=csrf, password=password, confirm='approve', snapshot_digest=''),
                    '/admin/demo/run': dict(csrf=csrf), '/admin/demo/reset': dict(csrf=csrf),
                    '/admin/helpers/{helper_id}/freeze': dict(csrf=csrf),
                    '/admin/helpers/{helper_id}/release': dict(csrf=csrf),
                    '/admin/helpers/{helper_id}/source-message-scope': dict(csrf=csrf, scope=json.dumps([
                        dict(intent='quote-only', sources=['marketing/price_list.md'], args=dict(to='limwj@greenstep.example',
                            subject='Published prices', body='The published website package is SGD 7,200.', attachment_ids=[]))])),
                    '/api/agent/session': {}, '/api/agent/call': {}, '/api/agent/model': {},
                    '/live/run': dict(csrf=csrf, scenario='normal:N01', mode='enforce'),
                    '/live/agent-run': dict(csrf=csrf, scenario='normal:N01'),
                    '/approvals/{approval_id}/view': dict(csrf=csrf),
                    '/approvals/{approval_id}/decide': dict(csrf=csrf, decision='approve', reason='Synthetic invoice checked.'),
                    '/policies/activate': dict(csrf=csrf, password=password, content=(Path(__file__).resolve().parents[1] / 'policies/default.yaml').read_text()),
                    '/redteam/run': dict(csrf=csrf, subset='smoke'),
                    '/admin/bench': dict(csrf=csrf),
                    '/admin/kill': dict(csrf=csrf, password=password, value='off'),
                    '/admin/default-mode': dict(csrf=csrf, password=password, value='enforce'),
                }
                registered = list(app.routes)
                for route in list(registered):
                    if hasattr(route, 'original_router'):
                        registered.extend(route.original_router.routes)
                posts = [r for r in registered if 'POST' in getattr(r, 'methods', set())]
                assert set(forms) == {r.path for r in posts}
                # Credential mutations last; login/logout cannot erase the role under test.
                posts.sort(key=lambda r: (r.path in ('/change-password', '/logout', '/login'), r.path))
                for route in posts:
                    template = route.path
                    if template.endswith(('/decide', '/view')):
                        run, helper, hold = held_refund()
                    path = template.replace('{helper_id}', own['session_id']).replace('{approval_id}', hold['approval_id']).replace('{incident_id}', incident)
                    if template.endswith('/source-message-scope'):
                        path = template.replace('{helper_id}', scope_helper['session_id'])
                    form = forms[template]
                    expected = 303 if anon else 403
                    if template.startswith('/api/agent/'):
                        expected = 401  # Human cookie never grants worker-token authority.
                    elif template == '/login':
                        expected = 303
                    elif template == '/logout':
                        expected = 303
                    elif template == '/change-password':
                        expected = 303
                    elif template.startswith('/breach-clock'):
                        expected = 401 if anon else (303 if admin else 403)
                    elif template.startswith('/admin/demo/'):
                        expected = 401 if anon else (303 if admin else 403)
                    elif template == '/admin/tools/review':
                        expected = 200 if admin else 403
                        if admin:
                            cookies()
                            shown = context.request.get(path).text()
                            import re
                            form['snapshot_digest'] = re.search('name="snapshot_digest" value="([^"]+)"', shown)[1]
                    elif template == '/live/agent-run':
                        expected = 200 if writer else 403
                    elif template in ('/live/run', '/redteam/run'):
                        expected = 303 if anon else (200 if writer else 403)
                    elif template.endswith('/view'):
                        expected = 303 if anon else (200 if writer else 403)
                    elif template.endswith('/decide'):
                        # Existing endpoint reports role refusal in an HTML result at HTTP 200.
                        expected = 303 if anon else 200
                    elif admin:
                        expected = 200 if template in ('/admin/bench', '/admin/helpers/{helper_id}/source-message-scope') else 303
                    result = check(path, 'POST', expected, form)
                    if template.endswith('/decide') and not anon:
                        stored = approvals.get(hold['approval_id'])
                        assert stored['status'] == ('claimed' if writer else 'pending'), result.text()
                        action = db.conn().execute('SELECT status FROM actions WHERE id=?', (stored['action_id'],)).fetchone()
                        assert action['status'] == ('executed' if writer else 'held')
                        assert len(gateway.get_world(run).refunds) == (1 if writer else 0)
                    if template == '/live/agent-run' and writer:
                        assert 'live agent needs' in result.text()
                    if template.endswith('/freeze') and admin:
                        assert gateway._load_card(own['session_id'])['frozen'] is True
                    if template.endswith('/release') and admin:
                        assert gateway._load_card(own['session_id'])['frozen'] is False
                    if template == '/change-password' and not anon:
                        password += '-changed'
                        session = auth.login(name, password)
                        csrf = session['csrf']
                        forms['/login']['password'] = password
                        forms['/logout']['csrf'] = csrf
                # Worker-token routes additionally exercised using a generated synthetic token.
                session = auth.login(name, password)
                csrf = session['csrf']
                cookies()
                for suffix in ('session', 'call', 'model'):
                    response = context.request.post('/api/agent/' + suffix, headers={'X-Agent-Token': own['token']},
                        data=json.dumps({'tool': 'list_inbox', 'args': {}}), max_redirects=0)
                    assert response.status == 200
                    rows.append(dict(path='/api/agent/' + suffix, method='POST', role=role, width=width,
                        expected_status=200, actual_status=200, evidence='generated worker token, read-only/no-live-model'))
                # Demo has real child-generated records, not invented JSON proof.
                if admin:
                    cookies()
                    check('/admin/demo/run', 'POST', 303, dict(csrf=csrf))
                    for view in ('source', 'guard', 'briefing', 'results'):
                        check('/admin/demo/' + view, 'GET', 200)
                    page.goto('/admin/demo')
                    proof = page.locator('a[href^="/admin/demo/proof/"]').first.get_attribute('href')
                    assert proof
                    check(proof, 'GET', 200)
                # Nonexistent detail URLs never become a successful protected resource.
                for path, expected in [('/run/matrix-missing', 303 if anon else 403),
                    ('/approvals/matrix-missing', 303 if anon else 403),
                    ('/breach-clock/matrix-missing', 401 if anon else (403 if role == 'viewer' else 404)),
                    ('/admin/demo/proof/matrix-missing', 401 if anon else (404 if admin else 403))]:
                    check(path, 'GET', expected)
                assert not errors and not outside
                context.close()
        browser.close()
    destination = Path(os.environ.get('TWINGUARD_VALID_MATRIX_RESULTS', str(tmp_path / 'valid-matrix.json')))
    destination = destination.with_name(destination.stem + '-' + role + '-' + str(width) + '.json')
    destination.write_text(
        json.dumps(dict(rows=rows, failure_count=0, roles=5, widths=[1440, 390],
            post_route_count=len(posts), scope='Real isolated synthetic state; no live model, network effects or handler mocks.'), indent=2) + '\n')
