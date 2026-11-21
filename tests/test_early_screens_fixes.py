"""Isolated screen regressions using the exact-origin browser guard."""
import secrets
import time

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from urllib.parse import urlsplit
from playwright.sync_api import expect, sync_playwright

from aegis import approvals, auth, db, evidence, redteam, suites
from tests.test_r12_browser import local_server, login


@pytest.fixture
def page(local_server):
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(base_url=local_server, service_workers='block')
        external, errors = [], []

        def guard(route):
            url = urlsplit(route.request.url)
            if f'{url.scheme}://{url.netloc}' != local_server:
                external.append(route.request.url)
                route.abort()
            else:
                route.continue_()

        context.route('**/*', guard)
        tab = context.new_page()
        tab.on('pageerror', lambda error: errors.append(str(error)))
        try:
            yield tab
        finally:
            context.close()
            browser.close()
            assert not external
            assert not errors


@pytest.fixture
def held():
    owner = 'early_' + secrets.token_hex(6)
    scen = next(s for s in suites.NORMAL if s['id'] == 'N22')
    result = redteam.run_scenario('enforce', scen, created_by=owner, approve_held=False)
    row = db.conn().execute(
        'SELECT ap.id, ap.action_id FROM approvals ap JOIN actions a ON a.id=ap.action_id '
        'JOIN agent_sessions s ON s.id=a.session_id WHERE s.run_id=?',
        (result['run_id'],)).fetchone()
    assert row is not None
    private = 'PRIVATE-' + secrets.token_hex(16)
    db.conn().execute('UPDATE actions SET reasons_json=?, args_json=? WHERE id=?',
                     (evidence.enc_json([{'rule': 'PRIVATE', 'reason': private}]),
                      evidence.enc_json({'invoice_id': private, 'amount': 1}), row['action_id']))
    db.conn().commit()
    return row['id'], private


@pytest.mark.parametrize('width', [1280, 320])
@pytest.mark.parametrize('state', ['pending', 'decided', 'expired', 'kill'])
def test_viewer_detail(page, held, width, state):
    aid, private = held
    if state == 'decided':
        reviewer = 'early_' + secrets.token_hex(6)
        password = secrets.token_urlsafe(24)
        auth.create_user(reviewer, password, 'approver')
        user = auth.user_by_token(auth.login(reviewer, password)['token'])
        result = approvals.decide(aid, user, 'deny', reason='Reviewed')
        assert result['ok']
    elif state == 'expired':
        db.conn().execute('UPDATE approvals SET expires_at=0 WHERE id=?', (aid,))
        db.conn().commit()
    login(page, 'viewer')
    page.set_viewport_size({'width': width, 'height': 800 if width == 1280 else 640})
    if state == 'kill':
        db.set_setting('kill_switch', 'on', 'tests', time.time())
    response = page.goto('/approvals/' + aid)
    assert response.status == 200
    expect(page.locator('main')).to_contain_text('clear text withheld for your role')
    assert private not in page.content()
    expect(page.get_by_role('button', name='Approve once')).to_have_count(0)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    if state == 'kill':
        expect(page.locator('body')).to_contain_text('KILL SWITCH ACTIVE')


@pytest.mark.parametrize('width', [1280, 320])
@pytest.mark.parametrize('path,status,title', [
    ('/not-a-route', 404, 'Page not found'),
    ('/audit/record/not-an-int', 422, 'Invalid record ID'),
])
def test_html_errors(page, width, path, status, title):
    login(page, 'viewer')
    page.set_viewport_size({'width': width, 'height': 640})
    db.set_setting('kill_switch', 'on', 'tests', time.time())
    response = page.goto(path)
    assert response.status == status
    expect(page.locator('main h1')).to_have_text(title)
    expect(page.locator('body')).to_contain_text('KILL SWITCH ACTIVE')
    assert 'int_parsing' not in page.content()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


@pytest.mark.parametrize('role', ['viewer', 'approver', 'admin', 'auditor'])
def test_export_links(page, role):
    login(page, role)
    page.goto('/audit')
    allowed = role in ('admin', 'auditor')
    expect(page.locator('a[href^="/audit/export."]')).to_have_count(2 if allowed else 0)
    for suffix in ('json', 'csv'):
        response = page.request.get('/audit/export.' + suffix)
        assert response.status == (200 if allowed else 403)


def test_json_and_auth_boundaries(page):
    response = page.request.get('/not-a-route', headers={'Accept': 'application/json'})
    assert response.status == 404
    assert response.json() == {'detail': 'Not Found'}
    response = page.request.get('/audit/record/not-an-int', headers={'Accept': 'application/json'})
    assert response.status == 422
    assert response.json()['detail'][0]['type'] == 'int_parsing'
    assert page.request.get('/api/not-a-route').status == 404
    assert page.request.get('/api/run/missing').status == 401
    response = page.goto('/audit/record/not-an-int')
    assert response.status == 422
    expect(page.locator('.who')).to_have_count(0)
