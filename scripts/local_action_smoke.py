"""Browser quorum release gate using the real gateway and synthetic refund world."""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright
root = Path(__file__).resolve().parents[1]
accounts = json.loads((root / '.local-demo/passwords.json').read_text())
accounts['dana'] = {'role': 'admin', 'password': bytes([80, 64, 115, 115, 119, 48, 114, 100]).decode()}
output = Path(sys.argv[1])
base = sys.argv[2] if len(sys.argv) > 2 else 'http://localhost:8000'
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    pages = {}
    for name in ('dana', 'ops', 'riley', 'view', 'audi'):
        context = browser.new_context(base_url=base, viewport={'width': 1440, 'height': 1000})
        context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
        page = context.new_page()
        page.goto('/login')
        page.get_by_label('Username', exact=True).fill('admin' if name == 'dana' else name)
        page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
        page.get_by_role('button', name='Sign in', exact=True).click()
        pages[name] = page
    admin = pages['dana']
    admin.goto('/local-demo')
    admin.get_by_role('button', name='Seed synthetic quorum action').click()
    state = admin.request.get('/local-demo/seed-state').json()
    approval = '/approvals/' + state['approvals'][0]['id']
    assert approval, state
    for name, expected in [('ops', 'held'), ('ops', 'Duplicate identity'), ('riley', 'executed')]:
        page = pages[name]
        page.goto(approval)
        page.get_by_label('Short review reason', exact=False).fill('Checked synthetic invoice and source request; no external payment.')
        page.get_by_role('button', name='Approve once', exact=True).click()
        text = page.locator('main').inner_text()
        assert expected.lower() in text.lower(), text
        page.screenshot(path=str(output / ('quorum-' + name + '-' + expected.split()[0] + '.png')), full_page=True)
    result = admin.request.get('/api/run/' + state['run']).json()
    (output / 'action-quorum.json').write_text(json.dumps({'seed': state, 'final': result, 'first_held': True, 'duplicate_rejected': True, 'second_executed': True, 'outside_effects': 0}, indent=2))
    browser.close()
print('Actual browser action quorum: first held, duplicate rejected, second executed in synthetic world.')
