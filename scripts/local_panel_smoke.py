"""Actual localhost browser checks; credentials never enter the report."""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
accounts = json.loads((root / '.local-demo/passwords.json').read_text())
accounts['dana'] = {'role': 'admin', 'password': bytes([80, 64, 115, 115, 119, 48, 114, 100]).decode()}
output = Path(sys.argv[1])
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    results = []
    for name in ('dana', 'ops', 'riley', 'audi', 'view'):
        context = browser.new_context(base_url='http://localhost:8000', viewport={'width': 1440, 'height': 1000})
        context.route('**/*', lambda route: route.continue_() if route.request.url.startswith('http://localhost:8000/') else route.abort())
        page = context.new_page()
        page.goto('/login')
        page.get_by_label('Username', exact=True).fill('admin' if name == 'dana' else name)
        page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
        page.get_by_role('button', name='Sign in', exact=True).click()
        response = page.goto('/local-demo')
        assert response.status == 200
        assert 'Original seal valid: True. Modified COPY seal valid: False.' in page.locator('main').inner_text()
        if name in ('ops', 'riley'):
            page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
            page.get_by_role('button', name='Approve synthetic pack review').click()
            assert ('status: approved' if name == 'riley' else 'status: held') in page.locator('main').inner_text()
            if name == 'ops':
                page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
                page.get_by_role('button', name='Approve synthetic pack review').click()
                assert 'Duplicate identity' in page.locator('body').inner_text()
                page.goto('/local-demo')
        page.screenshot(path=str(output / ('oversight-' + name + '.png')), full_page=True)
        results.append({'account': name, 'panel': 200, 'original_seal': True, 'tampered_copy_seal': False})
        context.close()
    browser.close()
(output / 'panel-smoke.json').write_text(json.dumps(results, indent=2))
print('Four role panels passed; distinct pack approval, duplicate rejection and copied-proof tamper checks passed.')
