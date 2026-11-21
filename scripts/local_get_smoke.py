"""Bounded GET matrix against actual server, using source route inventory."""
import ast
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright
root = Path(__file__).resolve().parents[1]
output = Path(sys.argv[1])
accounts = json.loads((root / '.local-demo/passwords.json').read_text())
paths = set()
for source in (root / 'aegis/app.py', root / 'aegis/breach_views.py', root / 'scripts/local_demo_panel.py'):
    for node in ast.walk(ast.parse(source.read_text())):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'get' and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and node.args[0].value.startswith('/'):
            paths.add(node.args[0].value)
rows = []
with sync_playwright() as pw:
    browser = pw.chromium.launch()
    contexts = {}
    for name in accounts:
        context = browser.new_context(base_url='http://localhost:8000', viewport={'width': 1440, 'height': 1000})
        page = context.new_page()
        page.goto('/login')
        page.get_by_label('Username', exact=True).fill(name)
        page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
        page.get_by_role('button', name='Sign in', exact=True).click()
        contexts[name] = (context, page)
    admin = contexts['dana'][1]
    state = admin.request.get('/local-demo/seed-state').json()
    admin.goto('/breach-clock')
    csrf = admin.locator('[name=csrf]').first.input_value()
    response = admin.request.post('/breach-clock', form={'csrf': csrf, 'text': 'Synthetic local incident'})
    incident = response.url.rsplit('/', 1)[-1]
    records = admin.request.get('/audit/export.json').json()
    if isinstance(records, dict):
        records = records.get('records', [])
    rid = str(records[0]['id'])
    proof = json.loads((root / '.local-demo/saved-rehearsal.json').read_text())['result']['record_projection'][0]['record_ref']
    params = {'run_id': state['run'], 'approval_id': state['approvals'][0]['id'], 'incident_id': incident, 'rid': rid, 'proof_ref': proof}
    for name, (context, page) in contexts.items():
        for pattern in sorted(paths):
            path = pattern
            for key, value in params.items():
                path = path.replace('{' + key + '}', value)
            assert '{' not in path, pattern
            response = page.request.get(path, max_redirects=0)
            status = response.status
            assert status in (200, 303, 401, 403), (name, path, status, response.text()[:200])
            if status == 200 and 'text/html' in response.headers.get('content-type', ''):
                page.goto(path)
                assert 'LOCAL OFFLINE DEMO: scripted stand-in' in page.locator('body').inner_text(), path
                page.screenshot(path=str(output / ('get-' + name + '-' + pattern.strip('/').replace('/', '-').replace('{', '').replace('}', '') + '.png')), full_page=True)
            rows.append({'route': pattern, 'role': accounts[name]['role'], 'identity': name, 'status': status, 'width': 1440, 'valid_seed_params': True})
    browser.close()
(output / 'get-matrix.json').write_text(json.dumps({'routes': len(paths), 'cases': len(rows), 'rows': rows}, indent=2))
print(f'GET matrix passed: {len(paths)} routes, {len(rows)} role cases, valid seed params, no 404/422/500.')
