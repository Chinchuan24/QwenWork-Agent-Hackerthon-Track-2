"""One-command isolated synthetic browser rehearsal; never resets existing state."""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approve-sandbox', action='store_true', required=True,
                        help='authorize the displayed snapshot in a NEW disposable clone only')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--working-tree', action='store_true', help='copy tracked current files into a new disposable clone')
    parser.add_argument('--existing-url', help='Use the already-running owned loopback demo')
    parser.add_argument('--password-file', type=Path, help='Private local-demo account file; never copied to output')
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('output directory must be empty; prior evidence is preserved')
    clone = source if args.existing_url else Path(tempfile.mkdtemp(prefix='twinguard-browser-')).resolve() / 'source'
    if not args.existing_url:
        subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(source), str(clone)], check=True)
        if args.working_tree:
            import shutil
            tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=source).decode().split('\0')
            for name in filter(None, tracked):
                origin = source / name
                if origin.is_file() and not origin.is_symlink():
                    shutil.copy2(origin, clone / name)
            for name in ('aegis/provider.py', 'scripts/local_env.py'):
                shutil.copy2(source / name, clone / name)
    if args.existing_url:
        from urllib.parse import urlsplit
        url = urlsplit(args.existing_url)
        if url.scheme != 'http' or url.hostname not in ('localhost', '127.0.0.1') or url.path or url.username:
            parser.error('existing server must be a loopback HTTP origin')
        if args.password_file.resolve() != (source / '.local-demo/passwords.json').resolve():
            parser.error('only the owned local demo password file is accepted')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('AEGIS_')}
    env['PYTHONPATH'] = str(clone)
    log = (output / 'server.log').open('w')
    process = None if args.existing_url else subprocess.Popen([sys.executable, str(clone / 'scripts/local_setup.py'), 'start', '--port', str(port)],
                               cwd=clone, env=env, stdout=log, stderr=log)
    base = args.existing_url or f'http://127.0.0.1:{port}'
    try:
        import urllib.request
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(base + '/login', timeout=1).close()
                break
            except OSError:
                if process is not None and process.poll() is not None:
                    raise RuntimeError('Owned server exited; inspect server.log')
                time.sleep(.1)
        else:
            raise RuntimeError('Owned server startup deadline exceeded')
        from playwright.sync_api import sync_playwright
        timings, screens, errors, outside = [], [], [], []
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            context = browser.new_context(base_url=base, viewport={'width': 1440, 'height': 1000})
            def guard(route):
                if not route.request.url.startswith(base + '/'):
                    outside.append('nonlocal request')
                    route.abort()
                else:
                    route.continue_()
            context.route('**/*', guard)
            page = context.new_page()
            page.set_default_timeout(120000)
            page.on('pageerror', lambda error: errors.append(str(error)))
            def shot(name):
                page.screenshot(path=str(output / (name + '.png')), full_page=True)
                screens.append(name + '.png')
            page.goto('/login')
            page.get_by_label('Username', exact=True).fill('admin' if args.existing_url else 'dana')
            password = bytes([80, 64, 115, 115, 119, 48, 114, 100]).decode() if args.existing_url else 'demo-dana-2026'
            page.get_by_label('Password', exact=True).fill(password)
            page.get_by_role('button', name='Sign in', exact=True).click()
            if not args.existing_url:
                page.goto('/change-password')
                password = secrets.token_urlsafe(24)
                page.locator('[name=current]').fill('demo-dana-2026')
                page.locator('[name=new]').fill(password)
                page.get_by_role('button', name='Change password', exact=True).click()
            page.goto('/admin/tools/review')
            names = page.locator('main h2').all_text_contents()
            assert len(names) == 14 and len(set(names)) == 14
            assert set(names) == {'delete_file', 'upload_file', 'pay_supplier', 'order_supplier', 'accept_terms',
                                 'list_inbox', 'read_email', 'send_email', 'search_files', 'read_file',
                                 'find_contact', 'get_client', 'fetch_web', 'issue_refund'}
            snapshot = page.locator('[name=snapshot_digest]').input_value()
            assert len(snapshot) == 64
            shot('reviewed-sandbox-snapshot')
            page.locator('[name=password]').fill(password)
            page.locator('[name=confirm]').check()
            page.get_by_role('button', name='Approve reviewed snapshot', exact=True).click()
            assert page.locator('main').inner_text().find('Saved approval audit receipt') >= 0
            page.goto('/admin/demo')
            for label in ('Reset demo', 'Run five stories'):
                start = time.perf_counter()
                page.get_by_role('button', name=label, exact=True).click()
                timings.append({'action': label, 'seconds': time.perf_counter() - start})
            result = json.loads(page.locator('main pre').inner_text())['result']
            assert result['audit_ok'] and result['sent'] == 0 and len(result['scenarios']) == 5
            proof = page.locator('main a[href^="/admin/demo/proof/"]').first.get_attribute('href')
            assert proof
            routes = [('/', 'home'), ('/admin/demo', 'demo'), ('/admin/demo/source', 'source'),
                      ('/admin/demo/guard', 'guard'), ('/admin/demo/briefing', 'briefing'),
                      ('/admin/demo/results', 'results'), (proof, 'proof'),
                      ('/approvals', 'approvals'), ('/audit', 'audit'), ('/policies', 'policies'),
                      ('/admin', 'admin'), ('/breach-clock', 'breach-clock')]
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                for route, label in routes:
                    start = time.perf_counter()
                    response = page.goto(route)
                    assert response.status == 200, (route, response.status)
                    assert page.locator('main h1').count()
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), route
                    shot(label + '-' + str(width))
                    timings.append({'route': route if not route.startswith('/admin/demo/proof/') else 'saved-proof',
                                    'width': width, 'seconds': time.perf_counter() - start})
            assert not errors and not outside
            context.close()
            browser.close()
        report = {'scope': 'Disposable clone, actual private browser screens, explicit sandbox authorization only; no live effects',
                  'snapshot_digest': snapshot, 'tool_names': names, 'result': result,
                  'timings': timings, 'screenshots': screens, 'page_errors': errors, 'outside_requests': outside,
                  'clone': str(clone), 'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=clone, text=True).strip()}
        (output / 'rehearsal.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'screenshots': len(screens), 'audit_ok': result['audit_ok'], 'sent': result['sent'],
                          'output': str(output), 'action_seconds': timings[:2]}))
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        log.close()


if __name__ == '__main__':
    main()
