"""Record every interaction in a fresh committed clone; no .env or remote traffic."""
import argparse
import html
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    clone = Path(tempfile.mkdtemp(prefix='tg-', dir='/tmp')) / 'source'
    subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(root), str(clone)], check=True)
    env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'LANG') if k in os.environ}
    env['TWINGUARD_LOCAL_PYTHON'] = sys.executable
    log = (output / 'recording-server.log').open('w')
    process = subprocess.Popen([str(clone / 'run-local-demo.sh'), '--scripted'], cwd=clone, env=env, stdout=log, stderr=log)
    base = None
    try:
        for _ in range(600):
            lines = (output / 'recording-server.log').read_text().splitlines()
            ready = next((line for line in lines if line.startswith('Ready http://')), None)
            if ready:
                base = ready.split()[1]
                break
            if process.poll() is not None:
                raise RuntimeError('Owned launcher exited; see retained log')
            time.sleep(.1)
        assert base, 'Readiness timeout'
        accounts = json.loads((clone / '.local-demo/passwords.json').read_text())
        steps, outside, errors, overflow = [], [], [], []
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            contexts = {}
            def page_for(name):
                if name in contexts:
                    return contexts[name][1]
                context = browser.new_context(base_url=base, viewport={'width': 1440, 'height': 900})
                def guard(route):
                    if route.request.url.startswith(base + '/'):
                        route.continue_()
                    else:
                        outside.append('nonlocal request')
                        route.abort()
                context.route('**/*', guard)
                page = context.new_page()
                page.on('pageerror', lambda e: errors.append(type(e).__name__))
                page.set_default_timeout(120000)
                contexts[name] = context, page
                return page
            def shot(page, title, scene='setup'):
                filename = f'{len(steps)+1:02d}-{scene}.png'
                page.screenshot(path=str(output / filename), full_page=True, mask=[page.locator('input[type=password]')])
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), page.url
                steps.append({'step': len(steps)+1, 'title': title, 'scene': scene, 'url': page.url, 'file': filename})
            def login(name):
                page = page_for(name)
                page.goto('/login?present=1')
                shot(page, name + ': blank login')
                page.get_by_label('Username', exact=True).fill(name)
                shot(page, name + ': select account')
                page.get_by_label('Password', exact=True).fill(accounts[name]['password'])
                shot(page, name + ': private password masked')
                page.get_by_role('button', name='Sign in', exact=True).click()
                shot(page, name + ': signed in')
                return page
            dana = login('dana')
            dana.goto('/admin/tools/review?present=1')
            assert dana.locator('main h2').count() == 14
            shot(dana, 'Review all 14 tool schemas and fingerprints')
            dana.locator('[name=password]').fill(accounts['dana']['password'])
            shot(dana, 'Reauthenticate review; password masked')
            dana.locator('[name=confirm]').check()
            shot(dana, 'Confirm exact displayed snapshot')
            dana.get_by_role('button', name='Approve reviewed snapshot', exact=True).click()
            assert 'Saved approval audit receipt' in dana.locator('main').inner_text()
            shot(dana, 'Saved tool approval receipt')
            dana.goto('/present/s06?present=1')
            shot(dana, 'Open fresh recording scene', 's06')
            dana.get_by_role('button', name='Reset recording dataset').click()
            shot(dana, 'Five behaviours queued / 0 processed', 's06')
            for index in range(5):
                dana.get_by_role('button', name='Process next queued behaviour').click()
                shot(dana, f'Actual processing completed {index+1}/5', 's06')
            dana.goto('/present/s07?present=1')
            assert 'BLOCKED' in dana.locator('main').inner_text()
            assert 'Nothing sent.' in dana.locator('main').inner_text()
            shot(dana, 'Client email blocked / zero sends / saved rules', 's07')
            dana.get_by_role('link', name='Open exact saved decision').click()
            shot(dana, 'Inspect actual client-list decision receipt', 's07')
            dana.goto('/present/s09?present=1')
            shot(dana, 'Draft HOLD / S$4,800 versus paper fixture S$6,200', 's09')
            dana.get_by_role('link', name='Check evidence receipt', exact=False).click()
            shot(dana, 'Inspect actual draft evidence rejection', 's09')
            dana.goto('/present/s11?present=1')
            shot(dana, 'Dana chooses corrected contract review', 's11')
            dana.get_by_role('button', name='Request corrected contract review').click()
            shot(dana, 'Saved genuine guard disagreement and contract HOLD', 's11')
            assert 'Aegis: safe / Delta: unsure' in dana.locator('main').inner_text()
            dana.get_by_label('Review reason').fill('Creator cannot approve own task')
            shot(dana, 'Dana tests no-self-approval boundary', 's11')
            dana.get_by_role('button', name='Approve corrected contract reply').click()
            shot(dana, 'Creator rejected', 's11')
            assert 'no self approval' in dana.locator('main').inner_text().lower()
            for name in ('ops', 'riley'):
                page = login(name)
                page.goto('/present/s11?present=1')
                shot(page, name + ': inspect same contract approval', 's11')
                page.get_by_label('Review reason').fill('Checked corrected price against paper fixture')
                shot(page, name + ': record review reason', 's11')
                page.get_by_role('button', name='Approve corrected contract reply').click()
                shot(page, name + ': approval outcome', 's11')
                if name == 'ops':
                    assert 'First approval saved' in page.locator('main').inner_text()
                    page.get_by_label('Review reason').fill('Duplicate identity must not count')
                    shot(page, 'ops: attempt duplicate', 's11')
                    page.get_by_role('button', name='Approve corrected contract reply').click()
                    shot(page, 'Duplicate rejected', 's11')
                    assert 'Duplicate identity' in page.locator('main').inner_text()
                else:
                    assert 'executed' in page.locator('main').inner_text(), page.locator('main').inner_text()
            for name in ('audi', 'view'):
                page = login(name)
                page.goto('/present/s13?present=1')
                shot(page, name + ': read-only briefing')
                assert not page.get_by_role('button', name='Approve corrected contract reply').count()
            dana.goto('/present/s13?present=1')
            shot(dana, 'Four briefing groups with audit-derived counts', 's13')
            dana.locator('main a[href^="/audit/record/"]').first.click()
            shot(dana, 'Briefing item proof receipt', 's13')
            dana.goto('/present/s14?present=1')
            shot(dana, 'Proof pack ready to verify', 's14')
            dana.get_by_role('button', name='Verify original proof pack').click()
            shot(dana, 'Green Verified / original pack sealed', 's14')
            assert dana.get_by_text('Verified', exact=True).count()
            dana.get_by_role('button', name='Tamper COPY: change one field').click()
            shot(dana, 'Red COPY / exact changed field / original still verifies', 's14')
            assert 'Modified COPY signature valid: False' in dana.locator('main').inner_text()
            routes = ['/present/' + s + '?present=1' for s in ('s06','s07','s09','s11','s13','s14')] + ['/admin/tools/review?present=1','/approvals?present=1','/audit?present=1','/local-demo?present=1']
            for width in (1440, 768, 390):
                dana.set_viewport_size({'width': width, 'height': 900})
                for route in routes:
                    response = dana.goto(route)
                    ok = response.status == 200 and dana.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    overflow.append({'width': width, 'route': route, 'passed': ok})
                    assert ok, (width, route)
            assert not outside and not errors
            for context, _ in contexts.values():
                context.close()
            browser.close()
        revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=clone, text=True).strip()
        report = {'revision': revision, 'origin': base, 'clone': str(clone), 'screenshots': steps, 'overflow_matrix': overflow, 'outside_requests': outside, 'page_errors': errors}
        (output / 'recording-evidence.json').write_text(json.dumps(report, indent=2))
        cells = ''.join('<article><h2>' + html.escape(str(s['step']) + '. ' + s['title']) + '</h2><p>' + html.escape(s['url']) + '</p><a href="recording-assets/' + s['file'] + '"><img alt="' + html.escape(s['title'], quote=True) + '" src="recording-assets/' + s['file'] + '"></a></article>' for s in steps)
        (output.parent / 'recording-contact-sheet.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>Twinguard actual recording steps</title><style>body{font:16px system-ui;margin:24px;background:#eeece4;color:#121714}main{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}img{width:100%}article{min-width:0}p{overflow-wrap:anywhere}@media(max-width:700px){main{grid-template-columns:1fr}}</style><h1>Actual recording steps</h1><p>Revision ' + revision + '. Password fields masked. Synthetic local data.</p><main>' + cells + '</main></html>')
        print(json.dumps({'screenshots': len(steps), 'overflow_cases': len(overflow), 'revision': revision, 'origin': base}))
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()


if __name__ == '__main__':
    main()
