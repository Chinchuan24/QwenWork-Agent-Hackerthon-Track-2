"""Real HTTPS rehearsal with an ephemeral self-signed certificate, no Docker."""
import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import ssl
import hashlib

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from playwright.sync_api import sync_playwright


@pytest.mark.parametrize('credential', ['', 'dummy-not-a-real-key'])
def test_https_browser_all_roles(tmp_path, credential):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
            .sign(key, hashes.SHA256()))
    keypath, certpath = tmp_path / 'tls.key', tmp_path / 'tls.crt'
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keypath.chmod(0o600)
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('AEGIS_')}
    env.update(AEGIS_ENV='production', AEGIS_DEMO_PUBLIC='1',
               AEGIS_PRODUCTION_DATA_DIR=str(tmp_path / 'volume'),
               AEGIS_TRUSTED_HOSTS='localhost', PORT=str(port),
               AEGIS_TLS_KEY_FILE=str(keypath), AEGIS_TLS_CERT_FILE=str(certpath))
    env['AEGIS_QWEN_API_KEY'] = credential
    proof = []
    with open(tmp_path / 'server.log', 'w') as log:
        process = subprocess.Popen([sys.executable, '-m', 'aegis.production'], env=env, stdout=log, stderr=log)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                for role in ('viewer', 'approver', 'auditor'):
                    # Explicitly scoped to this ephemeral local self-signed server.
                    context = browser.new_context(ignore_https_errors=True)
                    page = context.new_page()
                    outside = []
                    page.on('request', lambda r: outside.append(r.url) if not r.url.startswith(f'https://localhost:{port}/') else None)
                    page.goto(f'https://localhost:{port}/')
                    page.select_option('select', role)
                    page.get_by_role('button', name='Enter simulated role').click()
                    for path in ('/', '/world', '/audit', '/roles'):
                        for width in (390, 768, 1440):
                            page.set_viewport_size({'width': width, 'height': 900})
                            response = page.goto(f'https://localhost:{port}{path}')
                            assert response.status == 200
                            assert response.headers['x-frame-options'] == 'DENY'
                            assert response.headers['strict-transport-security']
                            assert page.get_by_text('SIMULATED PUBLIC DEMO.', exact=False).is_visible()
                            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                            page.screenshot(path=str(tmp_path / f'{role}-{path.replace("/", "_")}-{width}.png'))
                    csrf = page.locator('input[name=csrf]').first.input_value()
                    assert context.request.post(f'https://localhost:{port}/session', form={'csrf': csrf, 'role': 'admin'}).status == 403
                    for action in ('off', 'monitor', 'release', 'pay_supplier'):
                        assert context.request.post(f'https://localhost:{port}/action', form={'csrf': csrf, 'action': action}).status == 403
                    if role == 'approver':
                        page.goto(f'https://localhost:{port}/world')
                        page.get_by_role('button', name='Evaluate audience locally').click()
                        assert 'R15' in page.text_content('body')
                        page.goto(f'https://localhost:{port}/audit')
                    page.get_by_role('button', name='Reset my simulated world').click()
                    assert 'World generation 2' in page.text_content('main')
                    export = context.request.get(f'https://localhost:{port}/audit/export').json()
                    assert export['outside_effects'] == 0 and len(export['events']) == (3 if role == 'approver' else 2)
                    assert not outside
                    cookies = context.cookies()
                    assert all(c['secure'] and c['httpOnly'] and c['sameSite'] == 'Strict' for c in cookies)
                    proof.append({'role': role, 'pages': 4, 'breakpoints': 3, 'reset': True, 'external_requests': outside})
                    context.close()
                context = browser.new_context(ignore_https_errors=True)
                statuses = [context.request.get(f'https://localhost:{port}/healthz').status for _ in range(125)]
                assert 429 in statuses
                browser.close()
            stored_key = tmp_path / 'volume/keys/internal.key'
            key_digest = hashlib.sha256(stored_key.read_bytes()).hexdigest()
            # Interrupt a partial POST against this disposable server only.
            tls = ssl._create_unverified_context()
            with tls.wrap_socket(socket.create_connection(('127.0.0.1', port)), server_hostname='localhost') as sock:
                sock.sendall(b'POST /session HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\ncsrf=')
                time.sleep(.1)
                process.kill()
                process.wait(timeout=15)
                assert process.returncode == -9
            process = subprocess.Popen([sys.executable, '-m', 'aegis.production'], env=env, stdout=log, stderr=log)
            from urllib.request import urlopen
            for _ in range(100):
                try:
                    with urlopen(f'https://localhost:{port}/readyz', context=tls, timeout=1) as response:
                        assert json.load(response)['ready']
                        break
                except OSError:
                    time.sleep(.1)
            else:
                pytest.fail('hard-kill restart did not become ready')
            assert hashlib.sha256(stored_key.read_bytes()).hexdigest() == key_digest
            proof.append({'kill_signal': 9, 'mid_request': 'partial POST body', 'restart_ready': True, 'key_preserved': True, 'credential': 'absent' if not credential else 'dummy'})
        finally:
            process.terminate()
            process.wait(timeout=15)
    # Uvicorn re-raises the captured SIGTERM after completing its lifespan.
    assert process.returncode in (0, -15)
    assert 'Application shutdown complete.' in (tmp_path / 'server.log').read_text()
    (tmp_path / 'proof.json').write_text(json.dumps(proof, indent=2))
    print('HTTPS proof directory:', tmp_path)
