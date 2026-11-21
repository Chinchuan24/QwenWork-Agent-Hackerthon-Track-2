"""Packaging contract only; no real data, secrets, hosts or Docker required."""
import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULES = {'__init__', 'production', 'public_evaluator', 'claims', 'policy', 'sensitivity', 'mixed_demo'}


def test_isolated_nonroot_image():
    text = (ROOT / 'Dockerfile').read_text()
    assert re.search(r'^FROM python:3\.12-slim-bookworm@sha256:[a-f0-9]{64}$', text, re.M)
    assert 'USER 10001:10001' in text
    assert '--require-hashes' in text
    assert 'COPY aegis/__init__.py aegis/production.py aegis/public_evaluator.py aegis/claims.py aegis/policy.py aegis/sensitivity.py aegis/mixed_demo.py ./aegis/' in text
    assert 'run.py' not in text and 'COPY aegis/ ' not in text
    assert '"-m", "aegis.production"' in text
    assert '/readyz' in text and '|| true' not in text


def test_readonly_single_volume():
    s = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())['services']['aegis']
    assert s['read_only'] and s['cap_drop'] == ['ALL']
    assert s['volumes'] == ['aegis_data:/data']
    assert 'tmpfs' not in s
    assert s['ports'] == ['127.0.0.1:8080:8080']


def test_context_allowlist():
    lines = (ROOT / '.dockerignore').read_text().splitlines()
    assert '**' in lines
    assert {x for x in lines if x.startswith('!')} == {
        '!Dockerfile', '!requirements-production.lock', '!aegis/',
        *{'!aegis/' + m + '.py' for m in MODULES}}


def test_host_profiles():
    render = yaml.safe_load((ROOT / 'render.yaml').read_text())['services'][0]
    assert render['plan'] != 'free' and render['numInstances'] == 1
    assert render['disk']['mountPath'] == '/data'
    assert render['healthCheckPath'] == '/readyz'
    fly = tomllib.loads((ROOT / 'fly.toml').read_text())
    assert fly['mounts']['destination'] == '/data'
    assert fly['http_service']['auto_stop_machines'] == 'off'
    assert fly['http_service']['checks'][0]['path'] == '/readyz'
    railway = json.loads((ROOT / 'railway.json').read_text())
    assert railway['deploy']['healthcheckPath'] == '/readyz'
    assert 'volumes' not in railway
    assert 'deprecated' in (ROOT / 'docs/deploy.md').read_text().lower()


def test_template_covers_source_environment_names():
    names = set(re.findall(r'^([A-Z][A-Z0-9_]*)=', (ROOT / '.env.example').read_text(), re.M))
    for filename in ('aegis/config.py', 'aegis/production.py', 'aegis/qwen_client.py', 'aegis/worker.py'):
        tree = ast.parse((ROOT / filename).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('getenv', 'get'):
                if node.args and isinstance(node.args[0], ast.Constant):
                    key = node.args[0].value
                    if isinstance(key, str) and (key.startswith('AEGIS_') or key in ('PORT', 'DEBUG')):
                        assert key in names, key
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == 'environ':
                if isinstance(node.slice, ast.Constant):
                    assert node.slice.value in names
    assert {'AEGIS_DEBUG', 'DEBUG'} <= names


def test_core_host_contract_integration_gate():
    text = (ROOT / 'aegis/production.py').read_text()
    assert "os.getenv('PORT'" in text or 'os.getenv("PORT"' in text
    assert '/readyz' in text and '/healthz' in text


def test_image_module_closure_without_repository(tmp_path):
    package = tmp_path / 'aegis'
    package.mkdir()
    for module in MODULES:
        shutil.copyfile(ROOT / 'aegis' / (module + '.py'), package / (module + '.py'))
    code = '''import sys
from aegis.production import create_app
from aegis.public_evaluator import evaluate
assert evaluate('greenstep', 'Price SGD 5,800')['decision'] == 'block'
assert evaluate('greenstep', 'Price SGD 7,200')['decision'] != 'block'
assert evaluate('harbourbean')['decision'] == 'allow'
assert evaluate('audience')['decision'] == 'block'
assert not any(m in sys.modules for m in ('aegis.config', 'aegis.db', 'aegis.audit', 'aegis.gateway', 'aegis.qwen_client', 'aegis.worker'))
print('isolated module closure and input-dependent evaluation passed')
'''
    result = subprocess.run([sys.executable, '-c', code], cwd=tmp_path,
                            env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
