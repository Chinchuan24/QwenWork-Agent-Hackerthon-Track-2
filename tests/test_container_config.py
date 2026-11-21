"""Static isolated-public packaging checks without Docker or real secrets."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_persisted_state_and_external_secrets():
    compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
    service = compose['services']['aegis']
    assert service['read_only'] is True
    assert service['volumes'] == ['aegis_data:/data']
    assert set(compose['volumes']) == {'aegis_data'}
    assert service['cap_drop'] == ['ALL']
    assert service['security_opt'] == ['no-new-privileges:true']
    assert 'tmpfs' not in service
    assert set(service['environment']) == {'AEGIS_TRUSTED_HOSTS', 'AEGIS_TRUSTED_PROXY_CIDRS'}
    assert all('${' in v and ':?' in v for v in service['environment'].values())


def test_image_paths_and_fail_closed_install():
    text = (ROOT / 'Dockerfile').read_text()
    assert 'pip install --no-cache-dir --require-hashes -r requirements-production.lock' in text
    assert '|| true' not in text
    assert 'USER 10001:10001' in text
    assert 'chown 10001:10001 /data' in text
    assert 'VOLUME ["/data"]' in text
    assert 'TMPDIR=/data/tmp' in text
    assert 'AEGIS_PRODUCTION_DATA_DIR=/data/aegis' in text
    assert 'CMD ["python", "-m", "aegis.production"]' in text
    copies = [line for line in text.splitlines() if line.startswith('COPY ')]
    assert copies == [
        'COPY requirements-production.lock ./',
        'COPY aegis/__init__.py aegis/production.py aegis/public_evaluator.py aegis/claims.py aegis/policy.py aegis/sensitivity.py aegis/mixed_demo.py ./aegis/']
    for excluded in ('run.py', 'qwen_client.py', 'gateway.py', 'worker.py', 'config.py', 'db.py'):
        assert excluded not in text


def test_private_build_context_exclusions():
    patterns = (ROOT / '.dockerignore').read_text().splitlines()
    assert '**' in patterns
    allowed = {p[1:] for p in patterns if p.startswith('!')}
    assert allowed == {'Dockerfile', 'requirements-production.lock', 'aegis/',
                       'aegis/__init__.py', 'aegis/production.py', 'aegis/public_evaluator.py',
                       'aegis/claims.py', 'aegis/policy.py', 'aegis/sensitivity.py', 'aegis/mixed_demo.py'}
    assert not any(p.endswith(('.key', '.pem')) or '.env' in p for p in allowed)
