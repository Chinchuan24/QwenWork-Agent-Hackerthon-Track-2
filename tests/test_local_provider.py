"""Fake-only local provider and credential-file regressions."""
import json
import pytest
from aegis.provider import resolve
from scripts.local_env import load
from aegis import config, qwen_client as client

def test_selection():
    assert resolve({}) == ('scripted', '', '', '')
    result = resolve({'DEEPSEEK_API_KEY': 'fake-key'})
    assert result == ('deepseek', 'https://api.deepseek.com', 'deepseek-chat', 'fake-key')
    assert resolve({'AEGIS_MODEL_PROVIDER': 'scripted', 'DEEPSEEK_API_KEY': 'fake-key'})[3] == ''

@pytest.mark.parametrize('url', ['http://vendor.example/v1', 'https://127.0.0.1', 'https://x:y@vendor.example', 'https://vendor.example?secret=x', 'https://vendor.local', 'https://vendor.example:8080'])
def test_unsafe_endpoint(url):
    with pytest.raises(ValueError):
        resolve({'AEGIS_MODEL_PROVIDER': 'openai-compatible', 'AEGIS_MODEL_BASE_URL': url, 'AEGIS_MODEL_NAME': 'model'})

def test_public_boundary():
    with pytest.raises(ValueError):
        resolve({'AEGIS_MODEL_PROVIDER': 'openai-compatible'}, public=True)

def test_private_literal_file(tmp_path):
    file = tmp_path / '.env'
    file.write_text('DEEPSEEK_API_KEY=fixture-key\nAEGIS_MODEL_PROVIDER=deepseek\n')
    file.chmod(0o600)
    assert load(tmp_path)['DEEPSEEK_API_KEY'] == 'fixture-key'
    file.chmod(0o644)
    with pytest.raises(ValueError, match='chmod 600'):
        load(tmp_path)

@pytest.mark.parametrize('value', ['$(command)', '`command`', '${HOME}'])
def test_no_expansion(tmp_path, value):
    file = tmp_path / '.env'
    file.write_text('DEEPSEEK_API_KEY=' + value)
    file.chmod(0o600)
    with pytest.raises(ValueError):
        load(tmp_path)

def test_explicit_scripted_never_opens_env(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('scripted mode must not open credential files')
    monkeypatch.setattr('scripts.local_env.os.open', forbidden)
    assert resolve(load(tmp_path, scripted=True)) == ('scripted', '', '', '')


def test_local_strict_json(monkeypatch):
    monkeypatch.setattr(config, 'LOCAL_AI', True)
    assert client._parse_strict('preface {"verdict":"safe"}', {'safe'})['verdict'] == 'unsure'
    assert client._parse_strict(json.dumps({'verdict': 'safe'}), {'safe'})['verdict'] == 'safe'

def test_timeout_sanitized(monkeypatch):
    monkeypatch.setattr(config, 'LOCAL_AI', True)
    monkeypatch.setattr(config, 'QWEN_API_KEY', 'fixture-secret')
    monkeypatch.setattr(config, 'LIVE_RETRIES', 0)
    monkeypatch.setattr(client, '_admit_attempt', lambda mode: None)
    class Fake:
        def open(self, *args, **kwargs):
            raise TimeoutError('fixture-secret')
    from aegis import provider
    monkeypatch.setattr(provider, 'open_pinned', Fake().open)
    with pytest.raises(client.JudgeUnavailable) as error:
        client._chat('model', [{'role': 'user', 'content': 'sample'}])
    assert 'fixture-secret' not in str(error.value)
