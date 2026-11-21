import base64
import importlib.util
import json
import shutil
import stat
from pathlib import Path

import pytest


def helper():
    path = Path(__file__).resolve().parents[1] / 'scripts/local_setup.py'
    spec = importlib.util.spec_from_file_location('local_setup', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_init_private_repeat_and_relocation(tmp_path):
    h = helper()
    root = tmp_path / 'clone'
    root.mkdir()
    h.initialize(root)
    runtime = root / '.local-runtime'
    before = {p.relative_to(runtime): p.read_bytes() for p in runtime.rglob('*') if p.is_file()}
    h.initialize(root)
    assert before == {p.relative_to(runtime): p.read_bytes() for p in runtime.rglob('*') if p.is_file()}
    for p in [runtime, *runtime.rglob('*')]:
        assert stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600)
    moved = tmp_path / 'moved'
    shutil.move(root, moved)
    env = h.environment(moved, {'AEGIS_EVIDENCE_KEY': 'unsafe', 'AEGIS_SIGNER_PORT': '42', 'AEGIS_QWEN_API_KEY': 'live'})
    assert env['AEGIS_DATA_DIR'] == str(moved / '.local-runtime/data')
    assert env['AEGIS_SIGNER_PORT'] == '0'
    assert env['AEGIS_QWEN_API_KEY'] == ''
    assert env['AEGIS_EVIDENCE_KEY'] == ''
    assert len(base64.urlsafe_b64decode(Path(env['AEGIS_EVIDENCE_KEY_FILE']).read_text())) == 32
    assert not Path(env['AEGIS_SIGNER_STATE']).is_relative_to(Path(env['AEGIS_DATA_DIR']))


@pytest.mark.parametrize('damage', ['partial', 'key', 'config', 'symlink', 'permissions'])
def test_refuse_damage_without_changes(tmp_path, damage):
    h = helper()
    h.initialize(tmp_path)
    runtime = tmp_path / '.local-runtime'
    if damage == 'partial':
        (runtime / 'signer/signing.key').unlink()
    elif damage == 'key':
        (runtime / 'evidence.key').write_text(base64.urlsafe_b64encode(b'x' * 32).decode())
    elif damage == 'config':
        p = runtime / 'environment.json'
        obj = json.loads(p.read_text())
        obj['AEGIS_DATA_DIR'] = '../aegis_data'
        p.write_text(json.dumps(obj))
    elif damage == 'symlink':
        (runtime / 'data').rmdir()
        (runtime / 'data').symlink_to(tmp_path, target_is_directory=True)
    else:
        (runtime / 'evidence.key').chmod(0o644)
    before = (runtime / 'evidence.key').read_bytes()
    with pytest.raises(h.RuntimeInvalid):
        h.initialize(tmp_path)
    with pytest.raises(h.RuntimeInvalid):
        h.environment(tmp_path, {})
    assert (runtime / 'evidence.key').read_bytes() == before


def test_inherited_aegis_settings_are_removed(tmp_path):
    h = helper()
    h.initialize(tmp_path)
    inherited = {
        'PATH': '/usr/bin',
        'AEGIS_REPLAY_FILE': '/existing/replay.json',
        'AEGIS_RECORD_FILE': '/existing/record.json',
        'AEGIS_PORT': '9090',
        'AEGIS_SPEND_CAP_USD': 'invalid',
        'AEGIS_JUDGE_TIMEOUT_S': 'invalid',
        'AEGIS_ADAPTIVE_SEED': 'invalid',
        'AEGIS_FUTURE_SETTING': 'unsafe',
    }
    before = dict(inherited)
    env = h.environment(tmp_path, inherited)
    assert inherited == before
    assert env['PATH'] == inherited['PATH']
    assert not (set(inherited) - {'PATH'}) & set(env)
    assert {k for k in env if k.startswith('AEGIS_')} == {
        *h.LAYOUT, 'AEGIS_EVIDENCE_KEY', 'AEGIS_EVIDENCE_KEYRING_FILE',
        'AEGIS_SIGNER_PORT', 'AEGIS_QWEN_API_KEY', 'AEGIS_HOST',
    }


@pytest.mark.parametrize('port', [1, 8081, 65535])
def test_run_explicit_port(tmp_path, monkeypatch, port):
    h = helper()
    h.initialize(tmp_path)
    calls = []
    monkeypatch.setenv('AEGIS_PORT', '9090')
    monkeypatch.setenv('AEGIS_REPLAY_FILE', '/existing/replay.json')
    monkeypatch.setattr(h.os, 'execve', lambda *args: calls.append(args))
    monkeypatch.setattr(h.os, 'chdir', lambda path: None)
    h.run(tmp_path, port=port)
    assert calls[0][2]['AEGIS_PORT'] == str(port)
    assert 'AEGIS_REPLAY_FILE' not in calls[0][2]


@pytest.mark.parametrize('value', ['0', '65536', '-1', 'abc', '1.5'])
def test_cli_rejects_invalid_port(monkeypatch, value):
    h = helper()
    monkeypatch.setattr(h.sys, 'argv', ['local_setup.py', 'run', '--port', value])
    monkeypatch.setattr(h, 'run', lambda *args, **kwargs: pytest.fail('must not execute'))
    with pytest.raises(SystemExit) as exc:
        h.main()
    assert exc.value.code == 2


def test_cli_forwards_explicit_port(monkeypatch):
    h = helper()
    calls = []
    monkeypatch.setattr(h.sys, 'argv', ['local_setup.py', 'run', '--port', '8081'])
    monkeypatch.setattr(h, 'run', lambda root, port=None, live=False: calls.append(port))
    assert h.main() == 0
    assert calls == [8081]


def test_run_exec_is_private(tmp_path, monkeypatch, capsys):
    h = helper()
    h.initialize(tmp_path)
    calls = []
    monkeypatch.setattr(h.os, 'execve', lambda *args: calls.append(args))
    monkeypatch.setattr(h.os, 'chdir', lambda path: None)
    monkeypatch.setenv('AEGIS_PORT', '9090')
    h.run(tmp_path)
    executable, argv, env = calls[0]
    assert 'AEGIS_PORT' not in env
    assert argv == [executable, str(tmp_path / 'run.py')]
    assert env['AEGIS_HOST'] == '127.0.0.1'
    assert not capsys.readouterr().out
