import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from aegis import signer_client
from scripts import run_test_shards as runner


def gone(pid):
    for _ in range(60):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(.1)
    return False


def test_startup_failure_reaps_child(tmp_path, monkeypatch):
    children = []
    real = subprocess.Popen

    def launch(*args, **kwargs):
        child = real(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(signer_client.subprocess, 'Popen', launch)
    monkeypatch.setattr(signer_client.SignerClient, 'request', lambda *a: (_ for _ in ()).throw(RuntimeError('readiness failure')))
    try:
        with pytest.raises(RuntimeError, match='readiness failure'):
            signer_client.SignerManager(str(tmp_path / 'signer'))
        assert children[0].poll() is not None
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


@pytest.mark.parametrize('ending', ['normal', 'failure', 'timeout', 'kill'])
def test_isolated_pytest_reaps_signer(tmp_path, ending):
    root = Path(__file__).resolve().parents[1]
    pidfile = tmp_path / 'signer.pid'
    source = tmp_path / 'test_owned.py'
    source.write_text('''import os, time
from pathlib import Path
import pytest
from aegis.signer_client import SignerManager
@pytest.fixture
def signer(request):
    manager = SignerManager(os.environ['AEGIS_SIGNER_STATE'])
    request.addfinalizer(manager.stop)
    Path(%r).write_text(str(manager.proc.pid))
    return manager

def test_owned(signer):
    %s
''' % (str(pidfile), 'time.sleep(30)' if ending in ('timeout', 'kill') else 'assert False' if ending == 'failure' else 'assert signer.port > 0'))
    if ending == 'kill':
        env = runner.isolated_env(tmp_path / 'worker')
        parent = subprocess.Popen([sys.executable, '-m', 'pytest', '-o', 'addopts=', '-q', str(source)], cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if pidfile.exists():
                    break
                time.sleep(.1)
            assert pidfile.exists()
            parent.kill()
            parent.wait(timeout=5)
            assert gone(int(pidfile.read_text()))
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=5)
    else:
        result = runner.invoke([str(source)], tmp_path / 'worker', timeout=3 if ending == 'timeout' else 20)
        assert pidfile.exists(), Path(result['log_path']).read_text()
        assert gone(int(pidfile.read_text()))
        if ending == 'timeout':
            assert result['exit_code'] == 124
        else:
            assert result['pytest_exitstatus'] == (1 if ending == 'failure' else 0)
