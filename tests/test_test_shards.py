"""Runner contracts without a full suite launch."""
import base64
from pathlib import Path
import subprocess
import pytest
from scripts import run_test_shards as runner


def test_partition(tmp_path):
    sources = {'test_a.py': '', 'test_b.py': '', 'test_browser.py': 'import playwright',
               'test_adaptive.py': ''}
    for name, source in sources.items():
        (tmp_path / name).write_text(source)
    nodes = [name + '::test_one' for name in sources]
    groups = runner.partition(nodes, 4, tmp_path)
    assert groups == runner.partition(list(reversed(nodes)), 4, tmp_path)
    assert groups[-2]['files'] == ['test_browser.py']
    assert groups[-1]['files'] == ['test_adaptive.py']
    runner.verify_union(nodes, [[f + '::test_one' for f in g['files']] for g in groups])


@pytest.mark.parametrize('collections', [[['a', 'a']], [['a']], [['a', 'b', 'c']]])
def test_union_rejects_mismatch(collections):
    with pytest.raises(ValueError):
        runner.verify_union(['a', 'b'], collections)


def test_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_QWEN_API_KEY', 'production-secret')
    monkeypatch.setenv('AEGIS_EVIDENCE_KEY_FILE', '/production/key')
    monkeypatch.setenv('PYTEST_ADDOPTS', '--lf')
    first = runner.isolated_env(tmp_path / 'one')
    second = runner.isolated_env(tmp_path / 'two')
    assert 'AEGIS_QWEN_API_KEY' not in first
    assert 'AEGIS_EVIDENCE_KEY_FILE' not in first
    assert 'PYTEST_ADDOPTS' not in first
    assert first['AEGIS_EVIDENCE_KEY'] != second['AEGIS_EVIDENCE_KEY']
    assert len(base64.urlsafe_b64decode(first['AEGIS_EVIDENCE_KEY'])) == 32
    assert first['AEGIS_SIGNER_STATE'] != second['AEGIS_SIGNER_STATE']
    assert Path(first['TMPDIR']).is_dir()


def test_exit_receipt(tmp_path, monkeypatch):
    seen = []
    class FakeProcess:
        returncode = 2
        def wait(self, timeout=None):
            return self.returncode
    def fake_run(command, **kwargs):
        seen.append(command)
        assert kwargs['start_new_session'] is True
        return FakeProcess()
    monkeypatch.setattr(runner.subprocess, 'Popen', fake_run)
    result = runner.invoke(['tests/test_x.py'], tmp_path / 'worker', True)
    assert result['exit_code'] == 2
    assert 'nodes' not in result
    assert '--collect-only' in seen[0]
    assert result['runtime_seconds'] >= 0
    assert (tmp_path / 'worker/pytest.log').exists()


def test_measured_partition_splits_expensive_files(tmp_path):
    for name in ('test_regular.py', 'test_browser.py', 'test_adaptive.py'):
        (tmp_path / name).write_text('import playwright' if 'browser' in name else '')
    nodes = [f'{name}::test_{i}' for name in
             ('test_regular.py', 'test_browser.py', 'test_adaptive.py') for i in range(12)]
    timings = {n: 20 for n in nodes}
    groups = runner.partition(nodes, 30, tmp_path, timings)
    assert groups == runner.partition(list(reversed(nodes)), 30, tmp_path, timings)
    assert len(groups) == 30
    runner.verify_union(nodes, [g['nodes'] for g in groups])
    assert max(g['estimated_seconds'] for g in groups) == 40
    assert all(len(g['files']) == 1 for g in groups)


def test_timeout_preserves_partial_log(tmp_path, monkeypatch):
    real_popen = subprocess.Popen
    def launch(command, **kwargs):
        return real_popen([runner.sys.executable, '-u', '-c',
                           'import time; print("partial output"); time.sleep(30)'], **kwargs)
    monkeypatch.setattr(runner.subprocess, 'Popen', launch)
    result = runner.invoke([], tmp_path / 'timeout', timeout=0.2)
    assert result['timed_out'] is True
    assert result['exit_code'] == 124
    assert 'partial output' in Path(result['log_path']).read_text()
    assert result['runtime_seconds'] < 5


@pytest.mark.parametrize('stubborn', [False, True])
def test_timeout_signals_only_owned_child(tmp_path, monkeypatch, stubborn):
    signals = []
    class FakeProcess:
        returncode = 0
        def wait(self, timeout=None):
            if timeout is not None and (not signals or stubborn):
                raise subprocess.TimeoutExpired('pytest', timeout)
            return 0
        def terminate(self):
            signals.append('terminate')
        def kill(self):
            signals.append('kill')
    monkeypatch.setattr(runner.subprocess, 'Popen', lambda *a, **k: FakeProcess())
    monkeypatch.setattr(runner.os, 'killpg', lambda *a: pytest.fail('Unsafe group signal'))
    result = runner.invoke([], tmp_path, timeout=1)
    assert signals == (['terminate', 'kill'] if stubborn else ['terminate'])
    assert result['exit_code'] == 124


def test_measured_timings_includes_all_phases(tmp_path):
    path = tmp_path / 'receipt.json'
    path.write_text(runner.json.dumps({'shards': [{'result': {'reports': [
        {'nodeid': 'a::test_x', 'duration': 2},
        {'nodeid': 'a::test_x', 'duration': 3}]}}]}))
    assert runner.measured_timings(path) == {'a::test_x': 5}


@pytest.mark.parametrize('option,value', [('--shard-timeout', '301'),
                                         ('--collection-timeout', '181'),
                                         ('--shard-timeout', 'nan'),
                                         ('--shard-timeout', '0')])
def test_cli_rejects_unsafe_timeout(tmp_path, option, value):
    with pytest.raises(SystemExit) as exc:
        runner.main(['--output-dir', str(tmp_path), option, value])
    assert exc.value.code == 2


@pytest.mark.parametrize('collect,timeout', [(True, 181), (False, 301),
                                           (True, float('inf'))])
def test_invoke_enforces_caps(tmp_path, collect, timeout):
    with pytest.raises(ValueError):
        runner.invoke([], tmp_path, collect=collect, timeout=timeout)


def test_partial_reports_checkpoint(tmp_path, monkeypatch):
    from types import SimpleNamespace
    path = tmp_path / 'result.json'
    monkeypatch.setenv('AEGIS_SHARD_RESULT', str(path))
    monkeypatch.setattr(runner, '_nodes', [])
    monkeypatch.setattr(runner, '_reports', [])
    runner.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid='a::test_x')]))
    runner.pytest_runtest_logreport(SimpleNamespace(nodeid='a::test_x', when='call',
                                                  outcome='passed', duration=2))
    result = runner.json.loads(path.read_text())
    assert result['nodes'] == ['a::test_x']
    assert result['reports'][0]['duration'] == 2
    assert not path.with_suffix('.tmp').exists()


def test_invalid_shards():
    with pytest.raises(ValueError):
        runner.partition([], 2)


@pytest.mark.parametrize('shard_range,expected', [(None, 30), ('1:6', 6)])
def test_failure_does_not_stop_scheduling(tmp_path, monkeypatch, shard_range, expected):
    from types import SimpleNamespace
    groups = [dict(name=f'shard-{i}', nodes=[f'test_{i}']) for i in range(30)]
    for group in groups:
        (tmp_path / group['name']).mkdir()
    receipt = dict(revision_fingerprint='frozen', shards=groups,
                   inventory=dict(nodes=[g['nodes'][0] for g in groups]),
                   retained_directory=str(tmp_path))
    path = tmp_path / 'receipt.json'
    monkeypatch.setattr(runner, 'revision_fingerprint', lambda: 'frozen')
    monkeypatch.setattr(runner.subprocess, 'check_output', lambda *a, **k: '')
    launched = []
    def invoke(nodes, directory, **kwargs):
        launched.append(nodes[0])
        assert kwargs['timeout'] == 300
        return dict(exit_code=1 if nodes == ['test_0'] else 0)
    monkeypatch.setattr(runner, 'invoke', invoke)
    args = SimpleNamespace(shard_range=shard_range, jobs=6,
                           shard_timeout=300, batch_timeout=300)
    runner.execute_batch(receipt, path, args)
    assert len(launched) == expected
    assert len(set(launched)) == expected
    assert receipt['executed_shards'] == expected
    assert receipt['failed_shards'] == 1
    assert receipt['execution_complete'] == (expected == 30)
    assert receipt['status'] == ('failed' if expected == 30 else 'partial')
    assert runner.main(['--execute', '--resume', str(path), '--output-dir',
                        str(tmp_path), '--shard-range', '1:6']) == 1
    assert receipt['parallelism']['workers_per_shard'] == 1


def test_command_disables_failfast_and_default_cap(tmp_path, monkeypatch):
    class FakeProcess:
        returncode = 1
        def wait(self, timeout=None):
            assert timeout == 300
    monkeypatch.setattr(runner.subprocess, 'Popen', lambda *a, **k: FakeProcess())
    result = runner.invoke(['test_failure.py'], tmp_path)
    assert '--maxfail=0' in result['command']
    assert '-x' not in result['command']
    assert result['exit_code'] == 1


@pytest.mark.parametrize('broken', ['failure', 'timeout', 'missing', 'incomplete', 'none'])
def test_subshards_schedule_exact_union_and_fail_closed(tmp_path, monkeypatch, broken):
    launched = []
    def invoke(nodes, directory, collect=False, **kwargs):
        launched.append((nodes, collect, str(directory)))
        result = dict(nodes=nodes, exit_code=0, session_complete=True,
                      runtime_seconds=1, reports=[])
        if not collect:
            result['reports'] = [dict(nodeid=nodes[0], phase=phase,
                                      outcome='passed', duration=0.1)
                                 for phase in ('setup', 'call', 'teardown')]
            if nodes == ['b']:
                if broken == 'failure':
                    result['exit_code'] = 1
                elif broken == 'timeout':
                    result.update(exit_code=124, timed_out=True)
                elif broken == 'missing':
                    result['nodes'] = []
                elif broken == 'incomplete':
                    result['session_complete'] = False
        return result
    monkeypatch.setattr(runner, 'invoke', invoke)
    result = runner.invoke_subshards(['a', 'b', 'c'], tmp_path, 290)
    assert [n for nodes, collect, _ in launched if not collect for n in nodes] == ['a', 'b', 'c']
    assert len({directory for _, collect, directory in launched if not collect}) == 3
    assert (result['exit_code'] == 0) == (broken == 'none')
    assert len(result['subshards']) == 3
    assert result['runtime_seconds'] >= 0
