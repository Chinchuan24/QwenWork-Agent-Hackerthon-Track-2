"""Deterministic file shards; default is collection-only planning."""
import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
import math
import statistics
import hashlib
import importlib.util
import threading
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def isolated_env(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('AEGIS_', 'PYTEST_'))}
    env.update(AEGIS_DATA_DIR=str(directory / 'data'),
               AEGIS_ANCHOR_EXTERNAL=str(directory / 'external/anchor.json'),
               AEGIS_SIGNER_STATE=str(directory / 'signer'), AEGIS_SIGNER_PORT='0',
               AEGIS_EVIDENCE_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode(),
               TMPDIR=str(directory), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    return env


def partition(nodes, shards=30, root=ROOT, timings=None):
    if shards < 3:
        raise ValueError('At least three shards required')
    timings = timings or {}
    fallback = statistics.median(timings.values()) if timings else 1
    weights = {}
    for file in {n.split('::', 1)[0] for n in nodes}:
        measured = [timings[n] for n in nodes if n.split('::', 1)[0] == file and n in timings]
        estimate = statistics.median(measured) if measured else fallback
        weights.update({n: timings.get(n, estimate) for n in nodes
                        if n.split('::', 1)[0] == file})
    categories = {kind: [] for kind in ('regular', 'browser', 'adaptive')}
    target = max(1, sum(weights[n] for n in nodes) / shards)
    for file in sorted({n.split('::', 1)[0] for n in nodes}):
        source = (Path(root) / file).read_text()
        if 'playwright' in source or 'test_r12_browser import' in source:
            kind = 'browser'
        elif 'adaptive' in Path(file).name:
            kind = 'adaptive'
        else:
            kind = 'regular'
        selected = sorted(n for n in nodes if n.split('::', 1)[0] == file)
        weight = sum(weights[n] for n in selected)
        if weight > target and timings:
            categories[kind].extend(([n], weights[n]) for n in selected)
        else:
            categories[kind].append((selected, weight))
    slots = {'regular': shards - 2, 'browser': 1, 'adaptive': 1}
    if timings:
        slots = dict.fromkeys(categories, 1)
        for _ in range(shards - 3):
            kind = max(categories, key=lambda k: (sum(w for _, w in categories[k]) / slots[k], k))
            slots[kind] += 1
    groups = []
    for kind, units in categories.items():
        lanes = [dict(name=(kind if slots[kind] == 1 else f'{kind}-{i+1:02d}'),
                      files=[], nodes=[], test_count=0, estimated_seconds=0)
                 for i in range(slots[kind])]
        for selected, weight in sorted(units, key=lambda u: (-u[1], u[0])):
            lane = min(lanes, key=lambda g: (g['estimated_seconds'], g['name']))
            lane['nodes'].extend(selected)
            lane['estimated_seconds'] += weight
        for lane in lanes:
            lane['nodes'].sort()
            lane['files'] = sorted({n.split('::', 1)[0] for n in lane['nodes']})
            lane['test_count'] = len(lane['nodes'])
            if lane['nodes']:
                groups.append(lane)
    verify_union(nodes, [g['nodes'] for g in groups])
    return groups


def measured_timings(path):
    receipt = json.loads(Path(path).read_text())
    timings = Counter()
    for shard in receipt.get('shards', []):
        for report in shard.get('result', {}).get('reports', []):
            timings[report['nodeid']] += report['duration']
    return dict(timings)


def verify_union(expected, collections):
    actual = [n for collection in collections for n in collection]
    if len(expected) != len(set(expected)) or len(actual) != len(set(actual)):
        raise ValueError('Duplicate collected nodes')
    if set(expected) != set(actual):
        raise ValueError(f'Collection mismatch: missing={sorted(set(expected)-set(actual))}, '
                         f'extra={sorted(set(actual)-set(expected))}')


def verify_execution(result):
    nodes = result.get('nodes', [])
    if not nodes or len(nodes) != len(set(nodes)) or not result.get('session_complete'):
        raise ValueError('incomplete execution collection or session')
    reports = result.get('reports', [])
    if any(r.get('outcome') != 'passed' or r.get('nodeid') not in nodes for r in reports):
        raise ValueError('failed, skipped or uncollected execution report')
    for node in nodes:
        phases = Counter(r['phase'] for r in reports if r['nodeid'] == node)
        # Subtests add call reports; setup and teardown must each complete once.
        if phases['setup'] < 1 or phases['teardown'] < 1 or phases['call'] < 1:
            raise ValueError('missing ordinary execution phase')


def invoke(files, directory, collect=False, root=ROOT, timeout=None):
    cap = 180 if collect else 300
    timeout = cap if timeout is None else timeout
    if not math.isfinite(timeout) or not 0 < timeout <= cap:
        raise ValueError(f'Timeout must be positive and finite, <= {cap}')
    directory = Path(directory).resolve()
    root = Path(root).resolve()
    env = isolated_env(directory)
    path = directory / 'pytest-result.json'
    env['AEGIS_SHARD_RESULT'] = str(path)
    command = [sys.executable, '-m', 'pytest', '-p', 'scripts.run_test_shards',
               '-o', 'addopts=', '--maxfail=0', '-o', 'cache_dir=' + str(directory / 'cache'),
               '--basetemp', str(directory / 'pytest-temp'), '-q']
    if collect:
        command.append('--collect-only')
    command.extend(files)
    start = time.monotonic()
    timed_out = False
    try:
        with (directory / 'pytest.log').open('w') as log:
            proc = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Popen owns this child; never signal a reusable process-group ID.
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                proc.wait()
        result = json.loads(path.read_text()) if path.exists() else {}
        result['exit_code'] = 124 if timed_out else proc.returncode
        if not collect and result['exit_code'] == 0:
            try:
                verify_execution(result)
            except ValueError as exc:
                result.update(exit_code=1, error=str(exc))
    except (OSError, ValueError) as exc:
        result = dict(exit_code=None, error=str(exc))
    result.update(command=command, runtime_seconds=time.monotonic()-start,
                  directory=str(directory), collect_only=collect, timed_out=timed_out,
                  timeout_seconds=timeout, log_path=str(directory / 'pytest.log'))
    if timed_out:
        result.update(exit_code=124, error='Subprocess timeout; partial log retained')
    return result


def invoke_subshards(nodes, directory, timeout=300, collection_timeout=180):
    start = time.monotonic()
    directory = Path(directory)
    def run(pair):
        index, node = pair
        child = directory / f'node-{index:03d}'
        try:
            collection = invoke([node], child / 'collect', collect=True,
                                timeout=collection_timeout)
            result = invoke([node], child / 'execute', timeout=timeout)
            verify_union([node], [collection.get('nodes', [])])
            verify_union([node], [result.get('nodes', [])])
            phases = {r['phase'] for r in result.get('reports', [])
                      if r['nodeid'] == node}
            if (collection.get('exit_code') != 0 or not collection.get('session_complete')
                    or not result.get('session_complete')
                    or phases != {'setup', 'call', 'teardown'}):
                result['exit_code'] = result.get('exit_code') or 1
                result['error'] = 'Incomplete collection, session or node reports'
        except Exception as exc:
            result = dict(exit_code=None, error=str(exc))
            collection = locals().get('collection', {})
        return dict(nodes=[node], collection=collection, result=result)
    with ThreadPoolExecutor(max_workers=2) as pool:
        children = list(pool.map(run, enumerate(nodes, 1)))
    results = [child['result'] for child in children]
    union_verified = False
    try:
        verify_union(nodes, [c['collection'].get('nodes', []) for c in children])
        verify_union(nodes, [r.get('nodes', []) for r in results])
        union_verified = True
    except ValueError:
        pass
    return dict(nodes=nodes, subshards=children,
                reports=[report for r in results for report in r.get('reports', [])],
                exit_code=0 if union_verified and all(r.get('exit_code') == 0 for r in results) else 1,
                collection_union_verified=union_verified,
                session_complete=all(r.get('session_complete', False) for r in results),
                timed_out=any(r.get('timed_out', False) for r in results),
                runtime_seconds=time.monotonic()-start)


_nodes = []
_reports = []
_live_nodes = []
_live_reports = []


def pytest_collection_finish(session):
    _nodes[:] = [item.nodeid for item in session.items]
    _live_nodes[:] = _nodes
    checkpoint(0, False)


def pytest_runtest_logreport(report):
    entry = dict(nodeid=report.nodeid, phase=report.when,
                 outcome=report.outcome, duration=report.duration)
    _reports.append(entry)
    if report.nodeid.startswith('tests/'):
        _live_reports.append(entry)
    checkpoint(0, False)


def pytest_sessionfinish(session, exitstatus):
    _nodes[:] = [item.nodeid for item in session.items]
    _reports[:] = [r for r in _live_reports if r['nodeid'] in _nodes]
    checkpoint(exitstatus, True)


def checkpoint(exitstatus, complete):
    path = os.environ.get('AEGIS_SHARD_RESULT')
    if path:
        target = Path(path)
        temporary = target.with_suffix('.tmp')
        temporary.write_text(json.dumps(dict(nodes=_nodes, reports=_reports,
                                            pytest_exitstatus=int(exitstatus),
                                            session_complete=complete), indent=2))
        temporary.replace(target)


def revision_fingerprint(root=ROOT):
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob('*')):
        relative = path.relative_to(root)
        if any(part.startswith('.') or part in ('__pycache__', 'aegis_data', 'outputs')
               for part in relative.parts):
            continue
        if path.is_file() and path.suffix in ('.py', '.html', '.css', '.js', '.json', '.yml', '.txt'):
            digest.update(str(relative).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def save_receipt(path, receipt):
    temporary = path.with_suffix('.tmp')
    receipt['updated_at'] = datetime.now(timezone.utc).isoformat()
    temporary.write_text(json.dumps(receipt, indent=2))
    temporary.replace(path)


def execute_batch(receipt, path, args):
    if receipt.get('revision_fingerprint') != revision_fingerprint():
        raise ValueError('Revision fingerprint absent or changed; legacy passes cannot be reused')
    receipt['parallelism'] = dict(
        xdist_available=importlib.util.find_spec('xdist') is not None,
        workers_per_shard=1,
        reason='Resource-bound file shards avoid nested -n auto CPU oversubscription. '
               'Conftest allocates per-process data, signer state and keys, but '
               'within-file worker distribution and receipt isolation are not verified safe.')
    groups = receipt['shards']
    verify_union(receipt['inventory']['nodes'], [g['nodes'] for g in groups])
    first, last = (map(int, args.shard_range.split(':')) if args.shard_range
                   else (1, len(groups)))
    if not 1 <= first <= last <= len(groups):
        raise ValueError('Shard range must be inclusive, within the receipt')
    selected = [g for g in groups[first-1:last] if g.get('result', {}).get('exit_code') != 0]
    # Refuse overlapping batches and orphaned children identified by this retained path.
    processes = subprocess.check_output(['ps', '-axo', 'pid=,command='], text=True)
    retained = Path(receipt['retained_directory']).resolve()
    if any(' -m pytest ' in line and str(retained) in line.replace('/private/var/', '/var/')
           for line in processes.splitlines()):
        raise ValueError('A retained pytest child is still active; wait before resuming')
    lock = path.with_suffix('.lock')
    with lock.open('x'):
        pass
    mutex = threading.Lock()
    try:
        receipt['status'] = 'running'
        save_receipt(path, receipt)
        def run(group):
            try:
                directory = Path(tempfile.mkdtemp(prefix='attempt-', dir=retained / group['name']))
                timeout = min(args.shard_timeout, args.batch_timeout)
                previous = group.get('result', {})
                split = len(group['nodes']) > 1 and (
                    previous.get('timed_out') or previous.get('runtime_seconds', 0) >= timeout
                    or group.get('estimated_seconds', 0) >= timeout)
                group['result'] = (invoke_subshards(group['nodes'], directory, timeout,
                                                  getattr(args, 'collection_timeout', 180))
                                   if split else invoke(group['nodes'], directory, timeout=timeout))
            except Exception as exc:
                group['result'] = dict(exit_code=None, error=str(exc))
            with mutex:
                if revision_fingerprint() != receipt['revision_fingerprint']:
                    group['result']['revision_changed'] = True
                    group['result']['exit_code'] = None
                save_receipt(path, receipt)
        timeout = min(args.shard_timeout, args.batch_timeout)
        splitting = any(len(g['nodes']) > 1 and (
            g.get('result', {}).get('timed_out')
            or g.get('result', {}).get('runtime_seconds', 0) >= timeout
            or g.get('estimated_seconds', 0) >= timeout) for g in selected)
        jobs = 1 if splitting else args.jobs
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for offset in range(0, len(selected), jobs):
                list(pool.map(run, selected[offset:offset + jobs]))
        results = [g.get('result', {}) for g in groups]
        receipt['executed_shards'] = sum('result' in g for g in groups)
        receipt['failed_shards'] = sum(r.get('exit_code') != 0 for r in results if r)
        receipt['execution_complete'] = all('result' in g for g in groups)
        receipt['status'] = ('passed' if all(r.get('exit_code') == 0 for r in results)
                             else 'failed' if receipt['execution_complete'] else 'partial')
        save_receipt(path, receipt)
    finally:
        lock.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shards', type=int, default=30)
    parser.add_argument('--jobs', type=int, default=6)
    parser.add_argument('--shard-timeout', type=float, default=300)
    parser.add_argument('--collection-timeout', type=float, default=180)
    parser.add_argument('--timings-receipt', type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--resume', type=Path)
    parser.add_argument('--shard-range', help='Inclusive range; default schedules all unfinished shards')
    parser.add_argument('--batch-timeout', type=float, default=300,
                        help='Per-wave bound, at most --jobs children per wave')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.shards < 3 or args.jobs < 1:
        parser.error('--shards >=3 and --jobs >=1 required')
    if not (0 < args.shard_timeout <= 300 and 0 < args.collection_timeout <= 180):
        parser.error('Timeouts must be positive; shard <=300, collection <=180')
    args.jobs = min(args.jobs, 6)
    if not 5 < args.batch_timeout <= 300:
        parser.error('--batch-timeout must be >5 and <=300')
    if args.resume:
        if not args.execute:
            parser.error('--resume requires --execute')
        path = args.resume.resolve()
        receipt = json.loads(path.read_text())
        try:
            execute_batch(receipt, path, args)
        except (ValueError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(json.dumps(dict(receipt=str(path), status=receipt['status'])))
        return 0 if receipt['status'] == 'passed' else 1
    args.output_dir.mkdir(parents=True, exist_ok=True)
    retained = Path(tempfile.mkdtemp(prefix='aegis-test-shards-'))
    path = args.output_dir / (retained.name + '.json')
    receipt = dict(status='planning', retained_directory=str(retained),
                   jobs=args.jobs, requested_shards=args.shards, shards=[],
                   revision_fingerprint=revision_fingerprint())
    start = time.monotonic()
    try:
        baseline = invoke(['tests'], retained / 'inventory', collect=True,
                          timeout=args.collection_timeout)
        receipt['inventory'] = baseline
        if baseline['exit_code'] != 0 or not baseline.get('nodes'):
            raise ValueError('Inventory collection failed or empty; see retained log')
        timings = measured_timings(args.timings_receipt) if args.timings_receipt else {}
        groups = partition(baseline['nodes'], args.shards, timings=timings)
        receipt.update(test_count=len(baseline['nodes']),
                       file_count=len({f for g in groups for f in g['files']}), shards=groups,
                       measured_node_count=len(set(baseline['nodes']) & timings.keys()),
                       shard_timeout=args.shard_timeout, collection_timeout=args.collection_timeout)
        def collect(group):
            group['collection'] = invoke(group['nodes'], retained / group['name'] / 'collect', True,
                                         timeout=args.collection_timeout)
            return group['collection']
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            collections = list(pool.map(collect, groups))
        if any(c['exit_code'] != 0 for c in collections):
            raise ValueError('Shard collection failed; see retained logs')
        verify_union(baseline['nodes'], [c['nodes'] for c in collections])
        receipt.update(collection_union_verified=True, status='planned')
        save_receipt(path, receipt)
        if args.execute:
            execute_batch(receipt, path, args)
    except Exception as exc:
        receipt.update(status='failed', error=str(exc))
    finally:
        receipt['runtime_seconds'] = time.monotonic()-start
        save_receipt(path, receipt)
        print(json.dumps(dict(receipt=str(path), status=receipt['status'],
                              test_count=receipt.get('test_count'),
                              runtime_seconds=receipt['runtime_seconds'])))
    return 0 if receipt['status'] in ('planned', 'passed') else 1


if __name__ == '__main__':
    sys.exit(main())
