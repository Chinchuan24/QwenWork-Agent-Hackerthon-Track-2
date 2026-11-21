"""One offline S1 story through the real gateway, with disposable state."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DISCLAIMER = ('simulated Lumen business and built-in stand-in judges; real gateway; '
              'real separate signer over local pipes instead of TCP. No live AI, '
              'network, persistent runtime reuse, or whole sponsor acceptance claim.')


def story_passed(report):
    steps = report.get('steps', [])
    return (len(steps) == 2 and steps[0]['verdict'] in ('allow', 'hold', 'block')
            and steps[1]['verdict'] == 'block' and 'R15' in steps[1]['rules']
            and all(report.get(k) is True for k in
                    ('audit_ok', 'decision_bindings_ok', 'documents_unchanged', 'api_ok'))
            and report.get('effects') == 0)


def run_story(reviewed_manifest=None):
    """Launch isolated child; return measured report without importing core here."""
    import local_setup
    with tempfile.TemporaryDirectory(prefix='aegis-sponsor-') as scratch:
        local_setup.initialize(scratch)
        inherited = {k: v for k, v in os.environ.items() if not k.startswith('AEGIS_')}
        env = local_setup.environment(scratch, inherited)
        proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--child'],
                                cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, _ = proc.communicate(
                input=json.dumps(reviewed_manifest, allow_nan=False), timeout=30)
        except subprocess.TimeoutExpired:
            # The signer inherits this owned group; kill it before scratch cleanup.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                proc.communicate()
            raise RuntimeError('Isolated story timed out; owned process group stopped') from None
        if proc.returncode:
            raise RuntimeError('Isolated story execution failed; no persistent state used')
        return json.loads(stdout)


def _child(reviewed_manifest=None):
    os.umask(0o077)
    # Reject sockets even on loopback. The real signer runs over process pipes.
    def no_network(event, args):
        if event in ('socket.__new__', 'socket.connect', 'socket.bind', 'socket.getaddrinfo'):
            raise RuntimeError('Network forbidden in sponsor story')
    sys.addaudithook(no_network)
    sys.path.insert(0, str(ROOT))
    from aegis import config, signer_client
    signer_code = '''import json, sys
from aegis.signer import SignerState
state = SignerState(sys.argv[1])
for text in sys.stdin:
    req = json.loads(text)
    op = req['op']
    stream = req.get('stream', '')
    if op == 'ping': reply = {'ok': True}
    elif op == 'sign': reply = state.sign(stream, req['body'])
    elif op == 'latest': reply = state.latest.get(stream, {'seq': 0})
    elif op == 'verify_batch':
        lines = req.get('lines', [])
        records = state.records.get(stream, {})
        valid = [bool(records.get(line.get('seq')) and records[line['seq']]['sig'] == line.get('sig') and records[line['seq']]['body'] == line.get('body')) for line in lines]
        reply = {'results': valid, 'latest': state.latest.get(stream, {'seq': 0})}

    elif op == 'verify_line':
        line = req['line']
        rec = state.records.get(stream, {}).get(line.get('seq'))
        reply = {'ok': bool(rec and rec['sig'] == line.get('sig') and rec['body'] == line.get('body'))}
    else: reply = {'error': 'unsupported pipe operation'}
    print(json.dumps(reply), flush=True)
'''
    signer = subprocess.Popen([sys.executable, '-c', signer_code, config.AEGIS_SIGNER_STATE],
                              cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True)
    def request(client, obj):
        signer.stdin.write(json.dumps(obj) + '\n')
        signer.stdin.flush()
        line = signer.stdout.readline()
        if not line:
            raise signer_client.SignerUnavailable('Pipe signer unavailable')
        return json.loads(line)
    signer_client.SignerClient.request = request
    try:
        from aegis import audit, db, evidence, gateway, lumen_world, policy
        from aegis.lumen_sponsor import SCENARIOS
        db.init_db()
        from aegis.tool_passport import ToolPassport
        if (type(reviewed_manifest) is not dict
                or set(reviewed_manifest) != {'version', 'approved_records'}
                or type(reviewed_manifest['version']) is not int
                or reviewed_manifest['version'] < 1):
            raise ValueError('Explicit reviewed sandbox manifest required')
        passport = ToolPassport(reviewed_manifest['approved_records'])
        if any(passport.check(record).status != 'allow'
               for record in reviewed_manifest['approved_records']):
            raise ValueError('Invalid reviewed sandbox manifest')
        evidence.require_key_for_startup()
        policy.ensure_default(str(ROOT / 'policies/default.yaml'))
        policy.ensure_security_rules(str(ROOT / 'policies/default.yaml'))
        audit.migrate_to_signer()
        # Reissue the supplied operator review in this new DB/signing stream.
        import hashlib
        with gateway._PIPELINE_LOCK:
            saved = json.dumps(reviewed_manifest, allow_nan=False)
            baseline_hash = hashlib.sha256(saved.encode()).hexdigest()
            if audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable review audit verification failed')
            db.set_setting('sandbox_tool_approvals', saved, 'disposable-story-review', 0)
            review = audit.record_decision('sandbox_tools_reviewed', {
                'by': 'disposable-story-review', 'version': reviewed_manifest['version'],
                'baseline_hash': baseline_hash, 'fingerprints': dict(passport.approved)},
                trusted_ts=time.time())
            if review['checkpoint_ok'] is not True or audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable review checkpoint unavailable')
            authority = audit.record_decision('sandbox_tools_authorized', {
                'by': 'disposable-story-review', 'review_event_id': review['event_id'],
                'baseline_hash': baseline_hash}, trusted_ts=time.time())
            if authority['checkpoint_ok'] is not True or audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable authority checkpoint unavailable')
            db.set_setting('sandbox_tool_authority', json.dumps({
                'event_id': authority['event_id'], 'baseline_hash': baseline_hash}),
                'disposable-story-review', 0)
        scenario = SCENARIOS[0]
        start = time.perf_counter()
        rid = gateway.create_run('enforce', 'sponsor-story', label='Disposable simulated S1')
        w = lumen_world.fresh()
        gateway.WORLDS[rid] = w
        documents = copy.deepcopy(w.state['documents'])
        session = gateway.start_session(rid, scenario['task'], 'sponsor-story')
        steps, bindings, api_ok = [], True, True
        for index, action in enumerate(scenario['actions']):
            before = len(audit.export_records())
            reply = gateway.handle_call(session['token'], action['tool'],
                                        copy.deepcopy(action['args']), f'S1-{index}')
            records = [r for r in audit.export_records()[before:] if r['event'] == 'decision']
            bindings &= len(records) == 1
            if len(records) == 1:
                stored = json.loads(records[0]['detail_json'])
                bindings &= (records[0]['run_id'] == rid
                             and records[0]['session_id'] == session['session_id']
                             and stored['verdict'] == reply['verdict']
                             and stored['reasons'] == reply['reasons'])
            rules = [r['rule'] for r in reply.get('reasons', [])]
            api_ok &= not reply.get('error') and 'HARD-ERROR' not in rules
            result = reply.get('result')
            api_ok &= not (isinstance(result, dict) and 'error' in result)
            steps.append({'tool': action['tool'], 'verdict': reply['verdict'], 'rules': rules})
        report = dict(scenario='S1', disclaimer=DISCLAIMER, steps=steps,
                      audit_ok=audit.verify()['ok'], decision_bindings_ok=bindings,
                      api_ok=bool(api_ok), documents_unchanged=w.state['documents'] == documents,
                      effects=len(w.sent) + len(w.refunds), seconds=time.perf_counter() - start)
        report['passed'] = story_passed(report)
        return report
    finally:
        signer.stdin.close()
        try:
            signer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            signer.kill()
            signer.wait()
        signer.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--reviewed-manifest', help='Explicit reviewed sandbox manifest JSON, not a path')
    args = parser.parse_args()
    try:
        manifest = (json.load(sys.stdin) if args.child else
                    json.loads(args.reviewed_manifest) if args.reviewed_manifest else None)
        report = _child(manifest) if args.child else run_story(manifest)
        print(json.dumps(report, indent=2))
        return 0 if args.child or report['passed'] else 1
    except Exception:
        print('Sponsor story failed; no acceptance claimed and no keys printed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
