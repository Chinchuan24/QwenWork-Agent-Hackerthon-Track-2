"""Isolated backend rehearsal. No user paths, reset deletion, or network calls."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


_VOLATILE = {'ts', 'created_at', 'hash', 'prev_hash', 'token'}


def normalize(value):
    """Remove identity/time metadata, never decisions, numbers or source text."""
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()
                if k not in _VOLATILE and k not in ('run_id', 'session_id')}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def reset():
    """Allocate only a newly generated directory. Old rehearsals stay intact."""
    return Path(tempfile.mkdtemp(prefix='twinguard-demo-')).resolve()


def _child(run, reviewed_manifest=None):
    # The dedicated child allocates its own state before any config import.
    root = reset()
    for key in list(os.environ):
        if key.startswith('AEGIS_'):
            del os.environ[key]
    os.environ.update(AEGIS_DATA_DIR=str(root / 'data'),
                     AEGIS_ANCHOR_EXTERNAL=str(root / 'external/anchor.json'),
                     AEGIS_SIGNER_STATE=str(root / 'signer'),
                     AEGIS_EVIDENCE_KEY=base64.urlsafe_b64encode(os.urandom(32)).decode())
    from . import config, signer_client
    manager = signer_client.SignerManager(config.AEGIS_SIGNER_STATE)
    config.AEGIS_SIGNER_PORT = manager.port
    try:
        from . import audit, db, evidence, gateway, policy, lumen_world
        db.init_db()
        from .tool_passport import ToolPassport
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
        policy.ensure_default(str(config.ROOT / 'policies/default.yaml'))
        policy.ensure_security_rules(str(config.ROOT / 'policies/default.yaml'))
        audit.migrate_to_signer()
        # Reissue the supplied operator review in this new DB/signing stream.
        with gateway._PIPELINE_LOCK:
            saved = json.dumps(reviewed_manifest, allow_nan=False)
            baseline_hash = hashlib.sha256(saved.encode()).hexdigest()
            if audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable review audit verification failed')
            db.set_setting('sandbox_tool_approvals', saved, 'disposable-demo-review', 0)
            review = audit.record_decision('sandbox_tools_reviewed', {
                'by': 'disposable-demo-review', 'version': reviewed_manifest['version'],
                'baseline_hash': baseline_hash, 'fingerprints': dict(passport.approved)},
                trusted_ts=time.time())
            if review['checkpoint_ok'] is not True or audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable review checkpoint unavailable')
            authority = audit.record_decision('sandbox_tools_authorized', {
                'by': 'disposable-demo-review', 'review_event_id': review['event_id'],
                'baseline_hash': baseline_hash}, trusted_ts=time.time())
            if authority['checkpoint_ok'] is not True or audit.verify()['ok'] is not True:
                raise RuntimeError('Disposable authority checkpoint unavailable')
            db.set_setting('sandbox_tool_authority', json.dumps({
                'event_id': authority['event_id'], 'baseline_hash': baseline_hash}),
                'disposable-demo-review', 0)
        initial = lumen_world.fresh().state
        digest = hashlib.sha256(json.dumps(initial, sort_keys=True).encode()).hexdigest()
        if not run:
            return {'world_digest': digest, 'audit_ok': audit.verify()['ok']}
        from .lumen_sponsor import SCENARIOS
        from .briefing import build_briefing
        rows = []
        bindings = []
        sent = 0
        start = time.time()
        timings = []
        for scenario in SCENARIOS:
            t0 = time.perf_counter()
            rid = gateway.create_run('enforce', 'demo', label='Synthetic stand-in rehearsal')
            gateway.WORLDS[rid] = lumen_world.fresh()
            session = gateway.start_session(rid, scenario['task'], 'demo')
            replies = []
            for index, action in enumerate(scenario['actions']):
                args = dict(action['args'])
                if action['tool'] == 'upload_file':
                    args['target'] = 'audience.example'
                before = len(audit.export_records())
                reply = gateway.handle_call(session['token'], action['tool'], args,
                                            f"{scenario['id']}-{index}")
                emitted = [r for r in audit.export_records()[before:] if r['event'] == 'decision']
                if len(emitted) != 1:
                    raise RuntimeError('Reply has no unique stored decision')
                stored = json.loads(emitted[0]['detail_json'])
                if stored['verdict'] != reply['verdict'] or stored['reasons'] != reply['reasons']:
                    raise RuntimeError('Reply differs from stored decision')
                bindings.append({'story': scenario['id'], 'step': index,
                                 'record_ref': emitted[0]['id'],
                                 'reply': {'verdict': reply['verdict'], 'reasons': reply['reasons']}})
                replies.append(reply)
            rules = sorted({r['rule'] for reply in replies for r in reply.get('reasons', [])})
            # Compare only receipt-emitted citations with the unchanged source world.
            sources = [source for reply in replies for reason in reply.get('reasons', [])
                       if isinstance(reason.get('evidence'), dict)
                       for source in reason['evidence'].get('sources', [])
                       if isinstance(source, dict)]
            documents = gateway.WORLDS[rid].state['documents']
            valid_sources = []
            for source in sources:
                path, line, text = (source.get(k) for k in ('source', 'line', 'text'))
                if isinstance(path, str) and path in documents and type(line) is int:
                    lines = documents[path]['body'].splitlines()
                    if 1 <= line <= len(lines) and text == lines[line - 1]:
                        valid_sources.append((path, text))
            final_decision = replies[-1]['verdict']
            # Approved prototype blocks scope creep; this email script does not
            # exercise order_supplier/R12 or prove the weekly-plan spend gate.
            expected = 'block' if scenario['id'] == 'S5' else scenario['decision'].lower()
            required_rules = ('R02', 'R01') if scenario['id'] == 'S5' else scenario['rules']
            required_evidence = (tuple(item for item in scenario['evidence']
                                       if item[0] != 'notes/2026-11-16_weekly_plan.md')
                                 if scenario['id'] == 'S5' else scenario['evidence'])
            contract = {
                'expected_decision': expected,
                'decision_match': final_decision == expected,
                'missing_rules': [rule for rule in required_rules if rule not in rules],
                'missing_sources': [{'source': path, 'fragment': fragment}
                                    for path, fragment in required_evidence
                                    if not any(p == path and fragment in text
                                               for p, text in valid_sources)],
                'strictness_difference': scenario['id'] == 'S5' and final_decision == 'block',
            }
            # Evidence here is actual gateway-emitted evidence, not expected citations.
            rows.append({'scenario': scenario['id'], 'decisions': [r['verdict'] for r in replies],
                          'decision_refs': [b['record_ref'] for b in bindings
                                            if b['story'] == scenario['id']],
                          'rules': rules, 'sponsor_contract': contract,
                          'evidence': [r.get('evidence') for reply in replies

                            for r in reply.get('reasons', []) if r.get('evidence') is not None]})
            sent += len(gateway.WORLDS[rid].sent)
            timings.append(time.perf_counter() - t0)
        # Number-free probes use the real gateway and unmodified guard code.
        for task in ('Prepare Greenstep marketing copy.', 'Prepare public marketing copy.'):
            rid = gateway.create_run('enforce', 'demo', label='Disagreement probe')
            gateway.WORLDS[rid] = lumen_world.fresh()
            session = gateway.start_session(rid, task, 'demo')
            gateway.handle_call(session['token'], 'send_email',
                                {'to': 'limwj@greenstep.example', 'subject': 'Hello',
                                 'body': 'Thank you for your patience.'}, 'neutral-probe')
            sent += len(gateway.WORLDS[rid].sent)
        records = audit.export_records()
        guards = [dict(json.loads(r['detail_json']), record_ref=r['id'])
                  for r in records if r['event'] == 'second_opinion']
        briefing = build_briefing(records, start=start, end=time.time() + 1)
        verified = audit.verify()
        references = {r['id']: f'record-{position}' for position, r in enumerate(records, 1)}
        opaque = {}
        for r in records:
            for field in ('run_id', 'session_id'):
                if r.get(field) and r[field] not in opaque:
                    opaque[r[field]] = f'{field}-{len(opaque) + 1}'
            d = json.loads(r['detail_json'])
            for field in ('approval', 'action', 'action_id', 'request_digest'):
                if d.get(field) and d[field] not in opaque:
                    opaque[d[field]] = f'{field}-at-{references[r["id"]]}'
        def bind(value, field=None):
            if isinstance(value, dict):
                return {k: bind(v, k) for k, v in value.items() if k not in _VOLATILE}
            if isinstance(value, list):
                bound = [bind(v, field) for v in value]
                return sorted(bound) if field == 'seen_approval_ids' else bound
            if field in ('proof_ids', 'decision_refs', 'id', 'record_ref', 'incident_record_id') and value is not None:
                if value not in references:
                    raise RuntimeError('Proof references missing record')
                return references[value]
            if isinstance(value, str):
                if value.startswith('/audit/record/'):
                    return 'audit:' + references[int(value.rsplit('/', 1)[1])]
                if value in opaque:
                    return opaque[value]
            return value
        projection = [{'record_ref': references[r['id']], 'event': r['event'],
                       'run_ref': opaque.get(r.get('run_id')),
                       'session_ref': opaque.get(r.get('session_id')),
                       'detail': bind(json.loads(r['detail_json']))} for r in records]
        return {'world_digest': digest, 'scenarios': bind(rows), 'sent': sent,
                'bindings': bind(bindings), 'record_projection': projection,
                'guards': bind(guards), 'disagreements': bind([g for g in guards if
                    g['a']['verdict'] == 'safe' and g['b']['verdict'] in ('unsafe', 'unsure')]),
                'briefing': bind(briefing), 'audit_ok': verified['ok'],
                'records': verified['records'], 'backend_scenario_seconds': timings}
    finally:
        manager.stop()


def _launch(run, reviewed_manifest=None):
    from . import gateway, db
    try:
        gateway._sandbox_tool_registry(remember_only=True)
        approved = json.loads(db.get_setting('sandbox_tool_approvals', 'null'))
        if reviewed_manifest != approved:
            raise ValueError('parent verified authority must match supplied review')
    except Exception as exc:
        raise RuntimeError('parent authority unavailable; rehearsal refused') from exc
    env = {k: v for k, v in os.environ.items() if not k.startswith('AEGIS_')}
    t0 = time.perf_counter()
    invocation = ('import json, sys; from aegis.demo_repeatability import _child; '
                  f'print(json.dumps(_child({run!r}, json.load(sys.stdin))))')
    proc = subprocess.run([sys.executable, '-c', invocation],
                          cwd=Path(__file__).resolve().parent.parent, env=env,
                          input=json.dumps(reviewed_manifest, allow_nan=False),
                          capture_output=True, text=True, timeout=45)
    if proc.returncode:
        raise RuntimeError('Isolated rehearsal failed; no real state was changed')
    return json.loads(proc.stdout), time.perf_counter() - t0


def measure(reviewed_manifest=None):
    resets = [_launch(False, reviewed_manifest)[0] for _ in range(10)]
    measured = [_launch(True, reviewed_manifest) for _ in range(5)]
    results = [r for r, _ in measured]
    comparable = [{k: v for k, v in r.items() if k != 'backend_scenario_seconds'} for r in results]
    return {'mode': 'scripted stand-in', 'live': 'ready for key; not run',
            'resets': 10, 'runs': 5,
            'reset_identical': all(r == resets[0] for r in resets),
            'results_identical': all(r == comparable[0] for r in comparable),
            'results': results, 'backend_seconds': [s for _, s in measured],
            'browser_shot_seconds': None, 'planned_script_seconds': 165}


if __name__ == '__main__':
    if not sys.argv[1:]:
        print(json.dumps(measure(), indent=2))
    else:
        raise SystemExit('No user paths accepted')
