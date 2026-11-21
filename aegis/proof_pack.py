"""C4 masked local proof exports. No routes, key storage or external effects."""
import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import audit, auth, db, evidence, rule_match as rule_catalog

_CONTEXTS = {}
_CONTEXT_LOCK = threading.Lock()
_CONTEXT_TTL = 300
_MASK = '[masked]'
_TOOLS = {'read_file', 'search_files', 'list_files', 'send_email', 'refund',
          'delete_file', 'upload', 'upload_file', 'pay_supplier', 'order_supplier',
          'accept_terms', 'fetch_url', 'lookup_contact', 'share_file', 'update_record',
          'issue_refund', 'list_inbox', 'read_email', 'find_contact', 'get_client', 'fetch_web'}
_VERDICTS = {'allow', 'hold', 'block', 'safe', 'unsafe', 'unsure', 'error', 'timeout'}
_STATUSES = {'pending', 'held', 'blocked', 'executed', 'approved', 'rejected', 'expired', 'claimed', 'denied', 'changed', 'void'}
_MODES = {'scripted', 'stand-in', 'live', 'error', 'enforce', 'monitor', 'off'}
_SOURCES = {'PDPA', 'IMDA agent framework', 'CSA agent guide', 'OWASP agent list'}
_EVENTS = {'decision', 'second_opinion', 'approved_action_executed', 'approval_requested',
           'approval_decided', 'approval_denied', 'approval_changed', 'approval_void', 'approval_expired', 'session_started', 'session_frozen', 'session_exposed',
           'policy_activated', 'card_changed', 'proof_pack_exported', 'call_rejected',
            'pipeline_error', 'redaction', 'run_created', 'helper_frozen', 'helper_released',
             'sandbox_tools_reviewed', 'sandbox_tools_authorized'}


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _label(value, choices):
    return value if isinstance(value, str) and value in choices else 'not recorded'


def _private_ref(value, key):
    # References are stable only within one export; the key never leaves memory.
    if value is None:
        return 'not recorded'
    return 'ref:' + hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()


def _number(value):
    return value if type(value) is int and value >= 0 else None


def _rules(value):
    out = []
    if isinstance(value, list):
        for item in value:
            rule = item.get('rule') if isinstance(item, dict) else item
            if isinstance(rule, str) and re.fullmatch(r'(?:R\d{2}|ASI\d{2}|(?:HARD|GATE|R)-[A-Z0-9-]{1,40})', rule):
                out.append(rule)
    return sorted(set(out))


def _decode(value):
    try:
        decoded = evidence.dec_json(value)
        return decoded if isinstance(decoded, (dict, list)) else {}
    except Exception:
        return {'unreadable': True}


def _guard(value):
    value = value if isinstance(value, dict) else {}
    return {'verdict': _label(value.get('verdict'), _VERDICTS),
            'mode': _label(value.get('mode'), _MODES),
            'reason': _MASK if value.get('reason') else 'not recorded'}


def verify_export_context(token, csrf, password):
    """Verify a live human session, CSRF, role and password; issue one-use capability.

    Call only from a trusted human boundary. Never pass agent-controlled tokens
    or password fields from content into this function.
    """
    user = auth.user_by_token(token) if isinstance(token, str) else None
    if (not auth.require_role(user, 'admin', 'auditor') or user.get('must_change')
            or not isinstance(csrf, str) or not auth.check_csrf(user, csrf)
            or not isinstance(password, str) or auth._throttled(user['username'])):
        raise PermissionError('Export requires a permitted human session and fresh verification')
    if not auth._verify_pw(password, bytes.fromhex(user['salt']), user['pw_hash']):
        auth._login_fails.setdefault(user['username'], []).append(time.time())
        raise PermissionError('Re-authentication failed')
    capability = secrets.token_urlsafe(32)
    now = time.time()
    with _CONTEXT_LOCK:
        for old in list(_CONTEXTS):
            if _CONTEXTS[old]['expires'] < now:
                del _CONTEXTS[old]
        _CONTEXTS[capability] = {'token': token, 'user_id': user['id'],
                                 'expires': now + _CONTEXT_TTL,
                                 'pw_hash': user['pw_hash']}
    return capability


def _consume_context(context):
    with _CONTEXT_LOCK:
        ctx = _CONTEXTS.pop(context, None) if isinstance(context, str) else None
    if not ctx or time.time() > ctx['expires']:
        raise PermissionError('Missing, expired or used export verification')
    user = auth.user_by_token(ctx['token'])
    if (not auth.require_role(user, 'admin', 'auditor') or user.get('must_change')
            or user['id'] != ctx['user_id'] or user['pw_hash'] != ctx['pw_hash']):
        raise PermissionError('Export session or role changed')
    return user


def _integrity():
    try:
        result = audit.verify()
    except Exception as exc:
        result = {'ok': False, 'problems': ['Verifier could not read the record'],
                  'error_type': type(exc).__name__}
    # Keep actual verifier findings without copying arbitrary paths/error text.
    findings = []
    for problem in result.get('problems', []):
        text = str(problem)
        category = next((name for name in ('signer', 'checkpoint', 'external anchor',
            'fingerprint', 'chain link', 'rolled back') if name in text.lower()), 'record check')
        findings.append({'check': category, 'result': 'failed',
                         'record_numbers': [int(n) for n in re.findall(r'\b\d{1,12}\b', text)]})
    audit_result = {k: result[k] for k in ('ok', 'records', 'checkpoints', 'last_hash') if k in result}
    audit_result['problems'] = findings
    if 'error_type' in result:
        audit_result['error_type'] = result['error_type']
    signer = {'checked': False, 'ok': False, 'status': 'unavailable'}
    try:
        latest = audit._signer_request({'op': 'latest', 'stream': audit._stream_id()})
        rows = db.conn().execute('SELECT id,hash FROM audit ORDER BY id').fetchall()
        body = latest.get('body') or {}
        count = body.get('count')
        if latest.get('seq', 0) > 0 and type(count) is int and 0 < count <= len(rows):
            row = rows[count-1]
            checked = audit._signer_request({'op': 'verify_line', 'stream': audit._stream_id(),
                'line': {'body': body, 'seq': latest['seq'], 'sig': latest['sig']}})
            ok = bool(checked.get('ok')) and count == len(rows) and row['id'] == body.get('max_id') and row['hash'] == body.get('last_hash')
        else:
            ok = not rows and latest.get('seq') == 0
        signer = {'checked': True, 'ok': ok, 'status': 'matches' if ok else 'mismatch or missing',
                  'sequence': _number(latest.get('seq')), 'remembered_records': _number(count)}
    except Exception:
        pass
    return {'audit': audit_result, 'signer': signer,
            'ok': result.get('ok') is True and signer['ok']}


def _tool_passport_inventory(_ref):
    from . import gateway
    from .tool_passport import NOTICE

    try:
        # Dispatch takes pipeline before audit; never reverse that lock order.
        with gateway._PIPELINE_LOCK:
            snapshot = gateway._sandbox_tool_registry().proof_rows()
        rows = []
        for row in snapshot:
            hashes = {}
            for field in ('candidate_sha256', 'approved_sha256'):
                value = row.get(field)
                hashes[field] = value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) else None
            rows.append({'name': _ref(row.get('name')), **hashes,
                'status': _label(row.get('status'), {'allow', 'hold', 'block'}),
                'reason': _label(row.get('reason'), {'approved_manifest', 'manifest_changed',
                    'missing_tool', 'unknown_tool', 'invalid_manifest', 'description_injection'}),
                'scope': 'sandbox-only', 'gateway_enforced': False, 'notice': NOTICE})
        return {'status': 'available', 'rows': rows}
    except Exception:
        return {'status': 'unavailable', 'rows': []}


def build_proof_pack(start, end, *, context, signing_key, rule_match=None, card_versions=()):
    """Return sealed JSON bytes for inclusive UTC epoch-second bounds.

    Supplied C3/C5 metadata is projected, never trusted as a permission or a
    completed check. Unknown free text is omitted. Missing evidence stays visible.
    The integrator supplies a dedicated Ed25519 key, not the audit/evidence key.
    """
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (start, end)) or start > end:
        raise ValueError('Date range requires finite ordered UTC epoch seconds')
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise ValueError('A dedicated Ed25519 signing key is required')
    user = _consume_context(context)
    reference_key = secrets.token_bytes(32)
    def _ref(value):
        return _private_ref(value, reference_key)
    inventory = _tool_passport_inventory(_ref)
    # Same lock as audit append/verify. Snapshot all DB sources together; release
    # the read transaction before appending the export receipt.
    with audit._LOCK:
        c = db.conn()
        if c.in_transaction:
            raise RuntimeError('Export requires a clean database transaction')
        c.execute('BEGIN')
        try:
            integrity = _integrity()
            timeline = []
            approval_rows = {r['id']: r for r in c.execute('SELECT * FROM approvals')}
            linked_approvals, linked_actions = set(), set()
            for row in c.execute('SELECT * FROM audit WHERE ts>=? AND ts<=? ORDER BY ts,id', (start, end)):
                d = _decode(row['detail_json'])
                d = d if isinstance(d, dict) else {}
                approval_id = d.get('approval_id', d.get('approval'))
                approval_row = approval_rows.get(approval_id) if isinstance(approval_id, str) else None
                action_id = d.get('action_id', d.get('action'))
                if action_id is None and approval_row is not None:
                    action_id = approval_row['action_id']
                if isinstance(approval_id, str):
                    linked_approvals.add(approval_id)
                if isinstance(action_id, str):
                    linked_actions.add(action_id)
                timeline.append({'record_id': row['id'], 'time': row['ts'],
                    'approval': _ref(approval_id),
                    'decision': _label(d.get('decision'), {'approve', 'reject', 'change'}),
                    'requested_action': _ref(d.get('requested_action')),
                    'event': _label(row['event'], _EVENTS), 'session': _ref(row['session_id']),
                    'action': _ref(action_id),
                    'review_event': _ref(d.get('review_event_id')),
                    'baseline': _ref(d.get('baseline_hash')),
                    'helper': _ref(d.get('helper_id', row['session_id'])),
                    'tool': _label(d.get('tool'), _TOOLS), 'verdict': _label(d.get('verdict', d.get('outcome')), _VERDICTS),
                    'rules': _rules(d.get('reasons', d.get('rules', []))),
                    'guards': {'aegis': _guard(d.get('aegis', d.get('a'))),
                               'delta': _guard(d.get('delta', d.get('b')))},
                    'policy_version': _number(d.get('policy_version')),
                    'card_version': _number(d.get('card_version')),
                    'content': _MASK, 'unreadable': bool(d.get('unreadable'))})
            selected_approvals = [r for r in approval_rows.values()
                if r['id'] in linked_approvals or start <= r['requested_at'] <= end
                or (r['decided_at'] is not None and start <= r['decided_at'] <= end)]
            linked_actions.update(r['action_id'] for r in selected_approvals)
            actions = []
            for r in c.execute('SELECT * FROM actions ORDER BY created_at,id'):
                in_range = start <= r['created_at'] <= end or (r['executed_at'] is not None and start <= r['executed_at'] <= end)
                if not in_range and r['id'] not in linked_actions:
                    continue
                actions.append({'action': _ref(r['id']), 'helper': _ref(r['session_id']),
                    'time': r['created_at'], 'executed_at': r['executed_at'],
                    'range_scope': 'in range' if in_range else 'out-of-range dependency',
                    'tool': _label(r['tool'], _TOOLS), 'verdict': _label(r['verdict'], _VERDICTS),
                    'status': _label(r['status'], _STATUSES), 'rules': _rules(_decode(r['reasons_json'])), 'content': _MASK})
            approvals = []
            for r in sorted(selected_approvals, key=lambda r: (r['decided_at'] if r['decided_at'] is not None else r['requested_at'], r['id'])):
                in_range = start <= r['requested_at'] <= end or (r['decided_at'] is not None and start <= r['decided_at'] <= end)
                approvals.append({'approval': _ref(r['id']), 'action': _ref(r['action_id']),
                    'who': _ref(r['decided_by']), 'requested_at': r['requested_at'],
                    'range_scope': 'in range' if in_range else 'out-of-range dependency',
                    'decided_at': r['decided_at'], 'status': _label(r['status'], _STATUSES),
                    'fingerprint': _ref(r['fingerprint']), 'content': _MASK})
            policies = [{'version': r['version'], 'activated_at': r['ts'], 'by': _ref(r['activated_by']), 'content': _MASK}
                for r in c.execute('SELECT * FROM policy_versions WHERE ts<=? AND (ts>=? OR version=(SELECT version FROM policy_versions WHERE ts<=? ORDER BY ts DESC,version DESC LIMIT 1)) ORDER BY ts,version', (end, start, start))]
        finally:
            c.rollback()
        cards = [{'version': _number(r.get('version')), 'helper': _ref(r.get('helper_id')), 'content': _MASK}
                 for r in card_versions if isinstance(r, dict)]
        # Only reviewed catalog text is public. Caller text is never made public
        # merely because it names a known source or claims source verification.
        catalog = rule_catalog.rule_match_table()
        matches = []
        for r in catalog if rule_match is None else rule_match:
            if not isinstance(r, dict):
                continue
            reviewed = next((row for row in catalog
                if row['source'] == r.get('source') and row['number'] == r.get('number')
                and row['heading'] == r.get('heading')), None)
            unverified = (r.get('status') == 'not verified'
                          or r.get('source_verified') is False
                          or any(row['source'] == r.get('source') and not row['source_verified']
                                 for row in catalog))
            status = 'not verified' if unverified else 'not covered'
            if reviewed is not None:
                row = dict(reviewed)
                row.update(status=status, proof=[], source_verified=not unverified)
                matches.append(row)
            else:
                matches.append({'source': _label(r.get('source'), _SOURCES),
                    'status': status,
                    'requirement': _ref(r.get('number', r.get('heading'))),
                    'proof': _ref(r.get('proof')), 'summary': _MASK})
        payload = {'format': 'aegis-proof-pack-v1',
            'warning': '' if integrity['ok'] else 'FAILED: THE RECORD CHECK DID NOT PASS. Do not rely on this history as unchanged.',
            'summary': f"The range contains {len(actions)} stored actions, {len(approvals)} approval records and {len(timeline)} diary entries. Private content is hidden.",
            'range': {'start': start, 'end': end, 'timezone': 'UTC', 'edges': 'inclusive'},
            'created_at': time.time(), 'exporter': _ref(user['id']), 'integrity': integrity,
            'timeline': timeline, 'actions': actions, 'approvals': approvals,
            'tool_passport_inventory': inventory,
            'policy_versions': policies, 'card_versions': cards, 'rule_match': matches,
            'rule_match_notice': 'This table shows how Aegis helps you meet rules. It is not legal advice or a certification.',
            'limitations': ['Names and free text are masked; opaque references join records within this export only.',
                'Out-of-range dependencies include stored approvals and actions needed to resolve in-range receipt links; diary bounds remain unchanged.',
                'Missing guard answers and version bindings mean not recorded, not a successful check.',
                'Card and rule-match inputs are supplied metadata, not independently verified.',
                'A seal detects changes only when checked with a separately trusted public key.']}
        public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        signed = {'payload': payload, 'algorithm': 'Ed25519', 'key_id': hashlib.sha256(public).hexdigest()}
        signature = base64.b64encode(signing_key.sign(_canonical(signed))).decode('ascii')
        artifact = _canonical({**signed, 'signature': signature})
        audit.record('proof_pack_exported', {'by': user['username'], 'start': start, 'end': end,
            'artifact_sha256': hashlib.sha256(artifact).hexdigest(), 'integrity_ok': integrity['ok']})
        return artifact


def verify_seal(artifact, trusted_public_key):
    """Check against an OUT-OF-BAND trusted key, never a key from the artifact."""
    if not isinstance(trusted_public_key, Ed25519PublicKey):
        return False
    try:
        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError('Duplicate key')
                obj[key] = value
            return obj
        obj = json.loads(artifact, object_pairs_hook=unique)
        if set(obj) != {'payload', 'algorithm', 'key_id', 'signature'} or obj['algorithm'] != 'Ed25519':
            return False
        public = trusted_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if obj['key_id'] != hashlib.sha256(public).hexdigest():
            return False
        sig = base64.b64decode(obj.pop('signature'), validate=True)
        trusted_public_key.verify(sig, _canonical(obj))
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, RecursionError):
        return False
