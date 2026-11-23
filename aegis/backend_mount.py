"""Fake-world mounting API. Identity arguments must come from authenticated ingress."""
import asyncio
from copy import deepcopy
import hashlib
import json
import time

from .real_backend import RealBackend
from .live_product import LiveProduct, TestModel, Unavailable, QuotaModel

# Explicit reviewed definitions, never built from discovered tool definitions.
REVIEWED_MANIFESTS = [
    {'name': 'read_file', 'description': 'Read a document by id', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}}, 'required': ['doc_id']}},
    {'name': 'write_file', 'description': 'write_file', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}, 'body': {'type': 'string'}}, 'required': ['doc_id', 'body']}},
    {'name': 'delete_file', 'description': 'delete_file', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}}, 'required': ['doc_id']}},
    {'name': 'upload_file', 'description': 'upload_file', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}, 'target': {'type': 'string'}}, 'required': ['doc_id', 'target']}},
    {'name': 'send_email', 'description': 'Send an email. attachment_ids is a list of document ids.', 'input_schema': {'type': 'object', 'properties': {'to': {'type': 'string'}, 'subject': {'type': 'string'}, 'body': {'type': 'string'}, 'attachment_ids': {'type': 'array', 'items': {'type': 'string'}}, 'regarding_email': {'type': 'string'}}, 'required': ['to', 'subject', 'body']}},
]


def configure_runtime(audit, db, evidence, gateway, req):
    if req['op'] == 'review':
        reviewer = req['reviewer']
        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ValueError('Trusted reviewer required')
        saved = json.dumps({'version': 1, 'approved_records': REVIEWED_MANIFESTS}, sort_keys=True)
        digest = hashlib.sha256(saved.encode()).hexdigest()
        review = audit.record_decision('sandbox_tools_reviewed', {'baseline_hash': digest, 'by': reviewer}, trusted_ts=time.time())
        receipt = audit.record_decision('sandbox_tools_authorized', {'baseline_hash': digest, 'review_event_id': review['event_id'], 'by': reviewer}, trusted_ts=time.time())
        if not review['checkpoint_ok'] or not receipt['checkpoint_ok'] or not audit.verify()['ok']:
            raise ValueError('Review checkpoint required')
        db.set_setting('sandbox_tool_approvals', saved, reviewer, 0)
        db.set_setting('sandbox_tool_authority', json.dumps({'event_id': receipt['event_id'], 'baseline_hash': digest}), reviewer, 0)
        return gateway.tool_schemas()
    sess = gateway.session_by_token(req['token'])
    if not sess:
        raise PermissionError('Session required')
    if req['op'] == 'sealed_decisions':
        # Count original checkpoint-verified receipts, not presentation actions.
        with audit.publication_lock():
            if not audit.verify()['ok']:
                return {'sealed_decisions': None, 'sealed_links': None}
            rows = db.conn().execute(
                "SELECT detail_json, hash FROM audit WHERE session_id=? AND run_id=? "
                "AND event='decision' ORDER BY id LIMIT 257",
                (sess['id'], sess['run_id'])).fetchall()
            if len(rows) > 256:
                return {'sealed_decisions': None, 'sealed_links': None}
            sealed = set()
            links = []
            for row in rows:
                detail = evidence.dec_json(row['detail_json'])
                if (detail.get('stage') != 'final' or
                        detail.get('verdict') not in ('allow', 'hold', 'block') or
                        any(r.get('rule') == 'GATE-IDEM' for r in detail.get('reasons', []))):
                    continue
                action = db.conn().execute(
                    'SELECT id, tool, args_json FROM actions WHERE id=? AND session_id=?',
                    (detail.get('action_id'), sess['id'])).fetchone()
                if (action and detail.get('tool') == action['tool'] and
                        detail.get('args') == evidence.dec_json(action['args_json'])):
                    if action['id'] not in sealed:
                        sealed.add(action['id'])
                        links.append({'action_id': action['id'], 'hash': row['hash']})
            return {'sealed_decisions': len(sealed), 'sealed_links': links}
    if req['op'] == 'snapshot':
        return {path: {'title': doc['title']} for path, doc in gateway.get_world(sess['run_id']).state['documents'].items()}
    if req['op'] == 'action_explanations':
        if req.get('test_read_assessment'):
            from .real_runtime import qwen_client
            row = db.conn().execute('SELECT tool, args_json FROM actions WHERE id=? AND session_id=?',
                                    (req['action_id'], sess['id'])).fetchone()
            if not row or row['tool'] != 'read_file':
                raise PermissionError('Read action session required')
            args = evidence.dec_json(row['args_json'])
            w = gateway.get_world(sess['run_id'])
            payload = {'task': sess['task_text'], 'tool': row['tool'], 'args': args,
                       '_identity': gateway._RUN_IDENTITIES[sess['run_id']],
                       'office': gateway._office_evidence(sess, row['tool'], args, w),
                       'confidential_reads': gateway._confidential_reads(sess['id'])}
            answers = [qwen_client.judge(kind, deepcopy(payload)) for kind in ('safety_a', 'safety_b')]
            receipt = audit.record_decision('test_model_read_assessment',
                {'action_id': req['action_id'], 'payload': payload, 'answers': answers,
                 'supplemental': True}, trusted_ts=time.time(), session_id=sess['id'], run_id=sess['run_id'])
            if not receipt['checkpoint_ok']:
                raise ValueError('Assessment checkpoint required')
            return answers
        row = db.conn().execute('SELECT reasons_json FROM actions WHERE id=? AND session_id=?',
                                (req['action_id'], sess['id'])).fetchone()
        if not row:
            raise PermissionError('Action session mismatch')
        reasons = evidence.dec_json(row['reasons_json']) if row['reasons_json'] else []
        return [{'rule': str(r.get('rule', ''))[:160], 'reason': str(r.get('reason', ''))[:2000]}
                for r in reasons[:32] if isinstance(r, dict)]
    if req['op'] == 'card':
        if sess['created_by'] != req['owner']:
            raise PermissionError('Task owner required')
        card = {'helper_id': sess['id'], 'created_by': req['owner'], 'tools': [r['name'] for r in REVIEWED_MANIFESTS], 'read_folders': [''], 'read_sensitivity': ['public', 'internal', 'confidential', 'client-confidential', 'regulated'], 'expiry': time.time() + 3600, 'frozen': False}
        db.conn().execute('UPDATE helper_cards SET content=?, version=version+1 WHERE helper_id=?', (evidence.enc_json(card), sess['id']))
        db.conn().commit()
        receipt = audit.record_decision('helper_card_authorized', card, trusted_ts=time.time(), session_id=sess['id'], run_id=sess['run_id'])
        if not receipt['checkpoint_ok']:
            gateway.freeze_session(sess['id'], 'card checkpoint unavailable')
            raise ValueError('Card checkpoint required')
        return card
    from .real_runtime import approvals
    ap = approvals.get(req['approval_id'])
    action = db.conn().execute('SELECT session_id FROM actions WHERE id=?', (ap['action_id'],)).fetchone() if ap else None
    if not action or action['session_id'] != sess['id']:
        raise PermissionError('Approval session mismatch')
    return approvals.decide(req['approval_id'], req['user'], req['decision'], reason=req.get('reason'))


class MountedLiveProduct(LiveProduct):
    """LiveProduct UI contract backed by the unchanged original gateway."""
    def __init__(self, mixed, root, transport=None, *, reviewer):
        super().__init__(mixed, root, transport)
        self.identity = None
        self.action_context = None
        self.judge_trace = None
        self.backend = RealBackend(root, self._judge)
        try:
            self.tools = self.backend.request('review', reviewer=reviewer)
            if {t['function']['name'] for t in self.tools} != {r['name'] for r in REVIEWED_MANIFESTS}:
                raise ValueError('Exact reviewed catalog required')
        except BaseException:
            self.backend.close()
            raise

    def _judge(self, kind, payload):
        visitor, address = self.identity
        result = self.model.call(visitor, address, {'kind': kind, 'original_payload': payload}, self.action_context)
        if self.judge_trace is not None and kind in ('intent', 'leak', 'safety_a', 'safety_b') and isinstance(result, dict):
            self.judge_trace.append({'kind': kind, 'verdict': result.get('verdict'),
                                     'reason': str(result.get('reason', ''))[:2000],
                                     'source': 'captured response'})
        return result

    async def start_task(self, visitor, address, task):
        state = await super().start_task(visitor, address, task)
        with self.lock:
            self.identity = (visitor, address)
            self.action_context = self.mixed.admit_action(visitor, address, startup=True)
            try:
                session = self.backend.request('start', owner=visitor, task=self.sessions[state['id']]['task'])
            finally:
                if self.action_context:
                    self.mixed.close_action(self.action_context)
                self.action_context = None
            self.backend.request('card', token=session['token'], owner=visitor)
            self.sessions[state['id']]['backend_session'] = session
            if session.get('request_failed'):
                self.sessions[state['id']].update(mode='Recorded run', done=True,
                    recorded_trace=self._recorded(task))
        return self.status(visitor, state['id'])

    async def advance(self, visitor, sid):
        # Serialize identity context with the complete original pipeline.
        with self.lock:
            s = self._session(visitor, sid)
            if s['busy'] or s['pending'] or s['done']:
                return self.status(visitor, sid)
            s['busy'] = True
            try:
                self.identity = (visitor, s['address'])
                self.action_context = self.mixed.admit_action(visitor, s['address'])
                if not self.action_context:
                    raise Unavailable()
                token = s['backend_session']['token']
                action = self.model.call(visitor, s['address'], {'kind': 'helper', 'task_id': s['task_id'], 'task': s['task'], 'actions': s['actions'], 'tools': self.tools, 'files': self.backend.request('snapshot', token=token)}, self.action_context)
                if action == {'done': True} or len(s['actions']) >= 8:
                    s['done'] = True
                else:
                    if not self.mixed.enabled(visitor):
                        raise Unavailable()
                    self.judge_trace = []
                    try:
                        result = self.backend.request('call', token=token, tool=action.get('tool'), args=action.get('args'), idem_key=__import__('secrets').token_hex(16))
                        # Supplemental quota-backed mock evidence does not alter enforcement.
                        if (self.test_model and isinstance(self.model, QuotaModel)
                                and isinstance(self.model.transport, TestModel)
                                and self.mixed.key == 'sk-test-FAKE-0000000000000000'
                                and action.get('tool') == 'read_file' and result.get('action_id')
                                and not result.get('request_failed')):
                            self.backend.request('action_explanations', token=token,
                                action_id=result['action_id'], test_read_assessment=True)
                        result['judges'] = deepcopy(self.judge_trace)
                    finally:
                        self.judge_trace = None
                    if result.get('action_id'):
                        result['explanations'] = self.backend.request('action_explanations', token=token, action_id=result['action_id'])
                    result['id'] = result.get('action_id')
                    result['tool'] = action.get('tool')
                    result['args'] = deepcopy(action.get('args'))
                    s['actions'].append(result)
                    s['pending'] = result.get('approval_id') if result['verdict'] == 'hold' else None
                    if result.get('request_failed'):
                        raise Unavailable()
            except Unavailable:
                s.update(mode='Recorded run', done=True, pending=None,
                         recorded_trace=self._recorded(s['task_id']))
            finally:
                if self.action_context:
                    self.mixed.close_action(self.action_context)
                self.action_context = None
                s['busy'] = False
            return self.status(visitor, sid)

    async def approval(self, visitor, sid, action_id, approved, *, reviewer=None, reason=None):
        with self.lock:
            s = self._session(visitor, sid)
            if type(approved) is not bool or action_id != s['pending'] or not action_id or reviewer is None:
                raise ValueError('Held action and authenticated reviewer required')
            if not self.mixed.enabled(visitor) or not self.mixed.key:
                raise ValueError('Approval unavailable')
            self.identity = (visitor, s['address'])
            self.action_context = self.mixed.admit_action(visitor, s['address']) if approved else None
            if approved and not self.action_context:
                raise ValueError('Approval action limit reached')
            self.judge_trace = []
            try:
                result = self.backend.request('approval', token=s['backend_session']['token'], approval_id=action_id, user=reviewer, decision='approve' if approved else 'deny', reason=reason)
                rechecks = deepcopy(self.judge_trace)
            finally:
                self.judge_trace = None
                if self.action_context:
                    self.mixed.close_action(self.action_context)
                self.action_context = None
            if result.get('request_failed'):
                s.update(mode='Recorded run', done=True, pending=None,
                         recorded_trace=self._recorded(s['task_id']))
                return self.status(visitor, sid)
            if not result['ok']:
                if 'approval void' in result.get('error', ''):
                    s['pending'] = None
                    s['actions'][-1]['status'] = 'blocked'
                raise ValueError(result['error'])
            s['actions'][-1].update(result)
            s['actions'][-1]['approval_judges'] = rechecks
            s['pending'] = None
            return self.status(visitor, sid)

    def status(self, visitor, sid):
        state = super().status(visitor, sid)
        s = self._session(visitor, sid)
        if 'backend_session' in s:
            state['files'] = sorted(self.backend.request('snapshot', token=s['backend_session']['token']))
        state['backend'] = 'original gateway / fictional World'
        state['sealed_decisions'] = None
        state['sealed_links'] = None
        if 'backend_session' in s:
            state.update(self.backend.request('sealed_decisions', token=s['backend_session']['token']))
        return state

    def verify(self, visitor, sid, tamper=False):
        with self.lock:
            self._session(visitor, sid)
            if tamper:
                raise ValueError('Use an isolated copied durable store for tamper tests')
            return self.backend.request('verify')

    def close(self):
        self.backend.close()


def mount_live_product(mixed, root, transport=None, *, reviewer):
    return MountedLiveProduct(mixed, root, transport, reviewer=reviewer)

def install_sandbox_hooks(gateway):
    """Worker-local extension; original gateway remains the only dispatcher."""
    import re
    from .live_product import SEED
    from .real_runtime.world import World

    class LumenWorld(World):
        def __init__(self):
            super().__init__()
            self.state['firm'] = {'name': 'Lumen', 'domain': 'lumen.example'}
            self.state['documents'] = {
                path: {'title': path, 'owner': 'acme' if path == 'acme.txt' else 'firm',
                       'sensitivity': item['level'], 'body': item['body']}
                for path, item in SEED.items()}
            self.state['inbox'] = []
            self.state['web'] = {}
            self.state['ledger'] = {'MARCH-001': {'client': 'acme', 'amount': 8000,
                'payee': 'Acme Industries', 'status': 'paid'}}
            self.state['owner_floors'] = {}

        def office_action(self, tool, args):
            if tool == 'write_file':
                if args['doc_id'] in self.state['documents']:
                    return {'error': 'sandbox drafts never overwrite existing documents'}
                self.state['documents'][args['doc_id']] = {
                    'title': args['doc_id'], 'owner': 'firm',
                    'sensitivity': 'internal', 'body': args['body']}
                return {'written': True, 'doc_id': args['doc_id']}
            return super().office_action(tool, args)

    original_validate = gateway._validate_args
    def validate(tool, args):
        error = original_validate(tool, args)
        if error:
            return error
        if tool == 'write_file' and (not re.fullmatch(r'[a-zA-Z0-9_-]+\.txt', args['doc_id']) or args['doc_id'] in SEED):
            return 'sandbox new draft id required'
        return ''
    gateway.world.World = LumenWorld
    gateway.TOOL_SCHEMAS['write_file'] = {'doc_id': str, 'body': str}
    gateway.REQUIRED['write_file'] = ['doc_id', 'body']
    gateway.FREE_TEXT['write_file'] = ['body']
    gateway.SIDE_EFFECT.add('write_file')
    gateway.OFFICE_EFFECT.add('write_file')
    gateway._validate_args = validate
