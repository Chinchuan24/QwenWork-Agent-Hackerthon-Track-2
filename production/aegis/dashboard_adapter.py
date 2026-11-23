"""HTTP presentation boundary for the original fictional-world gateway."""
import asyncio
from copy import deepcopy
import json
import secrets
import threading

from .backend_mount import MountedLiveProduct
from .live_product import LiveProduct, TestModel

FAKE_KEY = 'sk-test-FAKE-0000000000000000'


class OriginalProduct(MountedLiveProduct):
    async def start_task(self, visitor, address, task):
        # The authenticated human is not the helper that requests the action.
        state = await LiveProduct.start_task(self, visitor, address, task)
        with self.lock:
            self.identity = (visitor, address)
            owner = 'system-helper-' + secrets.token_hex(16)
            self.action_context = self.mixed.admit_action(visitor, address, startup=True)
            try:
                session = self.backend.request('start', owner=owner, task=self.sessions[state['id']]['task'])
            finally:
                if self.action_context:
                    self.mixed.close_action(self.action_context)
                self.action_context = None
            self.backend.request('card', token=session['token'], owner=owner)
            self.sessions[state['id']]['backend_session'] = session
        return self.status(visitor, state['id'])


class RecordedAccess:
    key = FAKE_KEY

    def enabled(self, visitor):
        return True

    def admit_action(self, visitor, address, *, startup=False):
        return 'recorded-local'

    def close_action(self, context):
        pass


class DashboardTestModel(TestModel):
    def __call__(self, payload):
        context = json.loads(payload['messages'][1]['content'])
        if context['kind'] in ('safety_a', 'safety_b') and context.get('original_payload', {}).get('tool') == 'read_file':
            self.calls.append(deepcopy(payload))
            result = {'verdict': self.guard, 'reason':
                      'Reading is part of task.' if context['kind'] == 'safety_a' else 'Nothing leaves sandbox.'}
            return {'usage': {'prompt_tokens': 10, 'completion_tokens': 2},
                    'choices': [{'message': {'content': json.dumps(result)}}]}
        if context['kind'] == 'helper':
            step = len(context['actions'])
            plans = {
                'invoices': [('read_file', {'doc_id': 'march.txt'}), ('delete_file', {'doc_id': 'march-duplicate.txt'})],
                'partners': [('read_file', {'doc_id': 'clients.txt'}), ('upload_file', {'doc_id': 'clients.txt', 'target': 'partner.example'})],
                'contract': [('read_file', {'doc_id': 'acme.txt'}), ('write_file', {'doc_id': 'draft.txt', 'body': 'Acme contract price SGD 8000.'})],
            }
            action = dict(zip(('tool', 'args'), plans[context['task_id']][step])) if step < 2 else {'done': True}
            self.calls.append(deepcopy(payload))
            return {'usage': {'prompt_tokens': 10, 'completion_tokens': 2},
                    'choices': [{'message': {'content': json.dumps(action)}}]}
        return super().__call__(payload)


class LocalModel:
    """Recorded mock computations, without provider calls or quota reservations."""
    def __init__(self):
        self.transport = TestModel()

    def call(self, visitor, address, context, action_context=None):
        payload = {'messages': [{}, {'content': json.dumps(context)}]}
        return json.loads(self.transport(payload)['choices'][0]['message']['content'])


def normalize(state):
    result = deepcopy(state)
    result.setdefault('sealed_decisions', None)
    result.setdefault('sealed_links', None)
    if result.get('mode') == 'Test model':
        result['mode'] = 'Recorded run/test model'
    for action in result.get('actions', []):
        # The original gateway may skip judges on a decisive deterministic rule.
        # Do not invent two safe answers to fill dashboard cards.
        action.setdefault('judges', [])
        action.setdefault('explanations', [])
        action['rules'] = [r.get('rule') for r in action.get('reasons', []) if isinstance(r, dict)]
        action.pop('reasons', None)
        # Never present truncated details as a complete approval target.
        for field in ('args', 'result'):
            if field in action and len(json.dumps(action[field], ensure_ascii=True)) > 8000:
                action[field] = {'unavailable': 'Details exceed display bound; do not approve'}
                result['pending'] = None
        action.pop('backend_session', None)
    if result.get('recorded_trace'):
        result['recorded_trace'] = normalize(result['recorded_trace'])
    return result


class DashboardAdapter:
    def __init__(self, mixed, root, transport=None):
        self.mixed = mixed
        self.lock = threading.RLock()
        self.service = OriginalProduct(mixed, root / 'live', transport, reviewer='system-dashboard-tool-review')
        try:
            self.recorded = OriginalProduct(mixed, root / 'recorded', TestModel(), reviewer='system-recorded-tool-review')
        except BaseException:
            self.service.close()
            raise
        self.recorded.model = LocalModel()
        self.recorded.mixed = RecordedAccess()
        self.recorded.test_model = True
        self.owners = {}
        self.recordings = {}
        self.recorded_sessions = set()

    def close(self):
        try:
            self.recorded.close()
        finally:
            self.service.close()

    def _record(self, visitor, address, task):
        state = asyncio.run(self.recorded.start_task(visitor, address, task))
        sid = state['id']
        # Drive actual original gateway decisions. Holds remain unapproved.
        for _ in range(4):
            state = asyncio.run(self.recorded.advance(visitor, sid))
            if state['pending'] or state['done']:
                break
        return dict(normalize(state), label='Recorded run/test model', verification=self.recorded.verify(visitor, sid))

    def start(self, visitor, address, task):
        with self.lock:
            if not self.mixed.key or not self.mixed.enabled(visitor):
                state = asyncio.run(self.recorded.start_task(visitor, address, task))
                sid = state['id']
                self.recorded_sessions.add(sid)
            else:
                state = asyncio.run(self.service.start_task(visitor, address, task))
                sid = state['id']
            self.owners[sid] = (visitor, address, task)
            return normalize(state)

    def _owned(self, visitor, sid):
        owner = self.owners.get(sid)
        if not owner or owner[0] != visitor:
            raise PermissionError('Session required')
        return owner

    def status(self, visitor, sid):
        with self.lock:
            self._owned(visitor, sid)
            product = self.recorded if sid in self.recorded_sessions else self.service
            return normalize(self.recordings[sid][1] if sid in self.recordings else product.status(visitor, sid))

    def advance(self, visitor, sid):
        with self.lock:
            _, address, task = self._owned(visitor, sid)
            if sid in self.recordings:
                return self.status(visitor, sid)
            if sid in self.recorded_sessions:
                return normalize(asyncio.run(self.recorded.advance(visitor, sid)))
            state = asyncio.run(self.service.advance(visitor, sid))
            if state['mode'] in ('Stopped safely', 'Recorded run') or any(a.get('request_failed') for a in state['actions']):
                state['recorded_trace'] = self._record(visitor, address, task)
                state['mode'] = 'Recorded run'
                self.recordings[sid] = (visitor, state)
            return normalize(state)

    def approval(self, visitor, sid, action_id, approved, reason):
        with self.lock:
            self._owned(visitor, sid)
            if sid in self.recordings:
                raise ValueError('Recorded runs cannot be approved')
            product = self.recorded if sid in self.recorded_sessions else self.service
            try:
                return normalize(asyncio.run(product.approval(visitor, sid, action_id, approved,
                    reviewer={'username': visitor, 'role': 'approver'}, reason=reason)))
            except ValueError as error:
                if 'approval void' not in str(error):
                    raise
                state = product.status(visitor, sid)
                state['decision_error'] = str(error)
                return normalize(state)

    def verify(self, visitor, sid):
        with self.lock:
            self._owned(visitor, sid)
            if sid in self.recorded_sessions:
                return dict(self.recorded.verify(visitor, sid), scope='recorded mock original gateway')
            if sid in self.recordings:
                trace = self.recordings[sid][1]['recorded_trace']
                result = self.recorded.verify(visitor, trace['id'])
                return dict(result, scope='recorded mock original gateway')
            return dict(self.service.verify(visitor, sid), scope='original gateway')
