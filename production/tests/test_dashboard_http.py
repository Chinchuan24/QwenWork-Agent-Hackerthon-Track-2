import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis.production import create_app
from aegis.dashboard_adapter import FAKE_KEY


class DashboardHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / 'state'
        self.env = patch.dict(os.environ, {
            'AEGIS_ENV': 'production', 'AEGIS_DEMO_PUBLIC': '1',
            'AEGIS_PRODUCTION_DATA_DIR': str(self.root),
            'AEGIS_TRUSTED_HOSTS': 'testserver', 'AEGIS_MODEL_PROVIDER': 'deepseek',
            'DEEPSEEK_API_KEY': FAKE_KEY, 'AEGIS_LIVE_TEST_MODEL': '1',
            'AEGIS_LIVE_ACCESS_MODE': 'open', 'AEGIS_LIVE_BURST_ACTIONS': '60',
        }, clear=True)
        self.env.start()
        self.client = TestClient(create_app(), base_url='https://testserver')
        self.client.__enter__()
        self.login('approver')

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.tmp.cleanup()

    def login(self, role):
        self.client.cookies.clear()
        response = self.client.get('/')
        self.csrf = re.search('name="csrf" value="([^"]+)"', response.text)[1]
        self.assertEqual(self.client.post('/session', data={'csrf': self.csrf, 'role': role}).status_code, 200)

    def post(self, op, **data):
        if op == 'approval' and data.get('approved') and 'reason' not in data:
            data['reason'] = 'I reviewed the exact fictional target.'
        return self.client.post('/live-product/' + op, json=data, headers={'X-CSRF-Token': self.csrf})

    def test_action_judge_capture_is_scoped(self):
        state = self.post('start', task='invoices').json()
        sid = state['id']
        first = self.post('advance', task_id=sid).json()['actions'][0]
        self.assertNotIn('limits', [j['kind'] for j in first['judges']])
        state = self.post('advance', task_id=sid).json()
        second = state['actions'][1]
        kinds = [j['kind'] for j in second['judges']]
        self.assertEqual(kinds.count('safety_a'), 1)
        self.assertEqual(kinds.count('safety_b'), 1)
        self.assertTrue(second['explanations'])
        self.assertTrue(all(j['source'] == 'captured response' for j in second['judges']))
        self.assertEqual(state['actions'][0], first)
        status = self.client.get('/live-product/status', params={'task_id': sid}).json()
        self.assertEqual(status['actions'], state['actions'])

    def test_assets_csrf_and_boundaries(self):
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('<style>', response.text)
        self.assertNotIn('<script>', response.text)
        self.assertIn('script-src \'self\'', response.headers['content-security-policy'])
        for asset in ('dashboard.css', 'dashboard.js'):
            self.assertEqual(self.client.get('/dashboard/assets/' + asset).status_code, 200)
        self.assertEqual(self.client.post('/live-product/start', json={'task': 'invoices'}).status_code, 403)
        self.assertEqual(self.post('start', task='invoices', visitor='attacker').status_code, 400)
        self.assertEqual(self.post('start', task='unknown').status_code, 409)

    def test_tasks_decisions_approval_record_and_isolation(self):
        seen = set()
        for task in ('invoices', 'partners', 'contract'):
            state = self.post('start', task=task).json()
            self.assertIn('id', state, state)
            sid = state['id']
            for _ in range(3):
                state = self.post('advance', task_id=sid).json()
                self.assertIn('actions', state, state)
                seen.update(a['verdict'] for a in state['actions'])
                if state['pending']:
                    aid = state['pending']
                    self.assertEqual(self.post('approval', task_id=sid, action_id='wrong', approved=True).status_code, 409)
                    state = self.post('approval', task_id=sid, action_id=aid, approved=task == 'invoices').json()
                    if 'error' in state:
                        state = self.client.get('/live-product/status', params={'task_id': sid}).json()
                        self.assertEqual(state['actions'][-1]['status'], 'blocked')
                    self.assertIn('actions', state, state)
                    self.assertIsNone(state['pending'])
                    self.assertEqual(self.post('approval', task_id=sid, action_id=aid, approved=True).status_code, 409)
                if state['done']:
                    break
            verification = self.post('verify', task_id=sid).json()
            self.assertTrue(verification['ok'], verification)
            self.assertNotIn(FAKE_KEY, str(state))
            self.assertNotIn('backend_session', str(state))
            self.assertEqual(state['outside_effects'], 0)
            self.login('viewer')
            self.assertEqual(self.client.get('/live-product/status', params={'task_id': sid}).status_code, 404)
            self.assertEqual(self.post('approval', task_id=sid, action_id='x', approved=True).status_code, 403)
            self.login('approver')
        self.assertTrue({'allow', 'hold', 'block'} <= seen, seen)
        for path in self.root.rglob('*'):
            if path.is_file():
                self.assertNotIn(FAKE_KEY.encode(), path.read_bytes(), str(path))

    def test_disabled_and_missing_key_recorded_original(self):
        for variable, value in (('AEGIS_LIVE_ENABLED', '0'), ('AEGIS_LIVE_ACCESS_MODE', 'access-code')):
            with patch.dict(os.environ, {variable: value}):
                state = self.post('start', task='partners').json()
                self.assertEqual(state['mode'], 'Recorded run/test model', state)
                state = self.post('advance', task_id=state['id']).json()
                self.assertTrue(state['actions'])
                self.assertTrue(self.post('verify', task_id=state['id']).json()['ok'])
                self.assertEqual(self.post('approval', task_id=state['id'], action_id='x', approved=True).status_code, 409)

    def test_missing_key_and_caps(self):
        self.client.__exit__(None, None, None)
        with patch.dict(os.environ, {'DEEPSEEK_API_KEY': '', 'AEGIS_LIVE_TEST_MODEL': '0'}):
            self.client = TestClient(create_app(), base_url='https://testserver')
            self.client.__enter__()
            self.login('approver')
            state = self.post('start', task='invoices').json()
            self.assertEqual(state['mode'], 'Recorded run/test model', state)
            self.assertTrue(self.post('verify', task_id=state['id']).json()['ok'])
        self.client.__exit__(None, None, None)
        with patch.dict(os.environ, {'AEGIS_LIVE_SESSION_CALLS': '1'}):
            self.client = TestClient(create_app(), base_url='https://testserver')
            self.client.__enter__()
            self.login('approver')
            state = self.post('start', task='invoices').json()
            state = self.post('advance', task_id=state['id']).json()
            self.assertEqual(state['mode'], 'Recorded run', state)
            self.assertTrue(state['recorded_trace']['verification']['ok'])

    def test_approval_reason_and_exact_targets(self):
        self.login('approver')
        for task, tool, target in [('invoices', 'delete_file', 'march-duplicate.txt'), ('partners', 'upload_file', 'clients.txt'), ('contract', 'write_file', 'draft.txt')]:
            for approved in (task == 'invoices',):
                self.login('approver')
                self.client.__exit__(None, None, None)
                self.client = TestClient(create_app(), base_url='https://testserver')
                self.client.__enter__()
                self.login('approver')
                with __import__('sqlite3').connect(self.root / 'db' / 'public-demo.db') as db:
                    db.execute('DELETE FROM live_attempts')
                state = self.post('start', task=task).json()
                sid = state['id']
                self.post('advance', task_id=sid)
                state = self.post('advance', task_id=sid).json()
                action = state['actions'][-1]
                self.assertEqual(action['tool'], tool)
                self.assertEqual(action['args']['doc_id'], target)
                if task == 'partners':
                    self.assertEqual(action['args']['target'], 'partner.example')
                    self.assertEqual(action['verdict'], 'block')
                    continue
                aid = state['pending']
                self.assertTrue(aid, state)
                for invalid in (None, 42, [], ' ', '\x00', 'x' * 501):
                    response = self.post('approval', task_id=sid, action_id=aid, approved=True, reason=invalid)
                    self.assertEqual(response.status_code, 400, response.text)
                reason = 'Reviewed ' + target + ('; approve.' if approved else '; do not run.')
                from aegis.dashboard_adapter import DashboardAdapter
                original = DashboardAdapter.approval
                captured = []
                def capture(service, visitor, sid, aid, decision, text):
                    captured.append(text)
                    return original(service, visitor, sid, aid, decision, text)
                with patch.object(DashboardAdapter, 'approval', capture):
                    state = self.post('approval', task_id=sid, action_id=aid, approved=approved, reason=reason).json()
                self.assertEqual(captured, [reason])
                if 'error' in state:
                    self.assertTrue(approved)
                    state = self.client.get('/live-product/status', params={'task_id': sid}).json()
                    self.assertEqual(state['actions'][-1]['status'], 'blocked', state)
                else:
                    self.assertEqual(state['actions'][-1]['status'], 'blocked' if approved else 'denied', state)
                self.assertTrue(self.post('verify', task_id=sid).json()['ok'])

    def test_recorded_hold_approve_and_deny_without_live_access(self):
        with patch.dict(os.environ, {'AEGIS_LIVE_ENABLED': '0'}):
            for approved in (True, False):
                state = self.post('start', task='invoices').json()
                sid = state['id']
                self.post('advance', task_id=sid)
                state = self.post('advance', task_id=sid).json()
                self.assertTrue(state['pending'], state)
                state = self.post('approval', task_id=sid, action_id=state['pending'],
                                  approved=approved, reason='Reviewed exact duplicate; human decision.').json()
                if approved and 'error' in state:
                    state = self.client.get('/live-product/status', params={'task_id': sid}).json()
                self.assertEqual(state['actions'][-1]['status'], 'blocked' if approved else 'denied', state)
                self.assertIn('march-duplicate.txt', state['files'])
                self.assertEqual(state['outside_effects'], 0)
                self.assertTrue(self.post('verify', task_id=sid).json()['ok'])

    def test_one_actual_call_one_shared_reservation(self):
        import sqlite3
        state = self.post('start', task='invoices').json()
        with sqlite3.connect(self.root / 'db' / 'public-demo.db') as db:
            before = db.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0]
            self.assertTrue(before)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM live_attempts WHERE tokens=0').fetchone()[0], 0)
        self.post('advance', task_id=state['id'])
        with sqlite3.connect(self.root / 'db' / 'public-demo.db') as db:
            self.assertGreater(db.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0], before)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM live_attempts WHERE active=1').fetchone()[0], 0)

    def test_malicious_provider_fake_key_is_not_exposed(self):
        import contextlib
        import io
        from aegis.dashboard_adapter import DashboardTestModel
        for task in ('invoices', 'partners', 'contract'):
            stdout, stderr = io.StringIO(), io.StringIO()
            state = self.post('start', task=task).json()
            def malicious(model, payload):
                return {'usage': {'prompt_tokens': 10, 'completion_tokens': 2}, 'choices': [{'message': {'content': __import__('json').dumps({'tool': 'send_email', 'args': {'to': FAKE_KEY, 'body': FAKE_KEY, 'attachment_ids': [FAKE_KEY]}})}}]}
            with patch.object(DashboardTestModel, '__call__', malicious), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), self.assertLogs('aegis.production', level='INFO') as logs:
                response = self.post('advance', task_id=state['id'])
            self.assertNotIn(FAKE_KEY, response.text + str(response.headers) + stdout.getvalue() + stderr.getvalue() + str(logs.output))
            self.assertEqual(response.json()['mode'], 'Recorded run', response.text)
            for path in self.root.rglob('*'):
                if path.is_file():
                    self.assertNotIn(FAKE_KEY.encode(), path.read_bytes(), str(path))


if __name__ == '__main__':
    unittest.main()
