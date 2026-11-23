import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from aegis.mixed_demo import MixedDemo, RESERVE
from aegis.live_product import LiveProduct, TestModel

FAKE = 'sk-test-FAKE-0000000000000000'

class ProductTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': FAKE, 'AEGIS_LIVE_ACCESS_MODE': 'open'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.root = Path(self.tmp.name)
        self.mixed = MixedDemo(self.root / 'quota.db', b'test-salt')
        self.model = TestModel()
        self.service = LiveProduct(self.mixed, self.root / 'signer', transport=self.model)

    def task(self, task='invoices', visitor='v'):
        return asyncio.run(self.service.start_task(visitor, 'ip', task))['id']

    def step(self, sid, visitor='v'):
        return asyncio.run(self.service.advance(visitor, sid))

    def test_tasks_and_seals(self):
        for task, expected in [('invoices', 'hold'), ('partners', 'block'), ('contract', 'allow')]:
            sid = self.task(task, task)
            self.assertEqual(self.step(sid, task)['actions'][0]['verdict'], 'allow')
            state = self.step(sid, task)
            self.assertEqual(state['actions'][-1]['verdict'], expected)
            self.assertEqual(len(state['actions'][-1]['judges']), 2)
            self.assertTrue(self.service.verify(task, sid)['ok'])
            self.assertFalse(self.service.verify(task, sid, tamper=True)['ok'])
            self.assertTrue(self.service.verify(task, sid)['ok'])

    def test_approval_and_isolation(self):
        for approved in (True, False):
            visitor = str(approved)
            sid = self.task(visitor=visitor)
            self.step(sid, visitor)
            state = self.step(sid, visitor)
            aid = state['pending']
            state = asyncio.run(self.service.approval(visitor, sid, aid, approved))
            self.assertEqual(state['actions'][-1]['status'], 'executed' if approved else 'denied')
            with self.assertRaises(ValueError):
                asyncio.run(self.service.approval(visitor, sid, aid, approved))
            with self.assertRaises(PermissionError):
                self.service.status('intruder', sid)
            self.assertTrue(self.service.verify(visitor, sid)['ok'])
        sid = self.task(visitor='fresh')
        self.assertIn('march-duplicate.txt', self.service.status('fresh', sid)['files'])

    def test_all_caps_shared(self):
        original = self.mixed.limits.copy()
        for cap in ('SESSION_CALLS', 'IP_DAILY_CALLS', 'DAILY_CALLS', 'DAILY_TOKENS', 'MONTHLY_TOKENS', 'BURST_ACTIONS', 'CONCURRENCY'):
            self.mixed.limits = dict(original)
            self.mixed.limits[cap] = 0
            before = len(self.model.calls)
            sid = self.task(visitor=cap)
            state = self.step(sid, cap)
            self.assertEqual(state['mode'], 'Recorded run')
            self.assertEqual(len(self.model.calls), before)
            self.assertEqual(state['recorded_trace']['label'], 'Recorded run/test model')
        self.mixed.limits = original

    def test_key_switch_access_errors_no_leaks(self):
        for reason in ('missing', 'switch', 'access', 'error'):
            self.mixed.key = '' if reason == 'missing' else FAKE
            os.environ['AEGIS_LIVE_ENABLED'] = '0' if reason == 'switch' else '1'
            os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'access-code' if reason == 'access' else 'open'
            self.model.fail = reason == 'error'
            sid = self.task(visitor=reason)
            state = self.step(sid, reason)
            self.assertEqual(state['mode'], 'Recorded run')
            self.assertNotIn(FAKE, json.dumps(state))
        for file in self.root.rglob('*'):
            if file.is_file():
                self.assertNotIn(FAKE.encode(), file.read_bytes())

    def test_six_actions_three_calls_each_seventh_stops_before_provider(self):
        for _ in range(6):
            sid = self.task()
            state = self.step(sid)
            self.assertEqual(state['mode'], 'Test model')
            self.assertEqual(len(state['actions']), 1)
        self.assertEqual(len(self.model.calls), 18)
        state = self.step(self.task())
        self.assertEqual(state['mode'], 'Recorded run')
        self.assertEqual(len(self.model.calls), 18)
        with self.mixed.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*), SUM(calls), SUM(closed) FROM live_actions').fetchone(), (6, 18, 6))
            self.assertEqual(c.execute('SELECT COUNT(*), SUM(tokens), SUM(active) FROM live_attempts').fetchone(), (18, 216, 0))

    def test_context_cannot_be_omitted_forged_reused_or_cross_visitor(self):
        from aegis.live_product import Unavailable
        for context in (None, 'forged'):
            with self.assertRaises(Unavailable):
                self.service.model.call('v', 'ip', {'kind': 'helper'}, context)
        context = self.mixed.admit_action('v', 'ip')
        self.assertEqual(self.mixed.reserve_call('other', 'ip', context), ('scripted', []))
        self.mixed.close_action(context)
        self.assertEqual(self.mixed.reserve_call('v', 'ip', context), ('scripted', []))
        self.assertEqual(self.model.calls, [])

    def test_accounting_and_output(self):
        sid = self.task()
        self.step(sid)
        self.assertEqual(len(self.model.calls), 3)
        self.assertTrue(all(c['max_tokens'] == 512 for c in self.model.calls))
        with self.mixed.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*), SUM(active) FROM live_attempts').fetchone(), (3, 0))
        self.model.fail = True
        sid = self.task(visitor='fail')
        self.step(sid, 'fail')
        with self.mixed.connect() as c:
            self.assertEqual(c.execute('SELECT SUM(tokens) FROM live_attempts WHERE visitor=?', ('fail',)).fetchone()[0], RESERVE)

    def test_untrusted_actions_block(self):
        for action in ({'tool': 'shell', 'args': {}}, {'tool': 'write_file', 'args': {'doc_id': '../escape', 'body': 'bad'}}, {'tool': 'upload_file', 'args': {'doc_id': 'clients.txt', 'target': 'partner.example'}}):
            self.model.override = action
            visitor = json.dumps(action)
            sid = self.task(visitor=visitor)
            state = self.step(sid, visitor)
            self.assertEqual(state['actions'][-1]['verdict'], 'block')
            self.assertEqual(state['outside_effects'], 0)

    def test_guard_uncertainty_and_kill_before_approval(self):
        self.model.guard = 'unsure'
        sid = self.task()
        state = self.step(sid)
        self.assertEqual(state['actions'][-1]['verdict'], 'hold')
        os.environ['AEGIS_LIVE_ENABLED'] = '0'
        with self.assertRaises(ValueError):
            asyncio.run(self.service.approval('v', sid, state['pending'], True))
        self.assertEqual(self.service.status('v', sid)['actions'][-1]['status'], 'held')
