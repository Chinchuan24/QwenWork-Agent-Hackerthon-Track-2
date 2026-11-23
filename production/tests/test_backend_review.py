import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from aegis.backend_mount import mount_live_product
from aegis.live_product import TestModel, Unavailable
from aegis.mixed_demo import MixedDemo
from aegis.real_backend import RealBackend

FAKE = 'sk-test-FAKE-review-0000000000000000'


class BackendReviewTests(unittest.TestCase):
    def test_original_pipeline_default_actions_and_spending(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': FAKE,
            'AEGIS_LIVE_ACCESS_MODE': 'open'}, clear=True):
            root = Path(tmp)
            mixed = MixedDemo(root / 'quota.db', b'test')
            model = TestModel()
            service = mount_live_product(mixed, root / 'backend', model, reviewer='operator')
            try:
                for task in ('invoices', 'partners', 'contract'):
                    visitor = task
                    sid = asyncio.run(service.start_task(visitor, 'ip', task))['id']
                    for _ in range(2):
                        state = asyncio.run(service.advance(visitor, sid))
                        self.assertEqual(state['mode'], 'Test model')
                        self.assertFalse(state.get('recorded_trace'))
                    self.assertEqual(len(state['actions']), 2)
                    with mixed.connect() as c:
                        self.assertEqual(c.execute('SELECT COUNT(*) FROM live_actions WHERE visitor=? AND burst=1', (visitor,)).fetchone()[0], 2)
                        calls = c.execute('SELECT COUNT(*) FROM live_attempts WHERE visitor=?', (visitor,)).fetchone()[0]
                        self.assertGreater(calls, 2)
                        self.assertLessEqual(calls, 30)
                with mixed.connect() as c:
                    self.assertLessEqual(c.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0], 60)
                    self.assertEqual(c.execute('SELECT SUM(active) FROM live_attempts').fetchone()[0], 0)
            finally:
                service.close()

    def test_metadata_write_guards_and_midpipeline_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': FAKE,
            'AEGIS_LIVE_ACCESS_MODE': 'open'}, clear=True):
            root = Path(tmp)
            mixed = MixedDemo(root / 'quota.db', b'test')
            mixed.limits.update(BURST_ACTIONS=500, SESSION_CALLS=500)
            model = TestModel()
            service = mount_live_product(mixed, root / 'backend', model, reviewer='operator')
            try:
                self.assertEqual({t['function']['name'] for t in service.tools},
                    {'read_file', 'write_file', 'delete_file', 'send_email', 'upload_file'})
                sid = asyncio.run(service.start_task('owner', 'ip', 'contract'))['id']
                token = service.sessions[sid]['backend_session']['token']
                snapshot = service.backend.request('snapshot', token=token)
                self.assertEqual(set(snapshot), {'march.txt', 'march-duplicate.txt', 'clients.txt', 'acme.txt'})
                self.assertTrue(all(set(v) == {'title'} for v in snapshot.values()))
                state = asyncio.run(service.advance('owner', sid))
                helper = next(json.loads(p['messages'][1]['content']) for p in model.calls
                              if json.loads(p['messages'][1]['content'])['kind'] == 'helper')
                self.assertNotIn('body', json.dumps(helper['files']))
                self.assertNotIn('Meridian', json.dumps(model.calls))
                model.override = {'tool': 'write_file', 'args': {'doc_id': 'draft.txt', 'body': 'Acme draft'}}
                state = asyncio.run(service.advance('owner', sid))
                self.assertEqual(state['actions'][-1]['verdict'], 'hold')
                self.assertNotIn('draft.txt', state['files'])
                prompts = {json.loads(p['messages'][1]['content'])['kind']: p['messages'][0]['content'] for p in model.calls}
                self.assertIn('authorization and data protection', prompts['safety_a'])
                self.assertIn('alignment and proportionality', prompts['safety_b'])
                result = service.backend.request('call', token=token, tool='write_file', args={'doc_id': '../escape.txt', 'body': 'x'})
                self.assertEqual(result['verdict'], 'block')
                sid2 = asyncio.run(service.start_task('owner', 'ip', 'contract'))['id']
                original = service.model.call
                def fail_guard(visitor, address, context, action_context=None):
                    if context['kind'] == 'safety_a':
                        raise Unavailable()
                    return original(visitor, address, context, action_context)
                service.model.call = fail_guard
                state = asyncio.run(service.advance('owner', sid2))
                self.assertEqual(state['mode'], 'Recorded run')
                self.assertTrue(state['actions'][-1]['request_failed'])
                self.assertTrue(state['recorded_trace']['verification']['ok'])
                self.assertTrue(service.verify('owner', sid2)['ok'])
            finally:
                service.close()

    def test_malicious_provider_fake_key_logs_and_files(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': FAKE,
            'AEGIS_LIVE_ACCESS_MODE': 'open'}, clear=True):
            root = Path(tmp)
            mixed = MixedDemo(root / 'quota.db', b'test')
            def malicious(payload):
                raise RuntimeError('provider header Authorization: Bearer ' + FAKE)
            logs = io.StringIO()
            with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
                service = mount_live_product(mixed, root / 'backend', malicious, reviewer='operator')
                try:
                    state = asyncio.run(service.start_task('owner', 'ip', 'invoices'))
                    self.assertEqual(state['mode'], 'Recorded run')
                    self.assertNotIn(FAKE, json.dumps(state))
                finally:
                    service.close()
            self.assertNotIn(FAKE, logs.getvalue())
            for path in root.rglob('*'):
                if path.is_file():
                    self.assertNotIn(FAKE.encode(), path.read_bytes(), str(path))

    def test_copied_durable_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'original'
            backend = RealBackend(root, lambda *args: {'verdict': 'unsure'})
            backend.request('start', owner='owner', task='Read March invoices')
            self.assertTrue(backend.request('verify')['ok'])
            backend.close()
            copied = Path(tmp) / 'copied'
            shutil.copytree(root, copied)
            with sqlite3.connect(copied / 'data' / 'aegis.db') as db:
                triggers = db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").fetchall()
                for (name,) in triggers:
                    db.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
                db.execute("UPDATE audit SET event='tampered' WHERE id=(SELECT MIN(id) FROM audit)")
            with self.assertRaises(RuntimeError):
                RealBackend(copied, lambda *args: {'verdict': 'unsure'})
            backend = RealBackend(root, lambda *args: {'verdict': 'unsure'})
            self.assertTrue(backend.request('verify')['ok'])
