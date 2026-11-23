import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aegis.backend_mount import mount_live_product
from aegis.live_product import TestModel
from aegis.mixed_demo import MixedDemo
from aegis.real_backend import RealBackend


class MountTests(unittest.TestCase):
    def test_fake_original_outcomes_approval_and_restart(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': 'sk-test-FAKE-0000000000000000', 'AEGIS_LIVE_ACCESS_MODE': 'open'}, clear=True):
            root = Path(tmp)
            mixed = MixedDemo(root / 'quota.db', b'test')
            mixed.limits['BURST_ACTIONS'] = 200
            mixed.limits['SESSION_CALLS'] = 200
            model = TestModel()
            service = mount_live_product(mixed, root / 'backend', model, reviewer='operator')
            try:
                self.assertEqual(len(service.tools), 5)
                sid = asyncio.run(service.start_task('owner', 'ip', 'invoices'))['id']
                model.override = {'tool': 'read_file', 'args': {'doc_id': 'march.txt'}}
                state = asyncio.run(service.advance('owner', sid))
                self.assertEqual(state['actions'][-1]['verdict'], 'allow')
                model.override = {'tool': 'delete_file', 'args': {'doc_id': 'march-duplicate.txt'}}
                state = asyncio.run(service.advance('owner', sid))
                self.assertEqual(state['actions'][-1]['verdict'], 'hold', state['actions'][-1])
                aid = state['pending']
                self.assertTrue(aid)
                with self.assertRaises(ValueError):
                    asyncio.run(service.approval('owner', sid, aid, True, reviewer={'username': 'owner', 'role': 'admin'}, reason='Reviewed'))
                state = asyncio.run(service.approval('owner', sid, aid, False, reviewer={'username': 'other', 'role': 'approver'}))
                self.assertEqual(state['actions'][-1]['status'], 'denied')
                model.override = {'tool': 'delete_file', 'args': {'doc_id': 'march-duplicate.txt'}}
                state = asyncio.run(service.advance('owner', sid))
                with self.assertRaisesRegex(ValueError, 'Lumen policy forbids release'):
                    asyncio.run(service.approval('owner', sid, state['pending'], True, reviewer={'username': 'other', 'role': 'approver'}, reason='Fictional document reviewed'))
                self.assertIsNone(service.status('owner', sid)['pending'])
                model.override = {'tool': 'shell', 'args': {}}
                state = asyncio.run(service.advance('owner', sid))
                self.assertEqual(state['actions'][-1]['verdict'], 'block')
                verified = service.verify('owner', sid)
                self.assertTrue(verified['ok'])
                self.assertTrue(any('original_payload' in __import__('json').loads(p['messages'][1]['content']) for p in model.calls))
                with self.assertRaises(ValueError):
                    service.backend.request('call', token='x', tool='x', args={'x': 'x' * 70000})
            finally:
                service.close()
            backend = RealBackend(root / 'backend', lambda *args: {'verdict': 'unsure'})
            try:
                self.assertEqual(backend.request('verify')['last_hash'], verified['last_hash'])
            finally:
                backend.close()


if __name__ == '__main__':
    unittest.main()
