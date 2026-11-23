import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from aegis.real_backend import RealBackend


class RealBackendTests(unittest.TestCase):
    def test_original_record_restart_and_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            def judge(kind, payload):
                calls.append(kind)
                return {'verdict': 'unsure', 'mode': 'test model'}

            backend = RealBackend(root, judge)
            try:
                session = backend.request('start', owner='test-owner', task='Read public documents')
                self.assertEqual(session['limits_mode'], 'fallback-readonly')
                for tool, args in [('shell', {}), ('read_file', {'doc_id': 'doc_public'})]:
                    result = backend.request('call', token=session['token'], tool=tool, args=args)
                    self.assertEqual(result['verdict'], 'block')
                verified = backend.request('verify')
                self.assertTrue(verified['ok'])
                self.assertEqual(verified['records'], verified['checkpoints'])
                self.assertIn('limits', calls)
                self.assertFalse(hasattr(backend, 'signing_key'))
                connection = sqlite3.connect(root / 'data' / 'aegis.db')
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("UPDATE audit SET event='tampered'")
                connection.close()
            finally:
                backend.close()
            backend = RealBackend(root, judge)
            try:
                restored = backend.request('verify')
                self.assertTrue(restored['ok'])
                self.assertEqual(restored['last_hash'], verified['last_hash'])
                self.assertEqual(restored['records'], verified['records'])
            finally:
                backend.close()

    def test_dependency_closure_provenance(self):
        package = Path(__file__).resolve().parents[1] / 'aegis' / 'real_runtime'
        manifest = json.loads((package / 'provenance.json').read_text())
        self.assertEqual(len(manifest['sha256']), 21)
        self.assertEqual({p.name for p in package.glob('*.py')},
                         {name for name in manifest['sha256'] if name.endswith('.py')})
        for name, digest in manifest['sha256'].items():
            self.assertEqual(hashlib.sha256((package / name).read_bytes()).hexdigest(), digest)
        self.assertFalse((package / 'app.py').exists())
        self.assertFalse((package / 'worker.py').exists())


if __name__ == '__main__':
    unittest.main()
