import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from aegis.dashboard_adapter import DashboardAdapter, FAKE_KEY, RecordedAccess, normalize


class SealedLinksV3Tests(unittest.TestCase):
    def test_durable_hashes_task_visitor_and_recorded_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = DashboardAdapter(RecordedAccess(), Path(tmp))
            self.addCleanup(adapter.close)
            states = []
            for visitor in ('alice', 'alice', 'bob'):
                state = asyncio.run(adapter.recorded.start_task(visitor, 'ip', 'invoices'))
                sid = state['id']
                adapter.owners[sid] = (visitor, 'ip', 'invoices')
                adapter.recorded_sessions.add(sid)
                self.assertEqual(state['sealed_links'], [])
                state = adapter.advance(visitor, sid)
                state = adapter.advance(visitor, sid)
                self.assertEqual(state['sealed_decisions'], len(state['sealed_links']))
                self.assertEqual([x['action_id'] for x in state['sealed_links']],
                                 [a['id'] for a in state['actions']])
                session = adapter.recorded.sessions[sid]['backend_session']
                with sqlite3.connect(Path(tmp) / 'recorded/data/aegis.db') as db:
                    expected = db.execute(
                        "SELECT hash FROM audit WHERE session_id=? AND run_id=? AND event='decision' ORDER BY id",
                        (session['session_id'], session['run_id'])).fetchall()
                self.assertEqual([x['hash'] for x in state['sealed_links']], [r[0] for r in expected])
                for link in state['sealed_links']:
                    self.assertEqual(set(link), {'action_id', 'hash'})
                    self.assertRegex(link['hash'], r'^[0-9a-f]{64}$')
                self.assertNotIn(FAKE_KEY, json.dumps(state))
                self.assertNotIn(session['token'], json.dumps(state))
                self.assertNotIn('backend_session', json.dumps(state))
                self.assertEqual(adapter.status(visitor, sid)['sealed_links'], state['sealed_links'])
                with self.assertRaises(PermissionError):
                    adapter.status('intruder', sid)
                states.append(state)
            self.assertTrue(set(x['hash'] for x in states[0]['sealed_links']).isdisjoint(
                x['hash'] for x in states[1]['sealed_links']))
            trace = adapter._record('alice', 'ip', 'partners')
            combined = normalize(dict(states[0], recorded_trace=trace))
            self.assertEqual(combined['sealed_links'], states[0]['sealed_links'])
            self.assertEqual(combined['recorded_trace']['sealed_links'], trace['sealed_links'])
            self.assertEqual(trace['sealed_decisions'], len(trace['sealed_links']))
            for path in Path(tmp).rglob('*'):
                if path.is_file():
                    self.assertNotIn(FAKE_KEY.encode(), path.read_bytes())

    def test_missing_receipts_are_not_invented(self):
        state = normalize({'actions': [{}, {}], 'recorded_trace': {'actions': [{}]}})
        self.assertIsNone(state['sealed_links'])
        self.assertIsNone(state['recorded_trace']['sealed_links'])
