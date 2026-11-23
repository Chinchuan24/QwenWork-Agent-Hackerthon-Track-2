import json
import sqlite3
import unittest
from contextlib import nullcontext
from types import SimpleNamespace

from aegis.backend_mount import configure_runtime
from aegis.dashboard_adapter import normalize


class SealedDecisionTests(unittest.TestCase):
    def test_exact_linkage_isolation_and_bounds(self):
        c = sqlite3.connect(':memory:')
        c.row_factory = sqlite3.Row
        self.addCleanup(c.close)
        c.executescript('CREATE TABLE audit(id INTEGER PRIMARY KEY, session_id, run_id, event, detail_json, hash);'
                        'CREATE TABLE actions(id PRIMARY KEY, session_id, tool, args_json);')
        args = {'doc_id': 'march.txt'}
        c.execute('INSERT INTO actions VALUES(?,?,?,?)', ('a', 's', 'read_file', json.dumps(args)))
        c.execute('INSERT INTO actions VALUES(?,?,?,?)', ('other', 'other-session', 'read_file', json.dumps(args)))
        detail = dict(action_id='a', tool='read_file', args=args, stage='final', verdict='allow', reasons=[])
        def receipt(d, sid='s', rid='r', event='decision'):
            c.execute('INSERT INTO audit(session_id,run_id,event,detail_json,hash) VALUES(?,?,?,?,?)',
                      (sid, rid, event, json.dumps(d), '1' * 64))
        receipt(detail)
        receipt(detail)
        receipt(detail, sid='other-session')
        receipt(detail, rid='other-run')
        receipt(detail, event='helper_card_authorized')
        for changes in ({'action_id': 'other'}, {'action_id': None}, {'tool': 'delete_file'},
                        {'args': {}}, {'stage': 'initial'}, {'verdict': 'unknown'},
                        {'reasons': [{'rule': 'GATE-IDEM'}]}):
            receipt(dict(detail, **changes))
        verified = {'ok': True}
        audit = SimpleNamespace(publication_lock=nullcontext, verify=lambda: verified)
        gateway = SimpleNamespace(session_by_token=lambda token: {'id': 's', 'run_id': 'r'} if token == 'trusted' else None)
        def count(token='trusted'):
            return configure_runtime(audit, SimpleNamespace(conn=lambda: c),
                                     SimpleNamespace(dec_json=json.loads), gateway,
                                     {'op': 'sealed_decisions', 'token': token})
        self.assertEqual(count(), {'sealed_decisions': 1, 'sealed_links': [
            {'action_id': 'a', 'hash': '1' * 64}]})
        with self.assertRaises(PermissionError):
            count('wrong')
        verified['ok'] = False
        self.assertEqual(count(), {'sealed_decisions': None, 'sealed_links': None})
        verified['ok'] = True
        for _ in range(257):
            receipt(detail)
        self.assertEqual(count(), {'sealed_decisions': None, 'sealed_links': None})

    def test_recorded_counts_remain_separate(self):
        state = normalize({'sealed_decisions': 1, 'recorded_trace': {
            'mode': 'Test model', 'label': 'Recorded run/test model', 'sealed_decisions': 2}})
        self.assertEqual(state['sealed_decisions'], 1)
        self.assertEqual(state['recorded_trace']['sealed_decisions'], 2)
        self.assertEqual(state['recorded_trace']['label'], 'Recorded run/test model')
        self.assertIsNone(normalize({'actions': [{}, {}]})['sealed_decisions'])
