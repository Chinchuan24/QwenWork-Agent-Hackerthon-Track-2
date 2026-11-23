import json
import sqlite3

from tests.test_dashboard_http import DashboardHTTPTests


class DashboardV3CContractTests(DashboardHTTPTests):
    def test_read_mock_answers_are_captured_and_durably_bound(self):
        state = self.post('start', task='invoices').json()
        first = self.post('advance', task_id=state['id']).json()['actions'][0]
        self.assertEqual(first['verdict'], 'allow')
        self.assertIn('result', first)
        guards = [j for j in first['judges'] if j['kind'] in ('safety_a', 'safety_b')]
        self.assertEqual([j['kind'] for j in guards], ['safety_a', 'safety_b'])
        self.assertEqual([j['reason'] for j in guards],
                         ['Reading is part of task.', 'Nothing leaves sandbox.'])
        self.assertTrue(all(j['verdict'] == 'safe' and j['source'] == 'captured response' for j in guards))
        with sqlite3.connect(self.root / 'backend/live/data/aegis.db') as db:
            rows = db.execute("SELECT session_id, run_id FROM audit WHERE event='test_model_read_assessment'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertTrue(all(rows[0]))
        held = self.post('advance', task_id=state['id']).json()
        self.assertEqual(held['actions'][0], first)
        self.assertEqual(held['actions'][1]['verdict'], 'hold')
        self.assertTrue(held['pending'])
        self.assertNotIn('result', held['actions'][1])
        self.assertTrue(self.post('verify', task_id=state['id']).json()['ok'])
        self.assertEqual(held['outside_effects'], 0)
