import copy
import unittest
from datetime import datetime

from aegis.breach_prefill import pdpc_fact_prefill


class PrefillTests(unittest.TestCase):
    def test_unknown_no_inference(self):
        for incident in (None, {}, [], {'count': 99, 'audit_count': 500,
                'title': '900 people, passwords, serious harm',
                'steps': [{'step': '1000 affected', 'audit_id': 999}]}):
            with self.subTest(incident=incident):
                self.assertEqual(pdpc_fact_prefill(incident),
                                 {'count': '', 'data': '', 'harm': ''})

    def test_latest_known_per_field(self):
        incident = {'facts': {'count': 12, 'data': ['email'], 'harm': True},
                    'steps': [{'facts': {'count': 0}},
                              {'facts': {'data': 'phone', 'harm': False}},
                              {'facts': {'count': None, 'data': None, 'harm': None}}]}
        result = pdpc_fact_prefill(incident)
        self.assertEqual(result, {'count': 0, 'data': 'phone', 'harm': False})
        self.assertIs(result['harm'], False)
        self.assertIs(type(result['count']), int)

    def test_malformed_fields_clear_stale_values_independently(self):
        invalid = {
            'count': [False, True, -1, 2**63, 1.5, '12', {}, []],
            'data': [False, 3, {}, [], (), ['email', 2], ['', '  '], '', '  ',
                     'x' * 10001],
            'harm': [0, 1, 'false', [], {}],
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(pdpc_fact_prefill({'facts': {field: value}})[field], '')
                    incident = {'facts': {'count': 4, 'data': 'email', 'harm': True},
                                'steps': [{'facts': {field: value}}]}
                    expected = {'count': 4, 'data': 'email', 'harm': True}
                    expected[field] = ''
                    self.assertEqual(pdpc_fact_prefill(incident), expected)
                    incident['steps'].append({'facts': {field: None}})
                    incident['steps'].append({'facts': {}})
                    self.assertEqual(pdpc_fact_prefill(incident), expected)

    def test_schema_and_safe_containers(self):
        for facts in (None, [], 'count: 10', {'people': 10, 'categories': 'email'}):
            self.assertEqual(pdpc_fact_prefill({'facts': facts}),
                             {'count': '', 'data': '', 'harm': ''})
        for steps in (None, {}, 'unsafe'):
            self.assertEqual(pdpc_fact_prefill({'facts': {'count': 2}, 'steps': steps}),
                             {'count': 2, 'data': '', 'harm': ''})
        self.assertEqual(pdpc_fact_prefill({'steps': [None, 3, [],
                         {'facts': {'count': 7, 'other': 'ignored'}}]})['count'], 7)

    def test_copy_categories_without_mutation(self):
        for categories in (['email', 'phone'], ('email', 'phone')):
            incident = {'facts': {'data': categories}, 'steps': []}
            before = copy.deepcopy(incident)
            result = pdpc_fact_prefill(incident)
            self.assertEqual(result['data'], ['email', 'phone'])
            result['data'].append('password')
            self.assertEqual(incident, before)
            self.assertEqual(pdpc_fact_prefill(incident)['data'], ['email', 'phone'])

    def test_sg_midnight_month_end_append_order(self):
        for earlier, later in (
            ('2026-11-19T23:59:59+08:00', '2026-11-20T00:00:00+08:00'),
            ('2026-01-31T23:59:59+08:00', '2026-02-01T00:00:00+08:00'),
            ('2026-12-31T15:59:59+00:00', '2027-01-01T00:00:00+08:00'),
        ):
            with self.subTest(earlier=earlier):
                incident = {'facts': {}, 'steps': [
                    {'timestamp': datetime.fromisoformat(later).timestamp(),
                     'audit_id': 90, 'facts': {'count': 9, 'data': 'email'}},
                    {'timestamp': datetime.fromisoformat(earlier).timestamp(),
                     'audit_id': 10, 'facts': {'count': 3, 'data': 'phone'}}]}
                self.assertEqual(pdpc_fact_prefill(incident),
                                 {'count': 3, 'data': 'phone', 'harm': ''})
                for row in incident['steps']:
                    row['facts'] = {}
                self.assertEqual(pdpc_fact_prefill(incident),
                                 {'count': '', 'data': '', 'harm': ''})


if __name__ == '__main__':
    unittest.main()
