"""Synthetic plan replay, not gateway measured or a real normal day.

One action is one observation; action IDs are tool names, folders are doc_id
parents. Attachments and scope are not extra calls. The complete plan fits one
synthetic minute. Daily and minute baselines are projected separately. This is
not production calibration and uses no gateway, vendor service or alarm state.
"""
import copy
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

from aegis.helper_pattern import build_normal_baselines, daily_volume_pattern, helper_pattern
from aegis.lumen_normal import CASES

START = datetime(2026, 11, 18, 1, tzinfo=timezone.utc)


def project_plans(cases, start):
    events = []
    for case in cases:
        for action in case['actions']:
            doc_id = action['args'].get('doc_id')
            folder = None
            if doc_id is not None:
                path = PurePosixPath(doc_id)
                if path.is_absolute() or '..' in path.parts:
                    raise AssertionError('relative document IDs required')
                folder = str(path.parent)
            events.append(dict(helper=case['helper_id'],
                               timestamp=start + timedelta(seconds=len(events)),
                               tool=action['tool'], folder=folder,
                               action=action['tool'], refused=False))
    return events


class SyntheticPlanReplayTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = copy.deepcopy(CASES)
        self.source = project_plans(copy.deepcopy(CASES), START - timedelta(days=1))
        self.base = build_normal_baselines([self.source])
        self.minute_base = {}
        end = self.source[-1]['timestamp']
        for event in self.source:
            if not end - timedelta(seconds=60) <= event['timestamp'] <= end:
                continue
            baseline = self.minute_base.setdefault(event['helper'],
                {'period': '60_seconds', 'tools': {}, 'folders': {}, 'actions': {}})
            for dimension, field in (('tools', 'tool'), ('folders', 'folder'),
                                     ('actions', 'action')):
                value = event[field]
                if value is not None:
                    baseline[dimension][value] = baseline[dimension].get(value, 0) + 1
        self.replay = project_plans(copy.deepcopy(CASES), START)

    def tearDown(self):
        self.assertEqual(CASES, self.snapshot)

    def test_baselines_have_separate_periods_and_storage(self):
        for helper in self.base:
            self.assertEqual(self.base[helper]['period'], 'singapore_day')
            self.assertEqual(self.minute_base[helper]['period'], '60_seconds')
            for dimension in ('tools', 'folders', 'actions'):
                self.assertIsNot(self.base[helper][dimension],
                                 self.minute_base[helper][dimension])

    def test_projection_uses_actions_not_scope(self):
        plans = copy.deepcopy(CASES)
        for case in plans:
            case['needed_files'] = ['unused_scope/unused.md']
            case['allowed_tools'] = ['unused_scope_tool']
        self.assertEqual(project_plans(plans, START), self.replay)
        self.assertIsNot(self.source, self.replay)
        self.assertTrue(all(a is not b for a, b in zip(self.source, self.replay)))
        self.assertEqual(len(self.replay), sum(len(c['actions']) for c in CASES))
        deleted = [e for e in self.replay if e['tool'] == 'delete_file']
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]['folder'], 'admin')
        self.assertFalse(any(e['tool'] == 'read_file' and e['folder'] == 'admin'
                             for e in self.replay))
        self.assertTrue(all(e['folder'] is None for e in self.replay
                            if e['tool'] == 'send_email'))

    def test_canonical_counts_and_per_call_alarm_totals(self):
        before = copy.deepcopy((self.source, self.replay, self.base))
        expected = Counter()
        for case in CASES:
            expected[case['helper_id']] += len(case['actions'])
        totals = {}
        for helper, count in sorted(expected.items()):
            with self.subTest(helper=helper):
                records = [e for e in self.replay if e['helper'] == helper]
                self.assertEqual(len(records), count)
                self.assertEqual(self.base[helper]['total_actions'], count)
                for dimension, field in (('tools', 'tool'), ('folders', 'folder'),
                                         ('actions', 'action')):
                    counted = Counter(e[field] for e in records if e[field] is not None)
                    self.assertEqual(self.base[helper][dimension], dict(counted))
                alarms = Counter()
                for index, event in enumerate(self.replay):
                    if event['helper'] != helper:
                        continue
                    prefix = self.replay[:index + 1]
                    signals = (
                        ('window', helper_pattern(helper, prefix, self.minute_base, event['timestamp'])),
                        ('daily', daily_volume_pattern(helper, prefix, self.base, event['timestamp'])),
                    )
                    for name, signal in signals:
                        alarms[name + '_checks'] += 1
                        alarms[name + '_high'] += signal.level == 'high'
                        alarms[name + '_low'] += signal.level == 'low'
                        self.assertEqual(signal.level, 'normal')
                        self.assertEqual(signal.baseline_status, 'known')
                        self.assertEqual(signal.reasons, ())
                final = helper_pattern(helper, self.replay, self.minute_base,
                                       self.replay[-1]['timestamp'])
                for dimension, field in (('tools', 'tool'), ('folders', 'folder'),
                                         ('actions', 'action')):
                    self.assertEqual(dict(getattr(final, dimension)),
                                     dict(Counter(e[field] for e in records
                                                  if e[field] is not None)))
                self.assertEqual(daily_volume_pattern(helper, self.replay, self.base,
                                 self.replay[-1]['timestamp']).total_actions, count)
                self.assertEqual(alarms['window_checks'], count)
                self.assertEqual(alarms['daily_checks'], count)
                totals[helper] = dict(alarms)
        all_calls = Counter()
        for counts in totals.values():
            all_calls.update(counts)
        self.assertEqual(all_calls['window_checks'], len(self.replay))
        self.assertEqual(all_calls['daily_checks'], len(self.replay))
        self.assertEqual(sum(all_calls[k] for k in
                         ('window_high', 'window_low', 'daily_high', 'daily_low')), 0)
        self.assertEqual((self.source, self.replay, self.base), before)
        print('synthetic plan replay; per-helper totals:', totals)
        print('synthetic plan replay; all calls:', len(self.replay), dict(all_calls))

    def test_inserted_unknown_tool_and_folder_are_low(self):
        for field, value, reason in (
            ('tool', 'synthetic_unknown_tool', 'unknown_tool:synthetic_unknown_tool'),
            ('folder', 'synthetic_unknown_folder', 'unknown_folder:synthetic_unknown_folder'),
        ):
            with self.subTest(field=field):
                inserted = dict(self.replay[0], **{field: value})
                records = self.replay + [inserted]
                signal = helper_pattern(inserted['helper'], records, self.minute_base,
                                        self.replay[-1]['timestamp'])
                self.assertEqual(signal.level, 'low')
                self.assertEqual(signal.reasons, (reason,))
                self.assertEqual(signal.instruction, 'observe_helper')
                self.assertEqual(daily_volume_pattern(inserted['helper'], records,
                                 self.base, self.replay[-1]['timestamp']).level, 'normal')

    def test_inflated_daily_volume_without_window_burst(self):
        for helper, baseline in sorted(self.base.items()):
            normal = baseline['total_actions']
            boundary = max(19, 3 * normal)
            template = next(e for e in self.replay if e['helper'] == helper)
            records = [dict(template, timestamp=START + timedelta(seconds=61 * i))
                       for i in range(boundary + 1)]
            with self.subTest(helper=helper):
                at_boundary = daily_volume_pattern(helper, records[:-1], self.base,
                                                   records[-2]['timestamp'])
                self.assertEqual(at_boundary.total_actions, boundary)
                self.assertEqual(at_boundary.level, 'normal')
                inflated = daily_volume_pattern(helper, records, self.base,
                                                records[-1]['timestamp'])
                self.assertEqual(inflated.total_actions, boundary + 1)
                self.assertEqual(inflated.level, 'high')
                self.assertEqual(inflated.reasons, ('daily_volume',))
                self.assertEqual(inflated.instruction, 'review_helper')
                window = helper_pattern(helper, records, self.minute_base, records[-1]['timestamp'])
                self.assertEqual(window.level, 'normal')
                self.assertEqual(sum(dict(window.tools).values()), 1)


if __name__ == '__main__':
    unittest.main()
