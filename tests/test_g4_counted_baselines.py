import copy
import unittest
from datetime import datetime, timedelta, timezone

from aegis.helper_pattern import build_normal_baselines, daily_volume_pattern, helper_pattern

NOW = datetime(2026, 1, 2, 1, tzinfo=timezone.utc)


def events(n, **changes):
    return [dict(dict(helper="a", timestamp=NOW, tool="read", folder="src",
                      action="read", refused=False), **changes) for _ in range(n)]


class CountedBaselineTests(unittest.TestCase):
    def test_daily_maxima_and_purity(self):
        runs = [events(4) + events(6, timestamp=NOW - timedelta(days=1), tool="write"),
                events(7) + events(3, helper="b")]
        before = copy.deepcopy(runs)
        base = build_normal_baselines(runs)
        self.assertEqual(base["a"], {"tools": {"read": 7, "write": 6},
                                    "folders": {"src": 7}, "actions": {"read": 7},
                                    "total_actions": 7, "period": "singapore_day"})
        self.assertEqual(base["b"]["total_actions"], 3)
        self.assertEqual(runs, before)
        self.assertEqual(base, build_normal_baselines(runs))
        self.assertEqual(build_normal_baselines([[], []]), {})

    def test_baseline_period_contracts(self):
        daily = build_normal_baselines([events(7)])
        daily['a']['period'] = 'singapore_day'
        with self.assertRaisesRegex(ValueError, 'minute window'):
            helper_pattern('a', events(7), daily, NOW)
        legacy = copy.deepcopy(daily)
        legacy['a'].pop('period', None)
        self.assertEqual(helper_pattern('a', events(7), legacy, NOW).level, 'normal')
        self.assertEqual(daily_volume_pattern('a', events(7), legacy, NOW).level, 'normal')
        minute = copy.deepcopy(legacy)
        minute['a']['period'] = '60_seconds'
        self.assertEqual(helper_pattern('a', events(7), minute, NOW).level, 'normal')
        for period in ('60_seconds', 'other', None):
            with self.subTest(period=period):
                incompatible = {'a': dict(legacy['a'], period=period)}
                with self.assertRaises(ValueError):
                    daily_volume_pattern('a', [], incompatible, NOW)

    def test_midnight_and_future(self):
        midnight = NOW.replace(hour=16) - timedelta(days=1)
        records = events(9, timestamp=midnight - timedelta(microseconds=1))
        records += events(2, timestamp=midnight)
        self.assertEqual(build_normal_baselines([records])["a"]["total_actions"], 9)
        records += events(50, timestamp=NOW + timedelta(microseconds=1))
        records += events(50, helper="b")
        result = daily_volume_pattern("a", records, {}, NOW)
        self.assertEqual(result.total_actions, 2)
        self.assertEqual(result.level, "unknown")

    def test_thresholds_unknown_zero_and_purity(self):
        for n, normal, level in ((19, 0, "normal"), (20, 0, "high"),
                                 (21, 7, "normal"), (22, 7, "high"),
                                 (100, None, "unknown")):
            base, records = {"a": {"total_actions": normal}}, events(n)
            before = copy.deepcopy((base, records))
            result = daily_volume_pattern("a", records, base, NOW)
            self.assertEqual(result.level, level)
            self.assertEqual(result.total_actions, n)
            self.assertEqual(result.reasons, ("daily_volume",) if level == "high" else ())
            self.assertEqual((base, records), before)
            self.assertEqual(result, daily_volume_pattern("a", records, base, NOW))
        for base in ({}, {"a": None}, {"a": {}}):
            self.assertEqual(daily_volume_pattern("a", events(30), base, NOW).level, "unknown")

    def test_optional_and_refused(self):
        records = events(20, tool=None, folder=None, action=None)
        base = build_normal_baselines([records])
        self.assertEqual(base["a"]["tools"], {})
        self.assertEqual(base["a"]["total_actions"], 20)
        records = events(20, refused=True)
        with self.assertRaises(ValueError):
            build_normal_baselines([records])
        self.assertEqual(daily_volume_pattern("a", records, base, NOW).level, "normal")

    def test_invalid_inputs(self):
        bad = [None, [], {}, {"helper": "a"}]
        for field, value in (("helper", ""), ("timestamp", NOW.replace(tzinfo=None)),
                             ("refused", 1), ("tool", []), ("folder", " "), ("action", 0)):
            bad.append(dict(events(1)[0], **{field: value}))
        for event in bad:
            with self.subTest(event=event):
                with self.assertRaises(ValueError):
                    build_normal_baselines([[event]])
                with self.assertRaises(ValueError):
                    daily_volume_pattern("a", [event], {}, NOW)
        for runs in (None, {}, "abc", [None], [{}], ["abc"]):
            with self.assertRaises(ValueError):
                build_normal_baselines(runs)
        for base in (None, [], {"a": []}, {"a": {"tools": []}},
                     {"a": {"total_actions": True}}, {"a": {"total_actions": -1}},
                     {"a": {"total_actions": float("nan")}},
                     {"a": {"actions": {"unused": "1"}}}):
            with self.assertRaises(ValueError):
                daily_volume_pattern("a", [], base, NOW)
        for helper, now in (("", NOW), (True, NOW), ("a", None),
                            ("a", NOW.replace(tzinfo=None))):
            with self.assertRaises(ValueError):
                daily_volume_pattern(helper, [], {}, now)


if __name__ == "__main__":
    unittest.main()
