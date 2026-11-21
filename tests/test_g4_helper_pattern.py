import unittest
from datetime import datetime, timedelta, timezone

from aegis.helper_pattern import helper_pattern

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def events(count, **changes):
    return [dict(dict(helper="a", timestamp=NOW, tool="read", folder="src",
                      action="read", refused=False), **changes) for _ in range(count)]


def baseline(count):
    return {"a": {"tools": {"read": count}, "folders": {"src": count},
                  "actions": {"read": count}}}


class HelperPatternTests(unittest.TestCase):
    def test_normal_no_alarms(self):
        result = helper_pattern("a", events(30), baseline(30), NOW)
        self.assertEqual(result.level, "normal")
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.instruction, "continue")
        self.assertEqual(result.tools, (("read", 30),))
        self.assertEqual(result.folders, (("src", 30),))
        self.assertEqual(result.actions, (("read", 30),))

    def test_unknown_tool_folder_low(self):
        base = {"a": {"tools": {}, "folders": {}, "actions": {"read": 10}}}
        result = helper_pattern("a", events(1), base, NOW)
        self.assertEqual(result.level, "low")
        self.assertEqual(result.reasons, ("unknown_tool:read", "unknown_folder:src"))

    def test_missing_baseline_is_unknown_not_zero(self):
        for base in ({}, {"a": {}}, {"a": None}):
            result = helper_pattern("a", events(100), base, NOW)
            self.assertEqual(result.level, "unknown")
            self.assertEqual(result.baseline_status, "unknown")

    def test_volume_boundaries_each_dimension(self):
        for dimension in ("tools", "folders", "actions"):
            for count, expected, level in ((19, 1, "normal"), (20, 7, "normal"),
                                           (21, 7, "normal"), (22, 7, "high"),
                                           (20, 0, "high")):
                with self.subTest(dimension=dimension, count=count, expected=expected):
                    base = baseline(100)
                    key = "src" if dimension == "folders" else "read"
                    base["a"][dimension][key] = expected
                    self.assertEqual(helper_pattern("a", events(count), base, NOW).level, level)

    def test_refusal_threshold_without_baseline(self):
        for count, level in ((4, "unknown"), (5, "high")):
            result = helper_pattern("a", events(count, refused=True), {}, NOW)
            self.assertEqual(result.level, level)
            self.assertEqual(result.refused, count)
        self.assertEqual(result.instruction, "review_helper")
        self.assertEqual(result.helper, "a")

    def test_helper_isolation_and_window(self):
        records = events(4, refused=True)
        records += [dict(records[0], helper="b") for _ in range(100)]
        records += [dict(records[0], timestamp=NOW - timedelta(seconds=60, microseconds=1)),
                    dict(records[0], timestamp=NOW + timedelta(microseconds=1))]
        self.assertEqual(helper_pattern("a", records, baseline(100), NOW).level, "normal")
        records.append(dict(records[0], timestamp=NOW - timedelta(seconds=60)))
        self.assertEqual(helper_pattern("a", records, baseline(100), NOW).level, "high")
        self.assertEqual(helper_pattern("a", records, baseline(100),
                                       NOW + timedelta(seconds=61)).refused, 0)

    def test_partial_baseline_and_unknown_action(self):
        base = {"a": {"tools": {"read": None}, "folders": {"src": 100}, "actions": {}}}
        result = helper_pattern("a", events(100), base, NOW)
        self.assertEqual(result.level, "unknown")
        self.assertEqual(result.reasons, ())

    def test_pure_repeatable_no_input_mutation(self):
        records, base = events(5, refused=True), baseline(10)
        before = repr((records, base))
        self.assertEqual(helper_pattern("a", records, base, NOW),
                         helper_pattern("a", records, base, NOW))
        self.assertEqual(repr((records, base)), before)

    def test_malformed_refused_rejected(self):
        for value in (None, 0, 1, "false", [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "refused"):
                helper_pattern("a", events(1, refused=value), baseline(10), NOW)

    def test_invalid_identifiers_rejected(self):
        for value in (True, 1, "", "   ", [], {}):
            with self.subTest(helper=value), self.assertRaisesRegex(ValueError, "helper"):
                helper_pattern(value, [], {}, NOW)
            for field in ("tool", "folder", "action"):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, field):
                    helper_pattern("a", events(1, **{field: value}), baseline(10), NOW)

    def test_invalid_baseline_counts_rejected_even_when_unobserved(self):
        for dimension in ("tools", "folders", "actions"):
            for value in (-1, True, False, "1", float("nan"), float("inf"), -float("inf")):
                for observed in (False, True):
                    base = baseline(10)
                    key = ("src" if dimension == "folders" else "read") if observed else "unused"
                    base["a"][dimension][key] = value
                    with self.subTest(dimension=dimension, value=value, observed=observed):
                        with self.assertRaisesRegex(ValueError, "baseline counts"):
                            helper_pattern("a", events(1), base, NOW)

    def test_optional_identifiers_remain_valid(self):
        result = helper_pattern("a", events(1, tool=None, folder=None, action=None),
                                baseline(None), NOW)
        self.assertEqual(result.tools, ())
        self.assertEqual(result.folders, ())
        self.assertEqual(result.actions, ())
        self.assertEqual(result.refused, 0)

    def test_naive_time_rejected(self):
        with self.assertRaisesRegex(ValueError, "aware"):
            helper_pattern("a", [], {}, NOW.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "aware"):
            helper_pattern("a", events(1, timestamp=NOW.replace(tzinfo=None)), {}, NOW)
