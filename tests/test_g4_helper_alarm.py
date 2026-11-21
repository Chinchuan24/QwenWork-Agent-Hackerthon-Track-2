import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime, timedelta, timezone

from aegis.helper_alarm import AlarmState, apply_alarm, briefing_alerts, helper_is_frozen, release_helper
from aegis.helper_pattern import DailyVolumePattern, HelperPattern

NOW = datetime(2026, 1, 1, 16, tzinfo=timezone.utc)


def pattern(kind=HelperPattern, helper="a", level="high", reasons=("volume",)):
    if kind is DailyVolumePattern:
        return kind(helper, 30, "known", level, reasons, "review_helper")
    return kind(helper, (), (), (), 5, "known", level, reasons, "review_helper")


class HelperAlarmTests(unittest.TestCase):
    def test_high_local_latched_repeatable(self):
        for kind in (HelperPattern, DailyVolumePattern):
            original = AlarmState()
            state = apply_alarm(original, pattern(kind), NOW)
            self.assertEqual(original, AlarmState())
            self.assertEqual(state.frozen_helpers, frozenset({"a"}))
            self.assertFalse(helper_is_frozen(state, "b"))
            self.assertEqual(apply_alarm(state, pattern(kind), NOW), state)
            for level in ("normal", "unknown", "low"):
                state = apply_alarm(state, pattern(kind, level=level), NOW + timedelta(days=400))
                self.assertTrue(helper_is_frozen(state, "a"))

    def test_low_dates_dedup_and_missed_briefing(self):
        for kind in (HelperPattern, DailyVolumePattern):
            low = pattern(kind, level="low")
            before = NOW - timedelta(microseconds=1)
            state = apply_alarm(AlarmState(), low, before)
            self.assertEqual(state.low_alerts, (("a", ("volume",), date(2026, 1, 2)),))
            self.assertEqual(apply_alarm(state, low, before), state)
            state = apply_alarm(state, low, NOW)
            state = apply_alarm(state, replace(low, helper="b"), NOW)
            state = apply_alarm(state, replace(low, reasons=("other",)), NOW)
            self.assertEqual(len(state.low_alerts), 4)
            self.assertEqual(state.frozen_helpers, frozenset())
            self.assertEqual(briefing_alerts(state, before), ())
            self.assertEqual(briefing_alerts(state, NOW), state.low_alerts[:1])
            self.assertEqual(briefing_alerts(state, NOW + timedelta(days=20)), state.low_alerts)
            self.assertEqual(len(state.low_alerts), 4)

    def test_normal_unknown_no_hold(self):
        for kind in (HelperPattern, DailyVolumePattern):
            for level in ("normal", "unknown"):
                self.assertEqual(apply_alarm(AlarmState(), pattern(kind, level=level), NOW), AlarmState())

    def test_release_exact_true_retains_others_and_alerts(self):
        state = apply_alarm(AlarmState(), pattern(level="low"), NOW)
        for helper in ("a", "b"):
            state = apply_alarm(state, pattern(helper=helper), NOW)
        for value in (False, None, 1, "yes", [], {}):
            with self.subTest(value=value), self.assertRaises(PermissionError):
                release_helper(state, "a", owner_authorized=value)
        released = release_helper(state, "a", owner_authorized=True)
        self.assertEqual(released.frozen_helpers, frozenset({"b"}))
        self.assertEqual(released.low_alerts, state.low_alerts)
        self.assertEqual(state.frozen_helpers, frozenset({"a", "b"}))
        self.assertEqual(release_helper(released, "absent", owner_authorized=True), released)
        with self.assertRaises(TypeError):
            release_helper(state, "a")

    def test_immutable_state(self):
        state = AlarmState()
        with self.assertRaises(FrozenInstanceError):
            state.frozen_helpers = frozenset({"a"})
        for kwargs in ({"frozen_helpers": {"a"}}, {"low_alerts": []},
                       {"frozen_helpers": frozenset({""})},
                       {"low_alerts": (("a", ["reason"], date(2026, 1, 1)),)},
                       {"low_alerts": (("a", (), NOW),)}):
            with self.assertRaises(ValueError):
                AlarmState(**kwargs)

    def test_boundary_validation(self):
        for now in (None, "today", NOW.replace(tzinfo=None)):
            with self.assertRaises(ValueError):
                apply_alarm(AlarmState(), pattern(), now)
            with self.assertRaises(ValueError):
                briefing_alerts(AlarmState(), now)
        for helper in (None, True, 1, "", "   ", [], {}):
            with self.assertRaises(ValueError):
                apply_alarm(AlarmState(), pattern(helper=helper), NOW)
            with self.assertRaises(ValueError):
                helper_is_frozen(AlarmState(), helper)
            with self.assertRaises(ValueError):
                release_helper(AlarmState(), helper, owner_authorized=True)
        for level in (None, True, "HIGH", "", [], {}):
            with self.assertRaises(ValueError):
                apply_alarm(AlarmState(), pattern(level=level), NOW)
        for reasons in (["reason"], ([],), ("",)):
            with self.assertRaises(ValueError):
                apply_alarm(AlarmState(), pattern(reasons=reasons), NOW)
        with self.assertRaises(ValueError):
            apply_alarm(AlarmState(), object(), NOW)
        for call in (lambda: apply_alarm(None, pattern(), NOW),
                     lambda: helper_is_frozen(None, "a"),
                     lambda: release_helper(None, "a", owner_authorized=True),
                     lambda: briefing_alerts(None, NOW)):
            with self.assertRaises(ValueError):
                call()
