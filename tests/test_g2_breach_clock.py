import unittest
from dataclasses import FrozenInstanceError
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from aegis.breach_clock import breach_clock

SG = ZoneInfo("Asia/Singapore")


class BreachClockTests(unittest.TestCase):
    def test_overflow_sanitized(self):
        maximum = datetime.max.replace(tzinfo=timezone.utc)
        for args in ((maximum, None, None), (None, maximum, None),
                     (None, None, maximum),
                     (maximum.replace(tzinfo=SG), None, None),
                     (None, maximum.replace(tzinfo=SG), None)):
            with self.subTest(args=args):
                with self.assertRaisesRegex(ValueError, 'supported reminder range'):
                    breach_clock(*args)
        with self.assertRaisesRegex(ValueError, 'supported reminder range'):
            breach_clock(None, None, None, [{'timestamp': maximum}])

    def test_month_year_leap_boundaries(self):
        for text, assessment, notification in (
            ("2026-01-31T23:59:00+08:00", date(2026, 3, 2), date(2026, 2, 3)),
            ("2026-12-31T00:00:00+08:00", date(2027, 1, 30), date(2027, 1, 3)),
            ("2024-02-28T23:59:00+08:00", date(2024, 3, 29), date(2024, 3, 2)),
        ):
            with self.subTest(text=text):
                start = datetime.fromisoformat(text)
                result = breach_clock(start, start, start)
                self.assertEqual(result.assessment.deadline_date, assessment)
                self.assertEqual(result.notification.deadline_date, notification)
                self.assertEqual(result.notification.first_day, start.date() + timedelta(days=1))

    def test_end_of_calendar_date_not_72_hours(self):
        start = datetime(2026, 11, 19, 0, 1, tzinfo=SG)
        for now, status in (
            (datetime(2026, 11, 22, 0, 2, tzinfo=SG), "due_today"),
            (datetime(2026, 11, 22, 23, 59, 59, 999999, tzinfo=SG), "due_today"),
            (datetime(2026, 11, 23, tzinfo=SG), "overdue"),
        ):
            self.assertEqual(breach_clock(start, start, now).notification.status, status)

    def test_utc_singapore_midnight(self):
        start = datetime(2026, 12, 31, 16, tzinfo=timezone.utc)
        result = breach_clock(start, start, start)
        self.assertEqual(result.assessment.deadline_date, date(2027, 1, 31))
        self.assertEqual(result.notification.deadline_date, date(2027, 1, 4))
        self.assertEqual(result.notification.days_remaining, 3)
        self.assertEqual(result.notification.status, "pending")

    def test_assessment_midnight(self):
        start = datetime(2026, 11, 19, 20, tzinfo=SG)
        for now, status in (
            (datetime(2026, 12, 19, 23, 59, tzinfo=SG), "due_today"),
            (datetime(2026, 12, 20, tzinfo=SG), "overdue"),
        ):
            self.assertEqual(breach_clock(start, None, now).assessment.status, status)

    def test_no_determination_never_inferred(self):
        now = datetime(2026, 11, 19, tzinfo=SG)
        result = breach_clock(now, None, now, [{"step": "review", "count": 9999, "harm": True}])
        self.assertEqual(result.notification.status, "unknown")
        self.assertIsNone(result.notification.deadline_date)
        self.assertIsNone(result.notification.first_day)
        self.assertIsNone(result.notification.days_remaining)
        self.assertEqual(result.notice, "reminder, not legal advice")
        self.assertEqual(result.source, "PDPC Guide on Managing and Notifying Data Breaches, 15 March 2021")

    def test_unknown_inputs(self):
        result = breach_clock(None, None, None)
        self.assertEqual(result.assessment.status, "unknown")
        self.assertIsNone(result.assessment.deadline_date)
        result = breach_clock(datetime(2026, 1, 1, tzinfo=SG), None, None)
        self.assertEqual(result.assessment.deadline_date, date(2026, 1, 31))
        self.assertEqual(result.assessment.status, "unknown")
        self.assertIsNone(result.assessment.days_remaining)

    def test_naive_rejected(self):
        aware = datetime(2026, 1, 1, tzinfo=SG)
        naive = aware.replace(tzinfo=None)
        for args in ((naive, aware, aware), (aware, naive, aware), (aware, aware, naive)):
            with self.assertRaisesRegex(ValueError, "aware"):
                breach_clock(*args)
        with self.assertRaisesRegex(ValueError, "aware"):
            breach_clock(None, None, aware, [{"timestamp": naive}])

    def test_malformed_mapping_keys_rejected(self):
        class MutableKey:
            pass

        for key in (MutableKey(), ("nested", MutableKey())):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "facts"):
                    breach_clock(None, None, None, [{"data": {key: "email"}}])

    def test_step_actor_require_string_or_none(self):
        for field in ("step", "actor"):
            for value in (0, False, [], {}, ("owner",), {"owner"}):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, field):
                        breach_clock(None, None, None, [{field: value}])

    def test_valid_mapping_keys_and_step_actor_preserved(self):
        result = breach_clock(None, None, None, [
            {"step": "", "actor": "owner", "data": {("email", 0): [False]}},
            {"step": None, "actor": None},
        ])
        self.assertEqual(result.records[0].step, "")
        self.assertEqual(result.records[0].actor, "owner")
        self.assertEqual(result.records[0].facts, (("data", ((("email", 0), (False,)),)),))
        self.assertIsNone(result.records[1].step)
        self.assertIsNone(result.records[1].actor)

    def test_immutable_ordered_projection(self):
        now = datetime(2026, 1, 1, tzinfo=SG)
        records = [{"timestamp": now, "step": "assess", "actor": "owner", "count": 0,
                    "data": ["email"], "harm": False, "decision": "notify", "secret": "omit"},
                   {"step": "review", "count": None}]
        result = breach_clock(None, None, now, records)
        records[0]["data"].append("phone")
        records[0]["count"] = 500
        self.assertEqual(result.records[0].facts, (("count", 0), ("data", ("email",)), ("harm", False)))
        self.assertEqual(result.records[1].facts, ())
        self.assertEqual(result.records[1].step, "review")
        with self.assertRaises(FrozenInstanceError):
            result.records[0].step = "sent"
        with self.assertRaises(FrozenInstanceError):
            result.notice = "legal advice"
        self.assertEqual(breach_clock(None, None, now), breach_clock(None, None, now))


if __name__ == "__main__":
    unittest.main()
