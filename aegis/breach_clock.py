"""Pure G2 reminder projection; no determination, reporting, or sending.

breach_clock(credible_grounds, determination, now, records=()) accepts aware
 datetimes or None. Day one is the next Asia/Singapore calendar date. Deadlines
are the end of day 30 (assessment) and day 3 (notification), not rolling hours.
The caller supplies determination; facts never establish notifiability.
Source attribution is to the supplied PDPC guidance, not live verification.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Mapping, Sequence
from zoneinfo import ZoneInfo

SG = ZoneInfo("Asia/Singapore")
SOURCE = "PDPC Guide on Managing and Notifying Data Breaches, 15 March 2021"
NOTICE = "reminder, not legal advice"


@dataclass(frozen=True)
class Reminder:
    first_day: date | None
    deadline_date: date | None
    days_remaining: int | None
    status: str


@dataclass(frozen=True)
class StepRecord:
    timestamp: datetime | None
    step: str | None
    actor: str | None
    facts: tuple


@dataclass(frozen=True)
class BreachClock:
    assessment: Reminder
    notification: Reminder
    records: tuple[StepRecord, ...]
    notice: str = NOTICE
    source: str = SOURCE


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("timestamp must be an aware datetime or None")
    try:
        return value.astimezone(SG)
    except (OverflowError, ValueError):
        raise ValueError('Timestamp outside supported reminder range') from None


def _freeze(value):
    if isinstance(value, Mapping):
        return tuple((_freeze(key), _freeze(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, bool, int, float, date)):
        return value
    raise ValueError("facts must contain plain immutable values or containers")


def _reminder(trigger: datetime | None, now: datetime | None, days: int) -> Reminder:
    if trigger is None:
        return Reminder(None, None, None, "unknown")
    start = trigger.date()
    try:
        deadline = start + timedelta(days=days)
    except OverflowError:
        raise ValueError('Timestamp outside supported reminder range') from None
    remaining = None if now is None else (deadline - now.date()).days
    status = "unknown" if remaining is None else (
        "overdue" if remaining < 0 else "due_today" if remaining == 0 else "pending"
    )
    return Reminder(start + timedelta(days=1), deadline, remaining, status)


def breach_clock(
    credible_grounds: datetime | None,
    determination: datetime | None,
    now: datetime | None,
    records: Sequence[Mapping] = (),
) -> BreachClock:
    """Return frozen reminders and ordered timestamp/step/actor/fact records.

    Only non-None count/data/harm facts are copied; zero and False are known.
    Missing now leaves status unknown even when the deadline date is known.
    No system clock, persistence, threshold inference, or external action occurs.
    """
    grounds, determined, current = map(_aware, (credible_grounds, determination, now))
    for record in records:
        for field in ("step", "actor"):
            value = record.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{field} must be a string or None")
    projected = tuple(
        StepRecord(
            _aware(record.get("timestamp")),
            _freeze(record.get("step")),
            _freeze(record.get("actor")),
            tuple((key, _freeze(record[key])) for key in ("count", "data", "harm")
                  if record.get(key) is not None),
        )
        for record in records
    )
    return BreachClock(
        _reminder(grounds, current, 30),
        _reminder(determined, current, 3),
        projected,
    )
