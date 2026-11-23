"""Pure alarm state, not actual enforcement.

Callers must persist transitions atomically, authenticate the owner before
asserting owner_authorized, and enforce helper holds at their execution boundary.
No database, global freeze, automatic release, expiry, or alert consumption occurs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from .helper_pattern import DailyVolumePattern, HelperPattern

SINGAPORE = ZoneInfo("Asia/Singapore")


def _helper(helper):
    if not isinstance(helper, str) or not helper.strip():
        raise ValueError("helper must be a nonempty string")


def _reasons(reasons):
    if not isinstance(reasons, tuple) or any(
        not isinstance(reason, str) or not reason.strip() for reason in reasons
    ):
        raise ValueError("reasons must be a tuple of nonempty strings")


def _today(now):
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now must be an aware datetime")
    return now.astimezone(SINGAPORE).date()


@dataclass(frozen=True)
class AlarmState:
    frozen_helpers: frozenset[str] = frozenset()
    low_alerts: tuple[tuple[str, tuple[str, ...], date], ...] = ()

    def __post_init__(self):
        if not isinstance(self.frozen_helpers, frozenset):
            raise ValueError("frozen_helpers must be a frozenset")
        for helper in self.frozen_helpers:
            _helper(helper)
        if not isinstance(self.low_alerts, tuple):
            raise ValueError("low_alerts must be a tuple")
        for alert in self.low_alerts:
            if not isinstance(alert, tuple) or len(alert) != 3:
                raise ValueError("alerts must contain helper, reasons, due_date")
            helper, reasons, due_date = alert
            _helper(helper)
            _reasons(reasons)
            if type(due_date) is not date:
                raise ValueError("due_date must be a calendar date")


def _state(state):
    if not isinstance(state, AlarmState):
        raise ValueError("state must be an AlarmState")


def apply_alarm(
    state: AlarmState, pattern: HelperPattern | DailyVolumePattern, now: datetime
) -> AlarmState:
    """Latch only the high helper; queue unique low alerts for tomorrow."""
    _state(state)
    today = _today(now)
    if not isinstance(pattern, (HelperPattern, DailyVolumePattern)):
        raise ValueError("pattern must be a HelperPattern or DailyVolumePattern")
    _helper(pattern.helper)
    if not isinstance(pattern.level, str) or pattern.level not in (
        "high", "low", "normal", "unknown"
    ):
        raise ValueError("level must be high, low, normal, or unknown")
    _reasons(pattern.reasons)
    if pattern.level == "high":
        return AlarmState(state.frozen_helpers | {pattern.helper}, state.low_alerts)
    if pattern.level == "low":
        alert = (pattern.helper, pattern.reasons, today + timedelta(days=1))
        if alert not in state.low_alerts:
            return AlarmState(state.frozen_helpers, state.low_alerts + (alert,))
    return state


def helper_is_frozen(state: AlarmState, helper: str) -> bool:
    """Query a hold; the caller must implement actual enforcement."""
    _state(state)
    _helper(helper)
    return helper in state.frozen_helpers


def release_helper(
    state: AlarmState, helper: str, *, owner_authorized: bool
) -> AlarmState:
    """Release one helper only after caller-authenticated owner authorization."""
    if owner_authorized is not True:
        raise PermissionError("owner authorization must be exactly True")
    _state(state)
    _helper(helper)
    return AlarmState(state.frozen_helpers - {helper}, state.low_alerts)


def briefing_alerts(
    state: AlarmState, now: datetime
) -> tuple[tuple[str, tuple[str, ...], date], ...]:
    """Return due and overdue alerts without consuming missed briefings."""
    _state(state)
    today = _today(now)
    return tuple(alert for alert in state.low_alerts if alert[2] <= today)
