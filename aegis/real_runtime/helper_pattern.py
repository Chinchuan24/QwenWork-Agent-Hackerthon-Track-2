"""Pure per-helper count projection, with no enforcement or global state."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping, Sequence

from zoneinfo import ZoneInfo

SINGAPORE = ZoneInfo("Asia/Singapore")
WINDOW_SECONDS = 60
REFUSED_THRESHOLD = 5
BASELINE_MULTIPLIER = 3
MINIMUM_VOLUME = 20


@dataclass(frozen=True)
class HelperPattern:
    helper: str
    tools: tuple[tuple[str, int], ...]
    folders: tuple[tuple[str, int], ...]
    actions: tuple[tuple[str, int], ...]
    refused: int
    baseline_status: str
    level: str
    reasons: tuple[str, ...]
    instruction: str


@dataclass(frozen=True)
class DailyVolumePattern:
    helper: str
    total_actions: int
    baseline_status: str
    level: str
    reasons: tuple[str, ...]
    instruction: str


def _sequence(value):
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("event runs and events must be sequences")
    return value


def _identifier(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")


def _aware(value):
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("timestamp and now must be aware datetimes")


def _validated_events(events, training=False):
    for event in _sequence(events):
        if not isinstance(event, Mapping):
            raise ValueError("events must be mappings")
        _identifier(event.get("helper"), "helper")
        _aware(event.get("timestamp"))
        if not isinstance(event.get("refused"), bool):
            raise ValueError("refused must be a boolean")
        if training and event["refused"]:
            raise ValueError("refused events cannot train normal baselines")
        for field in ("tool", "folder", "action"):
            if field not in event:
                raise ValueError(f"event must supply {field}, optionally None")
            if event[field] is not None:
                _identifier(event[field], field)
        yield event


def build_normal_baselines(runs: Sequence[Sequence[Mapping]]) -> dict:
    """Count explicitly trusted normal runs, never discover or invent samples.

    Each run is a separate sample, partitioned by helper and Singapore date.
    Return per-helper tools/folders/actions maxima and total_actions maximum
    across those samples. Missing identifiers contribute only to the total;
    absent helpers/keys remain unknown rather than receiving invented zeros.
    Every observation counts once, even if its action identifier is None.
    Reject any refused event, including events belonging to other helpers.
    Trust and sample completeness are the caller's responsibility.
    """
    baselines = {}
    for run in _sequence(runs):
        days = {}
        for event in _validated_events(run, training=True):
            key = (event["helper"], event["timestamp"].astimezone(SINGAPORE).date())
            sample = days.setdefault(key, {"tools": Counter(), "folders": Counter(),
                                           "actions": Counter(), "total_actions": 0})
            sample["total_actions"] += 1
            for dimension, field in (("tools", "tool"), ("folders", "folder"),
                                     ("actions", "action")):
                if event[field] is not None:
                    sample[dimension][event[field]] += 1
        for (helper, day), sample in days.items():
            baseline = baselines.setdefault(helper, {"tools": {}, "folders": {},
                                                      "actions": {}, "total_actions": 0,
                                                      "period": "singapore_day"})
            baseline["total_actions"] = max(baseline["total_actions"], sample["total_actions"])
            for dimension in ("tools", "folders", "actions"):
                for value, count in sample[dimension].items():
                    baseline[dimension][value] = max(baseline[dimension].get(value, 0), count)
    return baselines


def _validate_daily_baselines(baselines):
    if not isinstance(baselines, Mapping):
        raise ValueError("baselines must be a mapping")
    for helper, baseline in baselines.items():
        _identifier(helper, "helper")
        if baseline is None:
            continue
        if not isinstance(baseline, Mapping):
            raise ValueError("helper baseline must be a mapping or None")
        if "period" in baseline and baseline["period"] != "singapore_day":
            raise ValueError("daily baseline period must be singapore_day")
        values = [baseline.get("total_actions")]
        for dimension in ("tools", "folders", "actions"):
            normal = baseline.get(dimension)
            if normal is None:
                continue
            if not isinstance(normal, Mapping):
                raise ValueError("baseline dimensions must be mappings or None")
            for key in normal:
                _identifier(key, dimension)
            values.extend(normal.values())
        for value in values:
            if value is not None and (isinstance(value, bool) or
                    not isinstance(value, (int, float)) or not 0 <= value < float("inf")):
                raise ValueError("baseline counts must be nonnegative finite numbers or None")


def daily_volume_pattern(helper: str, events: Sequence[Mapping],
                         baselines: Mapping, now: datetime) -> DailyVolumePattern:
    """Compare Singapore today's observations through now to daily total.

    Missing helper, total_actions or None means unknown, not zero. Explicit
    zero is known. High requires at least 20 observations and strictly more
    than 3x normal total. Refused observations count but do not independently
    trigger this daily signal. All supplied events/baselines are validated.
    """
    _identifier(helper, "helper")
    _aware(now)
    _validate_daily_baselines(baselines)
    today = now.astimezone(SINGAPORE).date()
    total = sum(1 for event in _validated_events(events)
                if event["helper"] == helper and event["timestamp"] <= now
                and event["timestamp"].astimezone(SINGAPORE).date() == today)
    baseline = baselines.get(helper)
    normal = None if baseline is None else baseline.get("total_actions")
    unknown = normal is None
    high = not unknown and total >= MINIMUM_VOLUME and total > BASELINE_MULTIPLIER * normal
    return DailyVolumePattern(helper, total, "unknown" if unknown else "known",
                              "high" if high else "unknown" if unknown else "normal",
                              ("daily_volume",) if high else (),
                              "review_helper" if high else
                              "establish_baseline" if unknown else "continue")


def helper_pattern(
    helper: str,
    events: Sequence[Mapping],
    baselines: Mapping,
    now: datetime,
) -> HelperPattern:
    """Compare counts in inclusive [now - 60 seconds, now] to normal counts.

    Events contain helper, aware timestamp, tool, folder, action and refused.
    Baselines map helper IDs to tools/folders/actions maps of normal counts
    for the same window. An absent map or None count is unknown, never zero.
    An unseen tool/folder in a known map is low; unseen actions are unknown.
    High means five refusals or a known count exceeded threefold with at
    least twenty observations. Instructions are advice to the caller only.
    """
    if not isinstance(helper, str) or not helper.strip():
        raise ValueError("helper must be a nonempty string")
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("now must be an aware datetime")
    start = now - timedelta(seconds=WINDOW_SECONDS)
    counts = {name: Counter() for name in ("tools", "folders", "actions")}
    refused = 0
    for event in events:
        if event.get("helper") != helper:
            continue
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, datetime) or timestamp.utcoffset() is None:
            raise ValueError("timestamp must be an aware datetime")
        if not start <= timestamp <= now:
            continue
        if not isinstance(event.get("refused"), bool):
            raise ValueError("refused must be a boolean")
        refused += event["refused"]
        for dimension, field in (("tools", "tool"), ("folders", "folder"),
                                 ("actions", "action")):
            value = event.get(field)
            if value is not None:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{field} must be a nonempty string or None")
                counts[dimension][value] += 1

    baseline = baselines.get(helper)
    if baseline is not None and baseline.get("period") == "singapore_day":
        raise ValueError("daily baseline cannot be used here; a minute window baseline is needed")
    unknown = baseline is None
    low, high = [], []
    if refused >= REFUSED_THRESHOLD:
        high.append("refused_threshold")
    for dimension, singular in (("tools", "tool"), ("folders", "folder"),
                                ("actions", "action")):
        normal = None if baseline is None else baseline.get(dimension)
        if normal is None:
            unknown = True
            continue
        for expected in normal.values():
            if expected is None:
                continue
            if isinstance(expected, bool) or not isinstance(expected, (int, float)):
                raise ValueError("baseline counts must be nonnegative finite numbers or None")
            if not 0 <= expected < float("inf"):
                raise ValueError("baseline counts must be nonnegative finite numbers or None")
        for value, count in sorted(counts[dimension].items()):
            if value not in normal:
                if dimension != "actions":
                    low.append(f"unknown_{singular}:{value}")
                else:
                    unknown = True
                continue
            expected = normal[value]
            if expected is None:
                unknown = True
                continue
            if count >= MINIMUM_VOLUME and count > BASELINE_MULTIPLIER * expected:
                high.append(f"volume_{singular}:{value}")
    level = "high" if high else "low" if low else "unknown" if unknown else "normal"
    instruction = "review_helper" if high else "observe_helper" if low else (
        "establish_baseline" if unknown else "continue"
    )
    return HelperPattern(
        helper, tuple(sorted(counts["tools"].items())),
        tuple(sorted(counts["folders"].items())),
        tuple(sorted(counts["actions"].items())), refused,
        "unknown" if unknown else "known", level, tuple(high + low), instruction,
    )
