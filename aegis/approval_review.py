"""Pure review of supplied stored approvals and audit events; never authorizes.

Records use id, decision (approve/reject/change), decided_at, viewed_at,
decided_by, high_risk (explicit bool), and reason. Existing claimed/executed/
approved and denied statuses are supported. Audit events use event, ts and
 detail/detail_json with approval, by and the same decision metadata.
Stored records take precedence over events for the same approval. The latest
view at or before the decision by its reviewer is used. Missing/invalid timing
is unknown, not request-to-decision time. Callers own history scope and trust.
Reason coverage measures nonblank presence, not correctness or quality.
"""
import json
import math
from collections.abc import Iterable, Mapping

MIN_DECISIONS = 10
APPROVAL_RATIO = 0.9
FAST_RATIO = 0.9
FAST_SECONDS = 10.0


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def build_approval_review(records: Iterable[Mapping], events: Iterable[Mapping] = (), *,
                          min_decisions=MIN_DECISIONS, approval_ratio=APPROVAL_RATIO,
                          fast_ratio=FAST_RATIO, fast_seconds=FAST_SECONDS) -> dict:
    """Return aggregate facts only, without I/O, AI, clock reads or speed gates.

    decision_seconds follows approval ID sort order. Unknown values are None.
    Both warning ratios use all decisions, including those with unknown timing.
    Event-only approvals use the latest decision; equal-time conflicts raise.
    Duplicate stored approval IDs raise rather than inflate decision counts.
    """
    if (isinstance(min_decisions, bool) or not isinstance(min_decisions, int)
            or min_decisions < 1 or not _number(fast_seconds) or fast_seconds <= 0
            or any(not _number(r) or not 0 <= r <= 1
                   for r in (approval_ratio, fast_ratio))):
        raise ValueError('Invalid review thresholds')
    approvals = {}
    for source in records:
        row = dict(source)
        aid = row['id']
        if not isinstance(aid, str) or not aid or aid in approvals:
            raise ValueError('Approval IDs must be unique nonempty strings')
        approvals[aid] = row
    stored_ids = set(approvals)
    views = {}
    for source in events:
        event = dict(source)
        detail = event.get('detail')
        if detail is None:
            try:
                detail = json.loads(event.get('detail_json', '{}'))
            except (ValueError, TypeError):
                continue
        if not isinstance(detail, dict):
            continue
        aid, ts = detail.get('approval'), event.get('ts')
        if not isinstance(aid, str) or not aid or not _number(ts):
            continue
        if event.get('event') == 'approval_screen_viewed':
            views.setdefault(aid, []).append((ts, detail.get('by')))
        elif event.get('event') == 'approval_decided' and aid not in stored_ids:
            row = dict(detail, id=aid, decided_at=ts, decided_by=detail.get('by'))
            previous = approvals.get(aid)
            if previous is None or ts > previous['decided_at']:
                approvals[aid] = row
            elif ts == previous['decided_at'] and row != previous:
                raise ValueError('Conflicting approval decisions')
    counts = dict(approve=0, reject=0, change=0)
    seconds = []
    high_risk = with_reason = fast = 0
    statuses = dict(claimed='approve', executed='approve', approved='approve',
                    denied='reject')
    for aid, row in sorted(approvals.items()):
        decision = row.get('decision') or statuses.get(row.get('status'))
        if decision not in counts:
            continue
        counts[decision] += 1
        end = row.get('decided_at')
        start = row.get('viewed_at')
        reviewer = row.get('decided_by')
        candidates = [ts for ts, who in views.get(aid, [])
                      if reviewer and _number(end) and ts <= end and who == reviewer]
        if _number(start) and _number(end) and start <= end:
            candidates.append(start)
        elapsed = end - max(candidates) if candidates else None
        if elapsed is not None and not _number(elapsed):
            elapsed = None
        seconds.append(elapsed)
        fast += elapsed is not None and elapsed < fast_seconds
        if row.get('high_risk') is True:
            high_risk += 1
            reason = row.get('reason')
            with_reason += isinstance(reason, str) and bool(reason.strip())
    total = sum(counts.values())
    warning = None
    if (total >= min_decisions and counts['approve'] / total >= approval_ratio
            and fast / total >= fast_ratio):
        warning = (f'{counts["approve"]} of {total} decisions were approvals; '
                   f'{fast} of {total} had a recorded screen-view-to-decision time '
                   f'under {fast_seconds:g} seconds. This pattern may warrant review; '
                   'it does not establish review quality and does not block decisions.')
    return dict(counts=counts, decision_seconds=seconds,
                high_risk_decisions=high_risk, high_risk_with_reason=with_reason,
                high_risk_reason_coverage=with_reason / high_risk if high_risk else None,
                warning=warning)
