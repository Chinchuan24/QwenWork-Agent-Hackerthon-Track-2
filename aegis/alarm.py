"""C6 reminder and management boundary; no routes, storage or outbound services.

Integration contract: the adapter receives the real server request, not a caller's
role/authorized flag. It must enforce login, role, CSRF, re-authentication and
password-change gates; reject helper credentials; resolve a current unique C3
card; enforce freezing on ALL current and future sessions/actions for that card;
leave other cards alone; and atomically persist each change with authenticated
audit evidence. Errors must not release actions. Unfreeze must not clear an
independent canary/session freeze. Stop uses the existing global switch, and
incident_report uses the masked, role-checked R9 service. save_assessment must
persist metadata and audit before returning. Reads also require a role check.
No adapter is supplied here: gateway.freeze_session alone is not card enforcement.
"""
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Protocol
from zoneinfo import ZoneInfo

SINGAPORE = ZoneInfo('Asia/Singapore')
PDPC_SOURCE = 'https://www.pdpc.gov.sg/organisations/e-services/report-your-organisations-data-breach'
PDPC_CHECKED = '2026-11-18'
PDPC_RULE = (
    'Notify the PDPC as soon as practicable, and no later than three (3) calendar '
    'days after determining the breach is notifiable. A breach is notifiable '
    'when it is likely to result in significant harm to individuals or affects '
    '500 or more individuals. Notification to affected individuals has separate '
    'criteria; the 500-person threshold alone does not decide that obligation.'
)


def _local(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('An offset-aware timestamp is required')
    return value.astimezone(SINGAPORE)


@dataclass(frozen=True)
class Assessment:
    """Owner answers only. No names, addresses, evidence text or automatic verdict."""
    personal_data: bool | None
    people_count: int | None = None
    harm: str = 'unknown'
    owner_notifiable: bool | None = None
    assessed_at: datetime | None = None

    def __post_init__(self):
        if self.personal_data is not None and type(self.personal_data) is not bool:
            raise ValueError('Personal data answer must be yes, no or unknown')
        if self.people_count is not None and (type(self.people_count) is not int or self.people_count < 0):
            raise ValueError('People count must be a non-negative whole number or unknown')
        if self.harm not in ('yes', 'no', 'unknown'):
            raise ValueError('Harm answer must be yes, no or unknown')
        if self.owner_notifiable is not None and type(self.owner_notifiable) is not bool:
            raise ValueError('Only a human assessment may set notifiable')
        if (self.owner_notifiable is not None) != (self.assessed_at is not None):
            raise ValueError('Assessment decision and timestamp must be supplied together')
        if self.assessed_at is not None:
            _local(self.assessed_at)
        if self.owner_notifiable is True and self.personal_data is not True:
            raise ValueError('A personal-data reminder requires confirmed personal data')


def reminder_view(assessment: Assessment, now: datetime) -> dict:
    """Pure server-rendered view. Refresh recomputes; no timer sends anything.

    Display ceiling is end of the third following Singapore calendar date, not
    72 hours. It is a planning reminder, never permission to wait until then.
    """
    current = _local(now)
    assessed = _local(assessment.assessed_at) if assessment.assessed_at else None
    if assessed and assessed > current:
        raise ValueError('Assessment cannot be in the future')
    deadline = None
    remaining = None
    state = 'awaiting_assessment'
    if assessment.personal_data is False:
        state = 'no_personal_data'
    elif assessment.owner_notifiable is False:
        state = 'owner_not_notifiable'
    elif assessment.owner_notifiable is True:
        deadline = datetime.combine(assessed.date() + timedelta(days=3), time(23, 59, 59), SINGAPORE)
        remaining = max(0, int((deadline - current).total_seconds()))
        state = 'overdue' if current > deadline else 'counting'
    return {
        'state': state, 'show_reminder': assessment.personal_data is not False,
        'assessed_at': assessed.isoformat() if assessed else None,
        'deadline': deadline.isoformat() if deadline else None,
        'remaining_seconds': remaining, 'timezone': 'Asia/Singapore',
        'as_of': current.isoformat(), 'rule': PDPC_RULE,
        'source': PDPC_SOURCE, 'source_checked': PDPC_CHECKED,
    }


class ManagementAdapter(Protocol):
    """Trusted integrator implementation of the authenticated contract above."""
    def perform(self, request: object, operation: str, target_id: str | None,
                assessment: Assessment | None) -> object: ...


class AlarmManagement:
    def __init__(self, adapter: ManagementAdapter | None = None):
        self.adapter = adapter

    def perform(self, request: object, operation: str, target_id: str | None = None,
                assessment: Assessment | None = None) -> object:
        if operation not in ('freeze_helper', 'unfreeze_helper', 'stop_everything',
                             'incident_report', 'save_assessment'):
            raise ValueError('Unknown alarm operation')
        if operation == 'stop_everything':
            if target_id is not None or assessment is not None:
                raise ValueError('Stop everything takes no target or assessment')
        elif not isinstance(target_id, str) or not target_id or len(target_id) > 128 or not all(
                c.isascii() and (c.isalnum() or c in '_-') for c in target_id):
            raise ValueError('An opaque card or incident ID is required')
        if operation == 'save_assessment':
            if not isinstance(assessment, Assessment):
                raise ValueError('Validated assessment required')
        elif assessment is not None:
            raise ValueError('Unexpected assessment')
        if self.adapter is None:
            raise RuntimeError('Alarm management is not connected; nothing changed')
        return self.adapter.perform(request, operation, target_id, assessment)
