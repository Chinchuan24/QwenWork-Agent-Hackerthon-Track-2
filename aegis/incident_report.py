"""R9 pure masked projection of a trusted, decoded audit snapshot.

This is not an authenticated report endpoint. IncidentReports is deliberately
closed until a trusted request adapter is installed. The adapter must validate
an actual human web session, enforce admin/auditor (or explicitly approved
management roles), password-change gates and CSRF for report creation; reject
helper credentials and caller-supplied role/authorized flags. It must resolve
IDs from storage, decode evidence with audit.export_records or evidence.dec,
check integrity without claiming success on failure, and persist an
incident_report_created receipt (actor, trigger IDs, artifact fingerprint)
before returning a downloadable masked artifact. No routes are installed here.

Input IDs refer to audit entries, not action IDs. Sequence follows audit IDs,
not wall-clock timestamps, which can move backwards. Missing historical
bindings are never inferred from current mutable session/action/policy rows.
"""
import json
import math
import re
from typing import Protocol

_MASK = '[private text hidden]'
_TOOLS = {'send_email', 'issue_refund', 'delete_file', 'read_file', 'search_files',
          'list_files', 'fetch_url', 'lookup_contact', 'upload_file', 'share_file',
          'update_record', 'pay_supplier', 'order_supplier', 'accept_terms'}
_EVENTS = {'session_started', 'session_exposed', 'session_frozen', 'decision',
           'second_opinion', 'approval_requested', 'approval_denied', 'approval_void',
           'approved_action_executed', 'pipeline_error', 'redaction', 'shield_unsure'}
_VERDICTS = {'allow', 'hold', 'block', 'safe', 'unsafe', 'unsure', 'error', 'timeout'}
_MODES = {'enforce', 'monitor', 'off', 'standin', 'stand-in', 'scripted', 'live', 'error'}


def _label(value, choices):
    return value if isinstance(value, str) and value in choices else 'not recorded'


def _action_binding(detail):
    values = [detail[k] for k in ('action_id', 'action') if k in detail]
    if not values or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{12}', v)
                         for v in values) or len(set(values)) != 1:
        return None
    return values[0]


def build_incident_report(audit_ids, records):
    """Return JSON-safe metadata without private content or any side effects.

    records is a trusted decoded snapshot, NOT request-provided evidence.
    detail_json must already be decrypted; unreadable input is refused. Exactly
    one incident may be selected; additional IDs must describe that same session.
    Proof references are for an authenticated resolver, not automatic hyperlinks.
    """
    if (not isinstance(audit_ids, (list, tuple)) or not audit_ids
            or any(type(i) is not int or i <= 0 for i in audit_ids)
            or len(set(audit_ids)) != len(audit_ids)):
        raise ValueError('Distinct positive audit IDs required')
    rows = []
    seen = set()
    for source in records:
        row = dict(source)
        rid = row.get('id')
        if type(rid) is not int or rid <= 0 or rid in seen:
            raise ValueError('Invalid or duplicate audit record')
        seen.add(rid)
        detail = row.get('detail')
        if detail is None:
            try:
                detail = json.loads(row.get('detail_json', ''))
            except (ValueError, TypeError):
                raise ValueError('Decoded audit evidence required') from None
        if not isinstance(detail, dict):
            raise ValueError('Invalid audit evidence')
        row['detail'] = detail
        rows.append(row)
    selected = [r for r in rows if r['id'] in audit_ids]
    if len(selected) != len(audit_ids):
        raise ValueError('Audit record not found')
    sessions = {r.get('session_id') for r in selected}
    if len(sessions) != 1 or not next(iter(sessions)):
        raise ValueError('One recorded session required')
    for row in selected:
        if not (row.get('event') == 'session_frozen' or
                (row.get('event') == 'decision' and row['detail'].get('verdict') in ('hold', 'block'))):
            raise ValueError('Select a held, blocked or frozen audit entry')
    selected.sort(key=lambda r: r['id'])
    anchor = selected[-1]
    timeline_rows = sorted((r for r in rows if r.get('session_id') in sessions
                            and r['id'] <= anchor['id']), key=lambda r: r['id'])
    d = anchor['detail']
    frozen = anchor.get('event') == 'session_frozen'
    action_binding = None if frozen else _action_binding(d)
    rules = []
    reasons = d.get('reasons', [])
    if isinstance(reasons, list):
        for reason in reasons:
            rule = reason.get('rule') if isinstance(reason, dict) else None
            if isinstance(rule, str) and re.fullmatch(r'(?:R\d{2}|ASI\d{2}|(?:HARD|GATE|R)-[A-Z0-9-]{1,40})', rule):
                rules.append(rule)
    task_rows = [r for r in timeline_rows if r.get('event') == 'session_started']
    exposures = [r['id'] for r in timeline_rows if r.get('event') == 'session_exposed']
    guards = []
    timeline = []
    for row in timeline_rows:
        detail = row['detail']
        ts = row.get('ts')
        timeline.append({'record_id': row['id'],
            'time': ts if type(ts) in (int, float) and math.isfinite(ts) else None,
            'event': _label(row.get('event'), _EVENTS),
            'tool': _label(detail.get('tool'), _TOOLS),
            'verdict': _label(detail.get('verdict', detail.get('outcome')), _VERDICTS),
            'content': _MASK})
        if row.get('event') == 'second_opinion':
            guard_binding = _action_binding(detail)
            scope = ('unknown' if action_binding is None or guard_binding is None else
                     'selected action' if action_binding == guard_binding else 'other action')
            guard = {'record_id': row['id'], 'scope': scope,
                     'binding': ('Recorded binding matches the selected action.' if scope == 'selected action' else
                                 'Recorded binding belongs to another action.' if scope == 'other action' else
                                 'Session evidence only; action binding not recorded or unresolved.')}
            for key in ('a', 'b'):
                answer = detail.get(key)
                answer = answer if isinstance(answer, dict) else {}
                guard[key] = {'verdict': _label(answer.get('verdict'), _VERDICTS),
                              'mode': _label(answer.get('mode'), _MODES),
                              'reason': _MASK if answer.get('reason') else 'not recorded'}
            guards.append(guard)
    version = d.get('policy_version')
    return {
        'format': 'aegis-incident-report-v1',
        'trigger': 'frozen' if frozen else d['verdict'],
        'summary': 'The helper was frozen.' if frozen else
                   ('The attempted action was held for review.' if d['verdict'] == 'hold' else
                    'The attempted action was blocked.'),
        'task': {'record_id': task_rows[0]['id'] if task_rows else None,
                 'content': _MASK if task_rows else 'not recorded'},
        'action': {'record_id': anchor['id'], 'tool': 'not recorded' if frozen else _label(d.get('tool'), _TOOLS),
                    'content': _MASK,
                    'action_id_binding': 'recorded' if action_binding else 'not recorded',
                    'guard_record_ids': [g['record_id'] for g in guards if g['scope'] == 'selected action'],
                    'guard_verdict': 'unknown'},
        'cause': {'content': _MASK, 'exposure_record_ids': exposures,
                  'notice': 'Outside content was read; this alone does not prove it caused the incident.'},
        'policy': {'rules': sorted(set(rules)),
                   'version': version if type(version) is int and version > 0 else None},
        'guards': guards,
        'protected_data': {'content': _MASK,
            'notice': 'Private content is hidden. Data categories and whether harm occurred are not established by this report.'},
        'timeline': timeline,
        'proof': {'trigger_record_ids': sorted(audit_ids),
                  'record_ids': [r['id'] for r in timeline_rows], 'verified': False,
                  'notice': 'References only. The authenticated service must check the stored history.'},
        'next_steps': ['Review the original request and the held action through the permitted review screen.',
                      'Do not approve until the target and content match the request.',
                      'If personal data may be involved, ask a person to assess it in the alarm screen. This is not legal advice.'],
        'limitations': ['No private text is exported, including tasks, causes, arguments and judge explanations.',
                       'Missing policy versions and action bindings are not guessed.',
                       'This projection neither verifies history nor records report creation.'],
    }


class ReportAdapter(Protocol):
    """Trusted server implementation, never a request-supplied adapter.

    make must authenticate the human session from server storage, reject expired
    sessions and helper tokens, enforce the permitted role, password-change gate,
    fresh re-authentication and CSRF before resolving any evidence. Caller role,
    authorized flags and decoded records are not authentication or proof.
    Resolve every selected audit ID from storage; decrypt the snapshot and check
    chain integrity against the independent signer. Missing historical action,
    guard, policy or identity bindings stay unknown, never joined by session or
    guessed from current rows. Integrity failure must be clearly reported, not
    upgraded to verified. Mask the artifact before fingerprinting it and persist
    incident_report_created with the authenticated actor, trigger audit IDs and
    exact artifact fingerprint before returning it. Receipt failure returns no
    download. Downloads require the same trusted authorization boundary; no
    private evidence, credentials or unsigned claims may be returned. Adapter
    errors propagate; this wrapper provides no fallback or authentication.
    """
    def make(self, request: object, audit_ids: tuple[int, ...]) -> object: ...


class IncidentReports:
    def __init__(self, adapter: ReportAdapter | None = None):
        self.adapter = adapter

    def make(self, request: object, audit_ids):
        if self.adapter is None:
            raise PermissionError('Incident reports are not connected to authenticated management')
        if (not isinstance(audit_ids, (list, tuple)) or not audit_ids
                or any(type(i) is not int or i <= 0 for i in audit_ids)
                or len(set(audit_ids)) != len(audit_ids)):
            raise ValueError('Distinct positive audit IDs required')
        return self.adapter.make(request, tuple(audit_ids))
