"""G2 human-session adapter over encrypted, append-only incident storage.

No routes, reports, sends, or inferred determinations. Write timestamps are
human-supplied Unix epochs, with the storage API's explicit confirmations.
The first explicit confirmation supplies each clock; conflicts are refused.
Ordinary steps never clear it. Historical actor IDs are projected, not mutable user names.
A route owner must obtain tokens/CSRF from the real session/request boundary;
never expose this private projection to helper tools or public exports.
"""
from datetime import datetime, timezone, timedelta
import math
import json
from dataclasses import replace

import hashlib

from . import auth, audit, db, evidence, incident_store
from .breach_clock import SG, breach_clock


_SCHEMA = 'aegis.g2.completion.v1'


def _ordinary(text):
    if isinstance(text, str) and _SCHEMA in text:
        raise ValueError('Reserved completion schema')


def _completion_receipt(incident_id, value):
    decision = {key: item for key, item in value.items() if key != 'receipt_id'}
    return dict(incident_id=incident_id, decision=decision,
                decision_sha256=hashlib.sha256(audit.canonical(decision).encode()).hexdigest())


def completion(incident, current):
    """Parse only a verified stored, exact schema; free text never completes."""
    found = None
    grounds = _at(incident.get('awareness_at'))
    determined = _at(incident.get('determination_at'))
    for row in incident['steps']:
        grounds = grounds or _at(row.get('awareness_at'))
        determined = determined or _at(row.get('determination_at'))
        text = row['step']
        if _SCHEMA not in text:
            if found and row.get('determination_at') is not None:
                raise ValueError('Completion is terminal')
            continue
        try:
            def pairs(items):
                result = dict(items)
                if len(result) != len(items):
                    raise ValueError('Duplicate completion key')
                return result
            value = json.loads(text, object_pairs_hook=pairs)
            if (type(value) is not dict or set(value) !=
                    {'schema', 'outcome', 'actor_id', 'reason', 'completed_at', 'human_confirmed', 'receipt_id'}
                    or value['schema'] != _SCHEMA or value['outcome'] != 'not_notifiable'
                    or type(value['actor_id']) is not int or value['actor_id'] != row['actor_id']
                    or value['human_confirmed'] is not True
                    or not isinstance(value['reason'], str) or not value['reason'].strip()
                    or row.get('determination_at') is not None or row.get('human_determination') is not False):
                raise ValueError('Invalid completion schema')
            if type(value['receipt_id']) is not int or value['receipt_id'] <= 0:
                raise ValueError('Invalid completion receipt')
            if audit.verify().get('ok') is not True:
                raise incident_store.IncidentIntegrityError('Completion audit verification failed')
            receipt = db.conn().execute('SELECT event, detail_json FROM audit WHERE id=?',
                                        (value['receipt_id'],)).fetchone()
            if (receipt is None or receipt['event'] != 'g2_assessment_completed'
                    or evidence.dec_json(receipt['detail_json']) != _completion_receipt(incident['id'], value)
                    or value['receipt_id'] >= row['audit_id']):
                raise incident_store.IncidentIntegrityError('Completion authority receipt mismatch')
            at = _at(value['completed_at'])
            recorded = _at(row['timestamp'])
            if (found or grounds is None or at is None
                    or at < grounds or (determined is not None and at < determined)
                    or at > current or recorded is None or at != recorded):
                raise ValueError('Invalid completion chronology')
            found = dict(value, completed_at=at.astimezone(SG))
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError('Invalid completion schema') from None
    return found


def project(incident, now=None):
    current = datetime.now(timezone.utc)
    if now is not None:
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError('now must be aware')
        current = min(current, now)
    grounds, determination = _triggers((incident, *incident['steps']), current)
    done = completion(incident, current)
    records = [dict(timestamp=_at(row['timestamp']),
                    step=row.get('step', row.get('title')), actor=str(row['actor_id']),
                    **row['facts']) for row in (incident, *incident['steps'])]
    clock = breach_clock(grounds, determination, now, records)
    if determination is not None or done:
        clock = replace(clock, assessment=replace(clock.assessment, status='completed', days_remaining=None))
    if done:
        clock = replace(clock, notification=replace(clock.notification, status='not_required', days_remaining=None))
    return clock


def complete_assessment(token, csrf, incident_id, *, reason, completed_at, human_confirmed=False):
    """Explicit terminal not-notifiable human decision; never inferred from facts."""
    user = _human(token, csrf, write=True)
    if not isinstance(reason, str) or not reason.strip() or human_confirmed is not True:
        raise ValueError('Confirmed decision and reason required')
    at = _at(completed_at)
    def prepare(stored):
        current_user = _human(token, csrf, write=True)
        if current_user['id'] != user['id']:
            raise PermissionError('Incident session identity changed')
        current = datetime.now(timezone.utc)
        grounds, determination = _triggers((stored, *stored['steps']), current)
        if (completion(stored, current) or grounds is None or at is None or at < grounds
                or (determination is not None and at < determination) or at > current):
            raise ValueError('Invalid or conflicting completion')
        value = dict(schema=_SCHEMA, outcome='not_notifiable', actor_id=user['id'],
                     reason=reason.strip(), completed_at=completed_at, human_confirmed=True)
        # Reserve room for the receipt ID before recording any intent.
        if len(json.dumps(dict(value, receipt_id=2**63 - 1), sort_keys=True)) > 10000:
            raise ValueError('Completion reason too long')
        detail = _completion_receipt(incident_id, value)
        def attach(receipt_id):
            return json.dumps(dict(value, receipt_id=receipt_id), sort_keys=True, allow_nan=False)
        payload = incident_store._payload(attach(2**63 - 1), None, completed_at,
                                          None, False, None, False)
        return payload, ('g2_assessment_completed', detail, attach)
    return incident_store.append_validated(user, incident_id, prepare)


def _human(token, csrf=None, *, write=False):
    if not isinstance(token, str) or not token:
        raise PermissionError('Human web session required')
    user = auth.user_by_token(token)
    if user is None:
        raise PermissionError('Human web session required')
    if write and (not isinstance(csrf, str) or not auth.check_csrf(user, csrf)):
        raise PermissionError('Incident CSRF check failed')
    # Storage rechecks current roles, identity and the password-change gate.
    return user


def _at(epoch):
    if epoch is None:
        return None
    if type(epoch) not in (int, float) or epoch < 0:
        raise ValueError('Finite nonnegative epoch required')
    try:
        if not math.isfinite(epoch):
            raise ValueError('Finite nonnegative epoch required')
        value = datetime.fromtimestamp(epoch, timezone.utc)
        # Both SG conversion and the longest reminder deadline must fit.
        value + timedelta(days=30, hours=8)
        return value
    except (OverflowError, OSError, ValueError):
        raise ValueError('Epoch outside supported reminder range') from None


def _triggers(entries, current):
    grounds = determination = None
    for entry in entries:
        timestamp = _at(entry.get('timestamp'))
        if timestamp is not None and timestamp > current:
            raise ValueError('Future step timestamp refused')
        for field, flag in (('awareness_at', 'human_awareness'),
                            ('determination_at', 'human_determination')):
            value = _at(entry.get(field))
            confirmed = entry.get(flag, False)
            if type(confirmed) is not bool or confirmed != (value is not None):
                raise ValueError('Epoch requires explicit human confirmation')
            if value is None:
                continue
            if value > current:
                raise ValueError('Future trigger refused')
            previous = grounds if field == 'awareness_at' else determination
            if previous is not None and previous != value:
                raise ValueError('Conflicting canonical trigger')
            if field == 'awareness_at':
                grounds = value
            else:
                determination = value
        if determination is not None and (grounds is None or determination < grounds):
            raise ValueError('Determination requires earlier known grounds')
    return grounds, determination


def create_incident(token, csrf, *, title, facts=None, timestamp=None,
                    awareness_at=None, human_awareness=False,
                    determination_at=None, human_determination=False):
    """Persist only supplied metadata through the existing trusted store."""
    user = _human(token, csrf, write=True)
    def prepare(stored):
        current_user = _human(token, csrf, write=True)
        if current_user['id'] != user['id']:
            raise PermissionError('Incident session identity changed')
        _ordinary(title)
        _triggers([dict(timestamp=timestamp, awareness_at=awareness_at,
                        human_awareness=human_awareness, determination_at=determination_at,
                        human_determination=human_determination)], datetime.now(timezone.utc))
        return incident_store._payload(title, facts, timestamp, awareness_at,
            human_awareness, determination_at, human_determination), None
    return incident_store.append_validated(user, None, prepare)


def add_step(token, csrf, incident_id, *, step, facts=None, timestamp=None,
             awareness_at=None, human_awareness=False,
             determination_at=None, human_determination=False):
    """Append a human step without resetting either canonical trigger."""
    user = _human(token, csrf, write=True)
    def prepare(stored):
        current_user = _human(token, csrf, write=True)
        if current_user['id'] != user['id']:
            raise PermissionError('Incident session identity changed')
        _ordinary(step)
        if completion(stored, datetime.now(timezone.utc)) and determination_at is not None:
            raise ValueError('Completion is terminal')
        _triggers((stored, *stored['steps'], dict(timestamp=timestamp,
            awareness_at=awareness_at, human_awareness=human_awareness,
            determination_at=determination_at, human_determination=human_determination)),
            datetime.now(timezone.utc))
        return incident_store._payload(step, facts, timestamp, awareness_at,
            human_awareness, determination_at, human_determination), None
    return incident_store.append_validated(user, incident_id, prepare)


def get_incident(token, incident_id, *, now=None):
    """Verify/decrypt stored history and return a frozen human-only projection.

    now is an explicit aware datetime (or None), never a default system clock.
    Creation metadata is the first log entry, followed by storage append order.
    Missing facts and timestamps stay unknown; count/harm never start a clock.
    """
    stored = incident_store.get_incident(_human(token), incident_id)
    return project(stored, now)
