"""LOCAL SCRIPTED actual sandbox receipts, not real human normal-day calibration.

Invented Lumen tasks, stand-in judges and controlled local time; no live AI.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from aegis import db, evidence, gateway
from aegis.helper_pattern import daily_volume_pattern, helper_pattern
from aegis.lumen_normal import CASES
from aegis.lumen_world import fresh
from conftest import make_session

REVIEW = dict(reviewer={'username': 'dana', 'role': 'admin'},
              review_note='LOCAL SCRIPTED receipt review; not human normal-day data')
MIDNIGHT = datetime(2026, 11, 18, 16, tzinfo=timezone.utc)


def finish(rid):
    db.conn().execute('UPDATE runs SET finished=1 WHERE id=?', (rid,))
    db.conn().commit()


def receipt(rid, session, tool, args, key=None):
    out = gateway.handle_call(session['token'], tool, args, key)
    row = db.conn().execute(
        "SELECT * FROM audit WHERE run_id=? AND session_id=? AND event='decision' ORDER BY id DESC LIMIT 1",
        (rid, session['session_id'])).fetchone()
    assert row is not None
    detail = evidence.dec_json(row['detail_json'])
    assert (detail['tool'], detail['args'], detail['verdict']) == (tool, args, out['verdict'])
    if out.get('action_id'):
        action = db.conn().execute('SELECT * FROM actions WHERE id=?', (out['action_id'],)).fetchone()
        assert action['session_id'] == session['session_id']
        assert action['tool'] == tool
        assert evidence.dec_json(action['args_json']) == args
        assert action['verdict'] == out['verdict']
        if out['verdict'] == 'allow':
            assert action['status'] == 'executed'
            assert not evidence.dec_json(action['result_json']).get('error')
    return out


@pytest.mark.parametrize('case', CASES, ids=lambda c: c['id'])
def test_local_scripted_representative_tasks(case, reviewed14_sandbox_tools):
    def session():
        rid = gateway.create_run('enforce', 'dana')
        gateway.WORLDS[rid] = fresh()
        task = case['task'] + '\nNeeded files: ' + ', '.join(case['needed_files'])
        task += '\nRecipients: ' + ', '.join(case['allowed_recipients'])
        scope = [{'args': a['args'],
                  'sources': [r['args']['doc_id'] for r in case['actions'] if r['tool'] == 'read_file'],
                  'intent': 'quote-only'} for a in case['actions'] if a['tool'] == 'send_email']
        return rid, gateway.start_session(rid, task, 'dana', source_message_scope=scope or None)

    source_id, source = session()
    target_id, target = session()
    assert source['session_id'] != target['session_id']
    try:
        source_results = [receipt(source_id, source, a['tool'], a['args'], f'source-{i}')
                          for i, a in enumerate(case['actions'])]
        finish(source_id)
        assert all(r['verdict'] == 'allow' for r in source_results)
        base = gateway.calibrate_helper_baseline(target['session_id'], [source_id], **REVIEW)
        events = gateway.helper_observations([source_id])
        assert {e['helper'] for e in events} == {source['session_id']}
        assert base['source_audit_ids'] == [e['audit_id'] for e in events]
        assert base['daily'][target['session_id']]['total_actions'] == len(case['actions'])
        assert base['minute'][target['session_id']]['tools'] == dict(Counter(a['tool'] for a in case['actions']))
        assert gateway.helper_baseline(source['session_id']) is None
        results = [receipt(target_id, target, a['tool'], a['args'], f'target-{i}')
                   for i, a in enumerate(case['actions'])]
        g4 = sum(any(r['rule'] == 'HARD-G4' for r in out['reasons']) for out in results)
        other = sum(out['verdict'] == 'hold' and not any(r['rule'] == 'HARD-G4' for r in out['reasons']) for out in results)
        assert g4 == 0
        assert [r['verdict'] for r in results] == [r['verdict'] for r in source_results]
        print(f"LOCAL SCRIPTED {case['id']} role={case['helper_id']} calls={len(results)} extra_G4_stops={g4} other_holds={other}")
    finally:
        gateway.WORLDS.pop(source_id, None)
        gateway.WORLDS.pop(target_id, None)


def test_actual_receipt_singapore_day_and_inclusive_minute(monkeypatch, reviewed14_sandbox_tools):
    now = [MIDNIGHT.timestamp() - 60]
    monkeypatch.setattr(gateway.time, 'time', lambda: now[0])
    rid, source = make_session()
    offsets = (-60, -0.001, 0, 0.001, 60.001)
    for offset in offsets:
        now[0] = MIDNIGHT.timestamp() + offset
        assert receipt(rid, source, 'list_inbox', {})['verdict'] == 'allow'
    finish(rid)
    _, target = make_session()
    base = gateway.calibrate_helper_baseline(target['session_id'], [rid], **REVIEW)
    sid = target['session_id']
    assert base['daily'][sid]['total_actions'] == 3
    assert base['minute'][sid]['tools'] == {'list_inbox': 3}
    events = gateway.helper_observations([rid])
    assert [e['timestamp'].timestamp() for e in events] == [MIDNIGHT.timestamp() + x for x in offsets]
    projected = [dict(e, helper=sid) for e in events]
    assert dict(helper_pattern(sid, projected, base['minute'], MIDNIGHT).tools) == {'list_inbox': 3}
    assert daily_volume_pattern(sid, projected, base['daily'], MIDNIGHT).total_actions == 1
    later = helper_pattern(sid, projected, base['minute'], MIDNIGHT + timedelta(seconds=60.001))
    assert dict(later.tools) == {'list_inbox': 2}


def test_multiple_source_identities_and_folders(reviewed14_sandbox_tools):
    runs, identities = [], set()
    for case in (CASES[0], CASES[3], CASES[5]):
        rid = gateway.create_run('enforce', 'dana')
        gateway.WORLDS[rid] = fresh()
        try:
            task = case['task'] + '\nNeeded files: ' + ', '.join(case['needed_files'])
            source = gateway.start_session(rid, task, 'dana')
            identities.add(source['session_id'])
            assert receipt(rid, source, 'read_file', case['actions'][0]['args'])['verdict'] == 'allow'
            finish(rid)
            runs.append(rid)
        finally:
            gateway.WORLDS.pop(rid, None)
    _, target = make_session()
    base = gateway.calibrate_helper_baseline(target['session_id'], runs, **REVIEW)
    assert len(identities) == 3
    assert len(base['source_audit_ids']) == 3
    assert base['daily'][target['session_id']]['total_actions'] == 1
    assert base['minute'][target['session_id']]['tools'] == {'read_file': 1}
    assert base['daily'][target['session_id']]['folders'] == {'marketing': 1, 'suppliers': 1, 'notes': 1}


@pytest.mark.parametrize('kind', ['empty', 'unfinished', 'refused', 'multiple_helpers'])
def test_insufficient_or_untrusted_samples_stay_unknown(kind, reviewed14_sandbox_tools):
    rid, source = make_session()
    target_id, target = make_session()
    if kind != 'empty':
        receipt(rid, source, 'not_a_tool' if kind == 'refused' else 'list_inbox', {})
    if kind == 'multiple_helpers':
        second = gateway.start_session(rid, 'Review Acme Q3.', 'dana')
        receipt(rid, second, 'list_inbox', {})
    if kind != 'unfinished':
        finish(rid)
    with pytest.raises(ValueError):
        gateway.calibrate_helper_baseline(target['session_id'], [rid], **REVIEW)
    assert gateway.helper_baseline(target['session_id']) is None
    records = gateway.helper_observations([rid])
    now = datetime.now(timezone.utc)
    assert helper_pattern(target['session_id'], records, {}, now).baseline_status == 'unknown'
    assert daily_volume_pattern(target['session_id'], records, {}, now).level == 'unknown'
    assert receipt(target_id, target, 'list_inbox', {})['verdict'] == 'allow'


def test_other_hold_is_not_g4_and_cannot_train(reviewed14_sandbox_tools):
    rid = gateway.create_run('enforce', 'dana')
    gateway.WORLDS[rid] = fresh()
    try:
        source = gateway.start_session(rid, CASES[0]['task'], 'dana')
        out = receipt(rid, source, 'list_inbox', {})
        assert out['verdict'] == 'hold'
        assert all(r['rule'] != 'HARD-G4' for r in out['reasons'])
        assert gateway.helper_observations([rid])[0]['refused'] is True
        finish(rid)
        _, target = make_session()
        with pytest.raises(ValueError):
            gateway.calibrate_helper_baseline(target['session_id'], [rid], **REVIEW)
        assert gateway.helper_baseline(target['session_id']) is None
    finally:
        gateway.WORLDS.pop(rid, None)
