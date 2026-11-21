import json

import pytest

from aegis import audit, db, evidence, proof_pack
from test_c4_proof_pack import access, build, isolated_audit


def test_sandbox_receipts_preserve_masked_bindings(access):
    secret = 'private-reviewer-and-baseline'
    review = audit.record('sandbox_tools_reviewed', {
        'by': secret, 'baseline_hash': secret, 'fingerprints': {secret: secret}})
    authorized = audit.record('sandbox_tools_authorized', {
        'by': secret, 'review_event_id': review, 'baseline_hash': secret})
    pack = build(access)
    rows = {row['record_id']: row for row in pack['timeline']}
    assert rows[review]['event'] == 'sandbox_tools_reviewed'
    assert rows[authorized]['event'] == 'sandbox_tools_authorized'
    assert rows[authorized]['review_event'].startswith('ref:')
    assert rows[authorized]['baseline'] == rows[review]['baseline']
    assert secret not in json.dumps(pack)


@pytest.mark.parametrize('field', ['action_id', 'action'])
def test_timeline_action_binding_is_opaque(access, field):
    action = 'private-action-id'
    rid = audit.record('approved_action_executed', {field: action, 'body': action})
    db.conn().execute(
        'INSERT INTO actions(id,session_id,tool,args_json,args_hash,created_at) VALUES(?,?,?,?,?,?)',
        (action, 'private-helper', 'send_email', evidence.enc_json({'body': action}), 'hash', 100))
    db.conn().commit()
    pack = build(access)
    row = next(row for row in pack['timeline'] if row['record_id'] == rid)
    assert row['action'] == pack['actions'][0]['action']
    assert action not in json.dumps(pack)


@pytest.mark.parametrize('executed_at', [100, 101, 102])
def test_range_includes_execution_of_earlier_action(access, executed_at):
    c = db.conn()
    c.executemany(
        'INSERT INTO actions(id,session_id,tool,args_json,args_hash,created_at,executed_at) '
        'VALUES(?,?,?,?,?,?,?)',
        [('earlier', 'helper', 'send_email', evidence.enc_json({}), 'hash', 99, executed_at),
         ('both', 'helper', 'send_email', evidence.enc_json({}), 'hash', 100, 101),
         ('outside', 'helper', 'send_email', evidence.enc_json({}), 'hash', 99, 103)])
    c.commit()
    pack = build(access, 100, 102)
    assert len(pack['actions']) == 2
    assert pack['actions'][0]['action'] != pack['actions'][1]['action']
    assert pack['actions'][0]['time'] == 99
    assert pack['actions'][0]['executed_at'] == executed_at


@pytest.mark.parametrize('status,decision', [('denied', 'reject'), ('changed', 'change'), ('void', 'approve')])
def test_approval_dependency_closure(access, status, decision):
    c = db.conn()
    c.execute('INSERT INTO actions(id,session_id,tool,args_json,args_hash,created_at,status) VALUES(?,?,?,?,?,?,?)',
              ('private-action', 'helper', 'send_email', evidence.enc_json({}), 'hash', 1, status))
    c.execute('INSERT INTO approvals(id,action_id,fingerprint,status,requested_at,expires_at) VALUES(?,?,?,?,?,?)',
              ('private-approval', 'private-action', 'fingerprint', status, 2, 999))
    c.commit()
    rid = audit.record('approval_decided', {'approval': 'private-approval', 'decision': decision})
    ts = c.execute('SELECT ts FROM audit WHERE id=?', (rid,)).fetchone()[0]
    pack = build(access, ts, ts)
    row = pack['timeline'][0]
    assert row['decision'] == decision
    assert row['approval'] == pack['approvals'][0]['approval']
    assert row['action'] == pack['approvals'][0]['action'] == pack['actions'][0]['action']
    assert pack['approvals'][0]['status'] == pack['actions'][0]['status'] == status
    assert pack['approvals'][0]['range_scope'] == pack['actions'][0]['range_scope'] == 'out-of-range dependency'
    assert 'private-' not in json.dumps(pack)


def test_requested_action_and_private_references(access):
    rid = audit.record('decision', {'action_id': 'one', 'requested_action': 'two'})
    first, second = build(access), build(access)
    a = next(r for r in first['timeline'] if r['record_id'] == rid)
    b = next(r for r in second['timeline'] if r['record_id'] == rid)
    assert a['requested_action'].startswith('ref:')
    assert a['action'] != b['action']
    assert a['action'] != 'ref:' + proof_pack.hashlib.sha256(proof_pack._canonical('one')).hexdigest()
