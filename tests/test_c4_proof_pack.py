import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis import audit, auth, config, db, evidence, proof_pack, signer_client


@pytest.fixture(autouse=True)
def isolated_audit(_clean_runtime, tmp_path, monkeypatch):
    # Failure-path exports must never leave gaps in the session audit stream.
    data = tmp_path / 'data'
    anchors = data / 'anchors'
    anchors.mkdir(parents=True)
    recordings = data / 'recordings'
    recordings.mkdir()
    signer_state = str(tmp_path / 'signer')
    monkeypatch.setattr(config, 'DATA_DIR', data)
    monkeypatch.setattr(config, 'DB_PATH', data / 'aegis.db')
    monkeypatch.setattr(config, 'ANCHOR_DIR', anchors)
    monkeypatch.setattr(config, 'RECORD_DIR', recordings)
    monkeypatch.setattr(config, 'AEGIS_ANCHOR_EXTERNAL', str(tmp_path / 'external' / 'anchor.json'))
    monkeypatch.setattr(config, 'AEGIS_SIGNER_STATE', signer_state)
    monkeypatch.setattr(audit, '_KEY_FILE', anchors / 'signing.key')
    monkeypatch.setattr(audit, '_ANCHOR_FILE', anchors / 'checkpoints.jsonl')
    monkeypatch.setattr(audit, '_signer_health_cache', {'ts': 0.0, 'ok': False})
    monkeypatch.setattr(audit, '_signer_degraded', {'ts': 0.0, 'reason': ''})
    # Preserve the shared connection; close only the connection owned here.
    monkeypatch.setattr(db._local, 'conn', None)
    signer = signer_client.SignerManager(signer_state)
    monkeypatch.setattr(config, 'AEGIS_SIGNER_PORT', signer.port)
    try:
        db.init_db()
        audit.migrate_to_signer()
        yield
    finally:
        if db._local.conn is not None:
            db._local.conn.close()
        signer.stop()


@pytest.fixture
def access():
    password = secrets.token_urlsafe(24)
    name = 'pack-' + secrets.token_hex(6)
    auth.create_user(name, password, 'auditor')
    return auth.login(name, password), password


def context(access):
    login, password = access
    return proof_pack.verify_export_context(login['token'], login['csrf'], password)


def build(access, start=0, end=None, **kwargs):
    key = Ed25519PrivateKey.generate()
    artifact = proof_pack.build_proof_pack(start, time.time()+10 if end is None else end,
        context=context(access), signing_key=key, **kwargs)
    assert proof_pack.verify_seal(artifact, key.public_key())
    return json.loads(artifact)['payload']


def test_edges_order(access):
    ids = [audit.record('decision', {'tool': 'read_file', 'verdict': 'allow'}) for _ in range(4)]
    times = {r['id']: r['ts'] for r in db.conn().execute('SELECT id,ts FROM audit')}
    pack = build(access, times[ids[1]], times[ids[2]])
    assert [r['record_id'] for r in pack['timeline']] == ids[1:3]
    assert pack['range']['edges'] == 'inclusive'
    assert build(access, 0, 253402300799)['timeline']


def test_gateway_tool_names_preserved_in_exports(access):
    tools = ['issue_refund', 'list_inbox', 'read_email', 'find_contact',
             'get_client', 'fetch_web', 'unknown_private_tool']
    ids = [audit.record('decision', {'tool': tool}) for tool in tools]
    c = db.conn()
    c.executemany(
        'INSERT INTO actions(id,session_id,tool,args_json,args_hash,created_at) VALUES(?,?,?,?,?,?)',
        [(tool, 'synthetic', tool, evidence.enc_json({}), 'synthetic', time.time())
         for tool in tools])
    c.commit()
    pack = build(access)
    expected = tools[:-1] + ['not recorded']
    assert [r['tool'] for r in pack['timeline'] if r['record_id'] in ids] == expected
    assert [r['tool'] for r in pack['actions']] == expected
    assert 'unknown_private_tool' not in json.dumps(pack)


@pytest.mark.parametrize('source', ['CSA agent guide', 'IMDA agent framework'])
@pytest.mark.parametrize('source_verified', [None, True])
def test_unmatched_rule_preserves_unverified_source_precedence(access, source, source_verified):
    secret = 'private unmatched requirement'
    row = {'source': source, 'heading': secret, 'status': 'covered', 'proof': secret}
    if source_verified is not None:
        row['source_verified'] = source_verified
    pack = build(access, rule_match=[row])
    assert pack['rule_match'][0]['status'] == 'not verified'
    assert pack['rule_match'][0]['source'] == source
    assert secret not in json.dumps(pack)


def test_mask_guards_versions_rule_match(access):
    secret = 'private launch plan without any identifying pattern'
    rid = audit.record('decision', {'tool': 'send_email', 'verdict': 'hold',
        'args': {'body': secret}, 'helper_id': secret, 'policy_version': 7, 'card_version': 3,
        'reasons': [{'rule': 'R15', 'reason': secret}],
        'aegis': {'verdict': 'safe', 'reason': secret},
        'delta': {'verdict': 'unsafe', 'reason': secret}, 'unknown': secret})
    pack = build(access, rule_match=[{'source': 'PDPA', 'status': 'not covered', 'summary': secret}],
                 card_versions=[{'version': 3, 'helper_id': secret, 'content': secret}])
    assert secret not in json.dumps(pack)
    row = next(r for r in pack['timeline'] if r['record_id'] == rid)
    assert row['guards']['aegis']['verdict'] == 'safe'
    assert row['guards']['delta']['verdict'] == 'unsafe'
    assert row['rules'] == ['R15']
    assert row['policy_version'] == 7 and row['card_version'] == 3
    assert pack['card_versions'][0]['version'] == 3
    assert pack['rule_match'][0]['status'] == 'not covered'


def test_tampered_log_exports_warning(access):
    rid = audit.record('decision', {'tool': 'read_file', 'verdict': 'allow'})
    c = db.conn()
    original = c.execute('SELECT detail_json FROM audit WHERE id=?', (rid,)).fetchone()[0]
    c.execute('DROP TRIGGER audit_no_update')
    try:
        c.execute('UPDATE audit SET detail_json=? WHERE id=?',
                  (evidence.enc_json({'tool': 'read_file', 'verdict': 'block'}), rid))
        c.commit()
        pack = build(access)
        assert pack['warning'].startswith('FAILED:')
        assert not pack['integrity']['audit']['ok']
        assert pack['integrity']['signer']['checked']
    finally:
        c.execute('UPDATE audit SET detail_json=? WHERE id=?', (original, rid))
        c.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
        c.commit()


def test_seal_edit_and_wrong_key(access):
    key = Ed25519PrivateKey.generate()
    artifact = proof_pack.build_proof_pack(0, time.time()+10, context=context(access), signing_key=key)
    assert proof_pack.verify_seal(artifact, key.public_key())
    changed = json.loads(artifact)
    changed['payload']['summary'] = 'changed'
    assert not proof_pack.verify_seal(json.dumps(changed), key.public_key())
    assert not proof_pack.verify_seal(artifact, Ed25519PrivateKey.generate().public_key())


def test_role_reauth_csrf_forgery_replay_expiry(access, monkeypatch):
    login, password = access
    for csrf, pw in [('wrong', password), (login['csrf'], 'wrong')]:
        with pytest.raises(PermissionError):
            proof_pack.verify_export_context(login['token'], csrf, pw)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(PermissionError):
        proof_pack.build_proof_pack(0, time.time(), context={'role': 'admin', 'reauthenticated': True}, signing_key=key)
    ctx = context(access)
    proof_pack.build_proof_pack(0, time.time()+10, context=ctx, signing_key=key)
    with pytest.raises(PermissionError):
        proof_pack.build_proof_pack(0, time.time()+10, context=ctx, signing_key=key)
    ctx = context(access)
    db.conn().execute('UPDATE users SET role=? WHERE id=?', ('viewer', login['user']['id']))
    db.conn().commit()
    with pytest.raises(PermissionError):
        proof_pack.build_proof_pack(0, time.time()+10, context=ctx, signing_key=key)
    with pytest.raises(PermissionError):
        context(access)
    db.conn().execute('UPDATE users SET role=? WHERE id=?', ('auditor', login['user']['id']))
    db.conn().commit()
    ctx = context(access)
    monkeypatch.setattr(proof_pack.time, 'time', lambda: 253402300799)
    with pytest.raises(PermissionError):
        proof_pack.build_proof_pack(0, 1, context=ctx, signing_key=key)


@pytest.mark.parametrize('change', ['logout', 'password', 'must_change'])
def test_export_rechecks_human_session(access, change):
    login, _ = access
    ctx = context(access)
    c = db.conn()
    if change == 'logout':
        auth.logout(login['token'])
    elif change == 'password':
        c.execute('UPDATE users SET pw_hash=? WHERE id=?', ('changed', login['user']['id']))
        c.commit()
    else:
        c.execute('UPDATE users SET must_change=1 WHERE id=?', (login['user']['id'],))
        c.commit()
    before = c.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(PermissionError):
        proof_pack.build_proof_pack(0, time.time()+10, context=ctx,
                                   signing_key=Ed25519PrivateKey.generate())
    assert c.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before


@pytest.mark.parametrize('start,end', [(2, 1), (float('nan'), 1), (0, float('inf')), (True, 1)])
def test_bad_range(access, start, end):
    with pytest.raises(ValueError):
        build(access, start, end)


@pytest.mark.parametrize('claimed', ['covered', 'partly'])
@pytest.mark.parametrize('proof', [None, '', [], {}, 'tests/nonexistent.py::test_missing'])
def test_rule_match_without_verified_proof_downgraded(access, claimed, proof):
    pack = build(access, rule_match=[
        {'source': 'PDPA', 'status': claimed, 'proof': proof},
        {'source': 'CSA agent guide', 'status': 'not verified', 'proof': proof},
    ])
    assert pack['rule_match'][0]['status'] == 'not covered'
    assert pack['rule_match'][1]['status'] == 'not verified'
    assert pack['rule_match'][1]['source'] == 'CSA agent guide'


def test_full_reviewed_rule_table_embedded(access):
    from aegis.rule_match import rule_match_table
    rows = rule_match_table()
    pack = build(access, rule_match=rows)
    assert len(pack['rule_match']) == len(rows)
    for original, exported in zip(rows, pack['rule_match']):
        for field in ('source', 'number', 'heading', 'summary', 'check', 'url',
                      'read_date', 'version', 'publication_status', 'source_verified', 'limitation'):
            assert exported[field] == original[field]
        assert exported['status'] == original['status']
        assert exported['proof'] == []
    assert build(access)['rule_match'] == pack['rule_match']


def test_catalog_projection_does_not_trust_caller_text(access):
    from aegis.rule_match import rule_match_table
    rows = rule_match_table(unreadable_sources={'OWASP agent list'})
    secret = 'private prose and https://private.invalid/token'
    rows[0].update(summary=secret, url=secret, check=secret, limitation=secret,
                   version=secret, proof=[secret], status='covered', source_verified=False)
    pack = build(access, rule_match=rows)
    assert secret not in json.dumps(pack)
    assert pack['rule_match'][0]['status'] == 'not verified'
    assert pack['rule_match'][0]['heading'] == 'Agent Goal Hijack'
    assert pack['rule_match'][0]['source'] == 'OWASP agent list'
    assert all(r['status'] == 'not verified' for r in pack['rule_match'][:10])


def test_seal_malformed_input_fails_closed():
    key = Ed25519PrivateKey.generate().public_key()
    for artifact in ('[]', 'null', '1', '{}', b'\xff', '{"payload":{},"payload":{}}'):
        assert proof_pack.verify_seal(artifact, key) is False


def test_signer_down_exports(access, monkeypatch):
    def down(_):
        raise audit.SignerUnavailable('unavailable')
    monkeypatch.setattr(audit, '_signer_request', down)
    pack = build(access)
    assert pack['warning'].startswith('FAILED:')
    assert not pack['integrity']['signer']['checked']


def test_large_range_no_truncation(access, monkeypatch):
    ctx = context(access)
    receipts = []
    monkeypatch.setattr(audit, 'record', lambda *args, **kwargs: receipts.append((args, kwargs)))
    # Isolate synthetic rows so other tests keep their existing audit chain.
    c = db.conn()
    c.executemany('INSERT INTO audit(ts,event,detail_json,prev_hash,hash) VALUES(?,?,?,?,?)',
        [(100+i/10000, 'decision', evidence.enc_json({'tool': 'read_file'}), 'synthetic', 'synthetic') for i in range(2000)])
    c.commit()
    try:
        key = Ed25519PrivateKey.generate()
        artifact = proof_pack.build_proof_pack(100, 101, context=ctx, signing_key=key)
        pack = json.loads(artifact)['payload']
        assert proof_pack.verify_seal(artifact, key.public_key())
        assert receipts[0][0][0] == 'proof_pack_exported'
        assert len(pack['timeline']) == 2000
        assert pack['warning'].startswith('FAILED:')
    finally:
        c.execute('DROP TRIGGER audit_no_delete')
        c.execute("DELETE FROM audit WHERE prev_hash='synthetic'")
        c.execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END")
        c.commit()
