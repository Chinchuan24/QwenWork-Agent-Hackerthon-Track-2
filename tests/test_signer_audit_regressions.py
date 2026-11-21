"""Narrow signer transition and fresh batch-verification regressions."""
import json
import threading

import pytest

from aegis import audit, config, db
from aegis.signer import Handler, Server, SignerState


@pytest.mark.parametrize('count,max_id', [(1, 2), (2, 1)])
def test_partial_position_advance_is_refused_and_restart_safe(tmp_path, count, max_id):
    state = SignerState(tmp_path)
    first = state.sign('test', {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64})
    before = state.rec_file.read_bytes()
    result = state.sign('test', {'count': count, 'max_id': max_id, 'last_hash': 'b' * 64})
    assert result.get('error'), result
    assert state.rec_file.read_bytes() == before
    assert SignerState(tmp_path).latest['test']['sig'] == first['sig']
    assert state.sign('test', {'count': 2, 'max_id': 2, 'last_hash': 'b' * 64})['seq'] == 2


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    state = SignerState(tmp_path / 'signer')
    server = Server(('127.0.0.1', 0), Handler)
    server.state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(config, 'AEGIS_SIGNER_PORT', server.server_address[1])
    monkeypatch.setattr(config, 'DB_PATH', tmp_path / 'audit.db')
    monkeypatch.setattr(audit, '_KEY_FILE', tmp_path / 'legacy.key')
    monkeypatch.setattr(audit, '_ANCHOR_FILE', tmp_path / 'checkpoints.jsonl')
    monkeypatch.setattr(config, 'AEGIS_ANCHOR_EXTERNAL', str(tmp_path / 'external.json'))
    monkeypatch.setattr(db._local, 'conn', None)
    db.init_db()
    try:
        yield state
    finally:
        db.conn().close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_audit_verifies_all_signatures_with_one_fresh_load(isolated, monkeypatch):
    for i in range(8):
        audit.record('batch', {'i': i})
    loads = []
    original = isolated._load

    def counted_load():
        loads.append(1)
        original()

    monkeypatch.setattr(isolated, '_load', counted_load)
    assert audit.verify()['ok'] is True
    assert len(loads) == 1
    anchors = [json.loads(line) for line in audit._ANCHOR_FILE.read_text().splitlines()]
    anchors[2]['body']['ts'] += 1
    audit._ANCHOR_FILE.write_text('\n'.join(map(json.dumps, anchors)) + '\n')
    result = audit.verify()
    assert result['ok'] is False
    assert any('signature invalid' in p for p in result['problems'])


def test_batch_refreshes_other_writer_and_detects_corruption(isolated):
    audit.record('first', {})
    assert audit.verify()['ok'] is True
    other = SignerState(isolated.dir)
    other.sign(audit._stream_id(), {'count': 2, 'max_id': 2, 'last_hash': 'b' * 64})
    result = audit.verify()
    assert result['ok'] is False
    assert any('rolled back' in p for p in result['problems'])
    records = isolated.rec_file.read_text().splitlines()
    forged = json.loads(records[0])
    forged['body']['last_hash'] = 'forged'
    isolated.rec_file.write_text(json.dumps(forged) + '\n' + records[1] + '\n')
    assert audit.verify()['ok'] is False


@pytest.mark.parametrize('anchor_state', ['retained', 'malformed', 'missing'])
def test_empty_rollback_fails_closed_with_signer_unavailable(isolated, monkeypatch, anchor_state):
    audit.record('prior_history', {})
    c = db.conn()
    c.execute('DROP TRIGGER audit_no_delete')
    c.execute('DELETE FROM audit')
    c.commit()
    audit._ANCHOR_FILE.write_text('')
    external = audit._external_path()
    if anchor_state == 'malformed':
        external.write_text('{')
    elif anchor_state == 'missing':
        # Redirect to absent evidence without deleting any file.
        monkeypatch.setattr(config, 'AEGIS_ANCHOR_EXTERNAL', str(external) + '.absent')

    def unavailable(_):
        raise audit.SignerUnavailable('test signer unavailable')

    monkeypatch.setattr(audit, '_signer_request', unavailable)
    result = audit.verify()
    assert result['ok'] is False, result
    assert any('signer unreachable' in p for p in result['problems'])
    if anchor_state == 'retained':
        assert any('external anchor expects' in p for p in result['problems'])
    elif anchor_state == 'malformed':
        assert any('external anchor: unreadable' in p for p in result['problems'])


def test_pristine_empty_database_remains_valid(isolated):
    assert not audit._external_path().exists()
    result = audit.verify()
    assert result['records'] == 0
    assert result['ok'] is True, result


@pytest.mark.parametrize('reply', [[], {'results': [], 'latest': None},
    {'results': [], 'latest': []}, {'results': [], 'latest': {}},
    {'results': [], 'latest': {'seq': False}}])
def test_empty_requires_explicit_integer_zero(isolated, monkeypatch, reply):
    monkeypatch.setattr(audit, '_signer_request', lambda _: reply)
    assert audit.verify()['ok'] is False


@pytest.mark.parametrize('field,value', [('count', True), ('count', 0),
    ('count', 1.0), ('max_id', False), ('max_id', -1), ('last_hash', 'bad')])
def test_invalid_sign_never_poisons_history(tmp_path, field, value):
    state = SignerState(tmp_path)
    body = {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64}
    assert state.sign('test', {**body, field: value}).get('error')
    assert not state.rec_file.exists()
    assert state.sign('test', body)['seq'] == 1


def test_idempotent_retry_syncs_existing_record(tmp_path, monkeypatch):
    from aegis import signer
    state = SignerState(tmp_path)
    body = {'count': 1, 'max_id': 1, 'last_hash': 'a' * 64}
    sync = signer.os.fsync
    def fail(_):
        raise OSError('sync failed')
    monkeypatch.setattr(signer.os, 'fsync', fail)
    with pytest.raises(OSError):
        state.sign('test', body)
    before = state.rec_file.read_bytes()
    calls = []
    monkeypatch.setattr(signer.os, 'fsync', lambda fd: (calls.append(fd), sync(fd))[1])
    assert state.sign('test', body)['seq'] == 1
    assert len(calls) >= 2
    assert state.rec_file.read_bytes() == before


def test_partial_checkpoint_tail_preserves_history(isolated):
    audit.record('first', {})
    before = audit._ANCHOR_FILE.read_bytes() + b'{"body":'
    audit._ANCHOR_FILE.write_bytes(before)
    assert audit.checkpoint() is False
    assert audit._ANCHOR_FILE.read_bytes() == before
    assert audit.verify()['ok'] is False


@pytest.mark.parametrize('field,value', [('seq', True), ('count', True), ('count', 1.0)])
def test_signed_body_requires_canonical_types(isolated, field, value):
    audit.record('first', {})
    anchor = json.loads(audit._ANCHOR_FILE.read_text())
    if field == 'seq':
        anchor[field] = value
    else:
        anchor['body'][field] = value
    audit._ANCHOR_FILE.write_text(json.dumps(anchor) + '\n')
    assert audit.verify()['ok'] is False
