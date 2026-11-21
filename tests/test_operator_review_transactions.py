"""Operator review transaction boundaries in disposable SQLite state."""
import asyncio
import json
import re
import sqlite3
from urllib.parse import urlencode

import pytest
from starlette.requests import Request
from starlette.exceptions import HTTPException
from aegis import app as web, audit, auth, config, db, evidence, gateway


@pytest.fixture
def review(tmp_path, monkeypatch):
    previous = db.conn()
    monkeypatch.setattr(config, 'DB_PATH', tmp_path / 'review.db')
    monkeypatch.setattr(audit, '_ANCHOR_FILE', tmp_path / 'checkpoints.jsonl')
    monkeypatch.setattr(audit, '_KEY_FILE', tmp_path / 'signing.key')
    monkeypatch.setattr(config, 'AEGIS_ANCHOR_EXTERNAL', str(tmp_path / 'external.json'))
    db._local.conn = None
    db.init_db()
    auth.create_user('transaction-reviewer', 'private-review-password', 'admin')
    login = auth.login('transaction-reviewer', 'private-review-password')
    c = db.conn()

    def call(data=None, headers=()):
        body = urlencode(data or {}).encode()

        async def receive():
            return {'type': 'http.request', 'body': body, 'more_body': False}

        request = Request({'type': 'http', 'method': 'POST' if data else 'GET',
                           'path': '/admin/tools/review', 'query_string': b'',
                           'headers': [(b'cookie', ('aegis_session=' + login['token']).encode()),
                                       (b'content-type', b'application/x-www-form-urlencoded'),
                                       *headers]}, receive)
        return asyncio.run(web.operator_tool_review(request))

    page = call()
    data = {'csrf': login['csrf'], 'password': 'private-review-password',
            'confirm': 'approve', 'snapshot_digest': re.search(
                r'name="snapshot_digest" value="([a-f0-9]+)"', page.body.decode())[1]}
    yield call, data, c
    c.rollback()
    c.close()
    db._local.conn = previous


def rows(c):
    return c.execute("SELECT * FROM audit WHERE event='sandbox_tools_reviewed'").fetchall()


@pytest.mark.parametrize('result', [False, None, 1])
def test_unconfirmed_checkpoint_retains_history_without_success(review, monkeypatch, result):
    call, data, c = review
    monkeypatch.setattr(audit, 'checkpoint', lambda: result)
    with pytest.raises(HTTPException) as error:
        call(data)
    assert error.value.status_code == 503
    assert len(rows(c)) == 1
    assert json.loads(db.get_setting('sandbox_tool_approvals'))['version'] == 1
    with pytest.raises(HTTPException) as retry:
        call(data)
    assert retry.value.status_code == 409
    assert len(rows(c)) == 1


def test_checkpoint_observes_baseline_and_receipt_in_same_commit(review, monkeypatch):
    call, data, c = review
    observed = []
    real_checkpoint = audit.checkpoint

    def checkpoint():
        assert not c.in_transaction
        with sqlite3.connect(config.DB_PATH) as reader:
            baseline, by, ts = reader.execute(
                "SELECT value, changed_by, ts FROM settings WHERE key='sandbox_tool_approvals'").fetchone()
            row = reader.execute("SELECT ts, detail_json FROM audit WHERE event='sandbox_tools_reviewed'").fetchone()
        assert json.loads(baseline)['version'] == 1
        assert by == 'transaction-reviewer' and ts == row[0]
        detail = evidence.dec_json(row[1])
        assert detail['snapshot_digest'] == data['snapshot_digest']
        assert detail['by'] == by and detail['version'] == 1
        assert detail['fingerprints']
        observed.append(True)
        return real_checkpoint()

    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    response = call(data)
    assert response.status_code == 200 and observed == [True, True]
    assert len(rows(c)) == 1
    assert f"Saved approval audit receipt: {rows(c)[0]['id']}" in response.body.decode()


@pytest.mark.parametrize('table', ['settings', 'audit'])
def test_insert_refusal_leaves_neither_baseline_nor_receipt(review, table):
    call, data, c = review
    c.execute(f"CREATE TEMP TRIGGER refuse_review BEFORE INSERT ON {table} "
              "BEGIN SELECT RAISE(ABORT, 'review insert refused'); END")
    with pytest.raises(sqlite3.IntegrityError, match='review insert refused'):
        call(data)
    assert not c.in_transaction
    assert db.get_setting('sandbox_tool_approvals', '') == ''
    assert rows(c) == []


@pytest.mark.parametrize('boundary', ['encryption', 'commit', 'checkpoint'])
def test_interruption_rolls_back_only_before_commit(review, monkeypatch, boundary):
    call, data, c = review

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt('review interrupted')

    if boundary == 'encryption':
        monkeypatch.setattr(evidence, 'enc', interrupted)
    elif boundary == 'checkpoint':
        monkeypatch.setattr(audit, 'checkpoint', interrupted)
    else:
        class Connection:
            def __getattr__(self, name):
                return getattr(c, name)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return c.__exit__(*args)

            commit = staticmethod(interrupted)

        monkeypatch.setattr(db, 'conn', lambda: Connection())
    with pytest.raises(KeyboardInterrupt, match='review interrupted'):
        call(data)
    assert not c.in_transaction
    assert bool(rows(c)) is (boundary == 'checkpoint')
    assert bool(db.get_setting('sandbox_tool_approvals', '')) is (boundary == 'checkpoint')


def test_snapshot_read_holds_database_write_reservation(review, monkeypatch):
    call, data, c = review
    original = gateway._current_tool_schemas
    attempts = []

    def schemas():
        with sqlite3.connect(config.DB_PATH, timeout=0) as other:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                other.execute("INSERT INTO settings VALUES('sandbox_tool_approvals', '{}', 'other', 0)")
        attempts.append(True)
        return original()

    monkeypatch.setattr(gateway, '_current_tool_schemas', schemas)
    assert call(data).status_code == 200
    assert attempts == [True] and not c.in_transaction


def test_literal_fixture_receipts_preserve_drift_rejection(review, reviewed14_sandbox_tools):
    _, _, c = review
    # The literal fixture issues real receipts in this disposable DB, never
    # approval for runtime discovery or a subsequently forged revision.
    saved = db.get_setting('sandbox_tool_approvals')
    assert json.loads(saved) == {'version': 1, 'approved_records': reviewed14_sandbox_tools}
    receipts = [tuple(row) for row in c.execute('SELECT * FROM audit')]
    authority = db.get_setting('sandbox_tool_authority')
    assert len(rows(c)) == 1
    assert c.execute("SELECT COUNT(*) FROM audit WHERE event='sandbox_tools_authorized'").fetchone()[0] == 1
    assert audit.verify()['ok'] is True
    assert len(gateway.tool_schemas()) == 14
    assert gateway._passport_state('read_email')['status'] == 'allow'
    baseline = json.loads(saved)
    baseline['version'] = 2
    db.set_setting('sandbox_tool_approvals', json.dumps(baseline), 'drift', 0)
    assert gateway.tool_schemas() == []
    assert gateway._passport_state('read_email')['status'] == 'block'
    assert [tuple(row) for row in c.execute('SELECT * FROM audit')] == receipts
    assert db.get_setting('sandbox_tool_authority') == authority
    assert audit.verify()['ok'] is True


@pytest.mark.parametrize('damage', ['baseline', 'authority', 'receipt', 'checkpoint', 'never_verified'])
def test_read_only_outage_rejects_snapshot_tampering(review, monkeypatch, damage):
    call, data, c = review
    assert call(data).status_code == 200
    assert gateway._passport_state('list_inbox')['status'] == 'allow'
    monkeypatch.setattr(config, 'AEGIS_SIGNER_PORT', 1)
    assert gateway._passport_state('list_inbox')['status'] == 'allow'
    if damage == 'baseline':
        baseline = json.loads(db.get_setting('sandbox_tool_approvals'))
        baseline['version'] += 1
        db.set_setting('sandbox_tool_approvals', json.dumps(baseline), 'forged', 0)
    elif damage == 'authority':
        db.set_setting('sandbox_tool_authority', '', 'forged', 0)
    elif damage == 'receipt':
        c.execute('DROP TRIGGER audit_no_update')
        c.execute("UPDATE audit SET ts=ts+1 WHERE event='sandbox_tools_reviewed'")
        c.commit()
    elif damage == 'checkpoint':
        lines = audit._ANCHOR_FILE.read_bytes().splitlines()
        audit._ANCHOR_FILE.write_bytes(b'\n'.join(lines[:-1]) + b'\n')
    else:
        monkeypatch.setattr(gateway, '_verified_tool_authorities', {})
    assert gateway._passport_state('list_inbox')['status'] == 'block'


def test_corrupt_audit_refuses_review_before_baseline_commit(review):
    call, data, c = review
    c.execute("INSERT INTO audit(ts,event,detail_json,prev_hash,hash) VALUES(?,?,?,?,?)",
              (1, 'forged', evidence.enc('{}'), 'wrong-parent', 'wrong-hash'))
    c.commit()
    assert audit.verify()['ok'] is False
    before = c.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    with pytest.raises(HTTPException) as refused:
        call(data)
    assert refused.value.status_code == 503
    assert db.get_setting('sandbox_tool_approvals', '') == ''
    assert c.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == before
    assert not c.in_transaction


def test_failed_checkpoint_never_grants_gateway_authority_after_recovery(review, monkeypatch):
    call, data, c = review
    real_checkpoint = audit.checkpoint
    monkeypatch.setattr(audit, 'checkpoint', lambda: False)
    with pytest.raises(HTTPException) as refused:
        call(data)
    assert refused.value.status_code == 503
    assert len(rows(c)) == 1
    monkeypatch.setattr(audit, 'checkpoint', real_checkpoint)
    assert real_checkpoint() is True
    assert audit.verify()['ok'] is True
    assert audit.signer_healthy(fresh=True) is True
    assert gateway.tool_schemas() == []
    assert gateway._passport_state('read_email')['status'] == 'block'


def test_authority_checkpoint_failure_stays_pending_after_recovery(review, monkeypatch):
    call, data, c = review
    real_checkpoint = audit.checkpoint
    calls = []

    def checkpoint():
        calls.append(True)
        return real_checkpoint() if len(calls) == 1 else False

    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    with pytest.raises(HTTPException) as refused:
        call(data)
    assert refused.value.status_code == 503 and len(calls) == 2
    assert len(rows(c)) == 1
    assert db.get_setting('sandbox_tool_authority', '') == ''
    monkeypatch.setattr(audit, 'checkpoint', real_checkpoint)
    assert real_checkpoint() is True and audit.verify()['ok'] is True
    assert gateway.tool_schemas() == []
    assert gateway._passport_state('read_email')['status'] == 'block'


def test_verified_receipt_binds_gateway_authority_to_exact_baseline(review):
    call, data, c = review
    assert call(data).status_code == 200
    assert audit.verify()['ok'] is True
    assert gateway.tool_schemas()
    baseline = json.loads(db.get_setting('sandbox_tool_approvals'))
    baseline['version'] += 1
    db.set_setting('sandbox_tool_approvals', json.dumps(baseline), 'forged', 0)
    assert gateway.tool_schemas() == []
    assert gateway._passport_state('read_email')['status'] == 'block'


def test_stale_snapshot_and_agent_request_make_no_writes(review):
    call, data, c = review
    with pytest.raises(HTTPException) as agent:
        call(data, [(b'x-agent-token', b'untrusted')])
    assert agent.value.status_code == 403
    with pytest.raises(HTTPException) as stale:
        call(dict(data, snapshot_digest='0' * 64))
    assert stale.value.status_code == 409
    assert not c.in_transaction and rows(c) == []
    assert db.get_setting('sandbox_tool_approvals', '') == ''
