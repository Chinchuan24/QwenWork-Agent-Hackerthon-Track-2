"""First-view transaction boundaries on a dedicated signer/database stream."""
import sqlite3

import pytest

from aegis import approvals, audit, auth, config, db, evidence
from test_approvals import held_refund, user
from test_r3_signer import isolated_failure_stream


@pytest.fixture
def unseen(isolated_failure_stream):
    auth.ensure_demo_users()
    _, _, held = held_refund()
    aid = held['approval_id']
    assert approvals.get(aid)['viewed_at'] is None
    assert not db.conn().in_transaction
    return aid


def views(aid):
    return [r for r in audit.export_records()
            if r['event'] == 'approval_screen_viewed'
            and evidence.dec_json(r['detail_json'])['approval'] == aid]


def test_view_single_timestamp_committed_before_checkpoint(unseen, monkeypatch):
    aid = unseen
    observed = []
    original = audit.record_decision

    def record(*args, **kwargs):
        assert kwargs['trusted_ts'] == 1234567890.25
        result = original(*args, **kwargs)
        observed.append(result)
        return result

    def checkpoint():
        assert not db.conn().in_transaction
        with sqlite3.connect(str(config.DB_PATH)) as reader:
            assert reader.execute('SELECT viewed_at, viewed_by FROM approvals WHERE id=?',
                                  (aid,)).fetchone() == (1234567890.25, 'ops')
            assert reader.execute("SELECT ts FROM audit WHERE event='approval_screen_viewed'").fetchall() == [(1234567890.25,)]
        return True

    monkeypatch.setattr(approvals.time, 'time', lambda: 1234567890.25)
    monkeypatch.setattr(audit, 'record_decision', record)
    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    assert approvals.mark_view(aid, user('ops'))['ok']
    assert len(observed) == 1
    assert views(aid)[0]['ts'] == approvals.get(aid)['viewed_at']


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
def test_view_precommit_failure_rolls_back(unseen, monkeypatch, failure):
    aid = unseen
    before = approvals.get(aid)
    history = audit.export_records()

    def refuse(*args, **kwargs):
        assert db.conn().in_transaction
        raise failure('before view recording')

    monkeypatch.setattr(audit, 'record_decision', refuse)
    with pytest.raises(failure, match='before view recording'):
        approvals.mark_view(aid, user('ops'))
    assert not db.conn().in_transaction
    assert approvals.get(aid) == before
    assert audit.export_records() == history


@pytest.mark.parametrize('failure', [False, None, OSError, KeyboardInterrupt])
def test_view_postcommit_failure_retains_exact_timestamp(unseen, monkeypatch, failure):
    aid = unseen

    def checkpoint():
        assert not db.conn().in_transaction
        assert len(views(aid)) == 1
        assert approvals.get(aid)['viewed_at'] == views(aid)[0]['ts']
        if failure in (OSError, KeyboardInterrupt):
            raise failure('after view commit')
        return failure

    monkeypatch.setattr(audit, 'checkpoint', checkpoint)
    if failure in (OSError, KeyboardInterrupt):
        with pytest.raises(failure, match='after view commit'):
            approvals.mark_view(aid, user('ops'))
    else:
        result = approvals.mark_view(aid, user('ops'))
        assert result['ok'] is False
        assert 'checkpoint unavailable' in result['error']
    assert not db.conn().in_transaction
    db.conn().close()
    db._local.conn = None
    assert approvals.get(aid)['viewed_at'] == views(aid)[0]['ts']
    history = audit.export_records()
    monkeypatch.setattr(audit, 'checkpoint', lambda: True)
    assert approvals.mark_view(aid, user('ops'))['ok']
    assert audit.export_records() == history
