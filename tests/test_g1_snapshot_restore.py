"""Coordinated G1 data restore leaves the isolated outside signer untouched."""
import shutil
from pathlib import Path

from aegis import approvals, audit, auth, config, db, evidence
from test_approvals import held_refund, user
from test_r3_signer import isolated_failure_stream


def test_g1_decision_reopen_and_coordinated_restore(isolated_failure_stream, tmp_path):
    auth.ensure_demo_users()
    _, _, held = held_refund()
    aid = held['approval_id']
    assert approvals.mark_view(aid, user('ops'))['ok']
    assert approvals.decide(aid, user('ops'), 'change', reason='Verify the invoice first')['ok']
    before = audit.verify()
    assert before['ok'], before['problems']
    data = Path(config.DATA_DIR)
    assert not Path(config.AEGIS_SIGNER_STATE).is_relative_to(data)
    assert not Path(config.AEGIS_ANCHOR_EXTERNAL).is_relative_to(data)
    db.conn().close()
    db._local.conn = None
    snapshot = tmp_path / 'approval-snapshot'
    shutil.copytree(data, snapshot)
    assert approvals.get(aid)['status'] == 'changed'
    assert approvals.get(aid)['reason'] == 'Verify the invoice first'
    history = audit.export_records()
    assert not approvals.decide(aid, user('ops'), 'approve', reason='Replay')['ok']
    assert audit.export_records() == history
    decision = [r for r in history if r['event'] == 'approval_decided'
                and evidence.dec_json(r['detail_json'])['approval'] == aid]
    assert len(decision) == 1
    assert evidence.dec_json(decision[0]['detail_json'])['reason'] == 'Verify the invoice first'
    advanced = audit.record_decision('g1_snapshot_advance', {'approval': aid},
                                     trusted_ts=decision[0]['ts'] + 1)
    assert advanced['checkpoint_ok'] is True
    healthy = audit.verify()
    assert healthy['ok'], healthy['problems']
    assert healthy['records'] > before['records']
    db.conn().close()
    db._local.conn = None
    shutil.copytree(snapshot, data, dirs_exist_ok=True)
    restored = audit.verify()
    assert restored['ok'] is False
    assert restored['records'] == before['records']
    expected = (f"data folder rolled back: signer remembers {healthy['records']} records, "
                f"found {before['records']} (records and checkpoints deleted together)")
    assert expected in restored['problems'], restored['problems']
    assert approvals.get(aid)['status'] == 'changed'
    assert approvals.get(aid)['reason'] == 'Verify the invoice first'
    history = audit.export_records()
    assert not approvals.decide(aid, user('ops'), 'approve', reason='Replay after restore')['ok']
    assert audit.export_records() == history
