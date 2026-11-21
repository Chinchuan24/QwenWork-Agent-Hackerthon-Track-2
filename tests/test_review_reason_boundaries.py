"""Approval reason boundaries without live releases."""
import pytest

from aegis import approvals, db, evidence, gateway
from test_new_attacks_governance import held

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")


@pytest.mark.parametrize("tool", ["send_email", "pay_supplier", "order_supplier", "issue_refund"])
@pytest.mark.parametrize("reason", [None, "", " \t", "x" * 501, "\u200b", "\x00", "\u2060\ufeff"])
def test_invalid_reason_cleanly_refuses_without_release(tool, reason, monkeypatch):
    rid, _, out = held()
    db.conn().execute("UPDATE actions SET tool=? WHERE id=?", (tool, out["action_id"]))
    db.conn().commit()
    released = []
    monkeypatch.setattr(gateway, "execute_approved", lambda *args: released.append(args))
    reviewer = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    result = approvals.decide(out["approval_id"], reviewer, "approve", reason=reason)
    assert result["ok"] is False and result["error"]
    assert not released and not gateway.get_world(rid).refunds
    assert approvals.get(out["approval_id"])["status"] == "pending"


def test_plaintext_encryption_preserves_envelope_idempotence():
    literal = "enc:v2:00"
    stored = evidence.enc_plaintext(literal)
    assert stored != literal
    assert evidence.dec(stored) == literal
    assert evidence.enc(stored) == stored


@pytest.mark.parametrize("text", ["enc:v1:!", "enc:v2:not-hex", "enc:v2:00"])
def test_legacy_corruption_is_sanitized(text):
    with pytest.raises(evidence.EvidenceKeyError, match="^stored evidence cannot be decrypted$") as failure:
        evidence.dec(text)
    assert failure.value.__cause__ is None
