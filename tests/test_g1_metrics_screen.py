"""G1: the authenticated queue shows stored counts, not private reasons."""
import re
import uuid
from html import unescape

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import approvals, auth, db
from test_approvals import held_refund
from test_m1_auth import _csrf, _login


@pytest.fixture
def client():
    app_module.startup()
    with TestClient(app_module.app) as client:
        yield client


def login_role(client, role):
    username = "g1-metrics-" + uuid.uuid4().hex
    password = "g1-metrics-password-123"
    auth.create_user(username, password, role)
    cookie = _login(client, username, password)
    assert cookie
    return cookie


def test_queue_counts_require_authentication(client):
    response = client.get("/approvals", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "Approval review counts" not in response.text


@pytest.mark.parametrize("role", ["admin", "approver", "auditor", "viewer"])
def test_queue_renders_real_stored_counts_without_private_reason(client, role):
    reviewer = login_role(client, "approver")
    _, _, held = held_refund()
    approval_id = held["approval_id"]
    reason = "private-review-reason-" + uuid.uuid4().hex
    csrf = _csrf(client, reviewer, f"/approvals/{approval_id}")
    assert csrf
    response = client.post(
        f"/approvals/{approval_id}/decide",
        data={"decision": "deny", "reason": reason, "csrf": csrf},
        cookies={"aegis_session": reviewer},
    )
    assert response.status_code == 200
    stored = approvals.get(approval_id)
    assert stored["status"] == "denied"
    assert stored["reason"] == reason
    _, _, pending = held_refund()
    rows = db.conn().execute("SELECT status, claimed_at FROM approvals").fetchall()
    expected = {
        "approve": sum(row["status"] in ("claimed", "approved", "executed") or
                       (row['status'] == 'void' and row['claimed_at'] is not None) for row in rows),
        "reject": sum(row["status"] == "denied" for row in rows),
        "change": sum(row["status"] == "changed" for row in rows),
    }
    cookie = login_role(client, role)

    response = client.get("/approvals", cookies={"aegis_session": cookie})

    assert response.status_code == 200
    assert reason not in response.text
    text = " ".join(unescape(re.sub(r"<[^>]+>", " ", response.text)).split())
    assert "Approval review counts" in text
    section = text.split("Approval review counts", 1)[1]
    for label, count in expected.items():
        assert re.search(rf"\b{label}\s*:?\s*{count}\b", section, re.IGNORECASE), section
    assert approvals.get(pending["approval_id"])["status"] == "pending"


@pytest.mark.parametrize("role", ["auditor", "viewer"])
def test_read_only_roles_cannot_decide_from_queue(client, role):
    cookie = login_role(client, role)
    _, _, held = held_refund()
    approval_id = held["approval_id"]
    csrf = _csrf(client, cookie, "/approvals")
    assert csrf

    response = client.post(
        f"/approvals/{approval_id}/decide",
        data={"decision": "deny", "reason": "Not authorized", "csrf": csrf},
        cookies={"aegis_session": cookie},
    )

    assert response.status_code in (200, 403)
    assert "your role cannot approve" in response.text or response.status_code == 403
    stored = approvals.get(approval_id)
    assert stored["status"] == "pending"
    assert stored["decided_at"] is None
    assert stored["reason"] is None
