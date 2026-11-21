"""G1: review timing starts only on an authorized, CSRF-protected POST."""
import time
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import approvals, auth, db, gateway
from conftest import make_session
from test_m1_auth import _csrf, _login


@pytest.fixture
def client():
    app_module.startup()
    with TestClient(app_module.app) as client:
        yield client


@pytest.fixture
def approval_id():
    _, session = make_session(
        task="Process the large refund Cirrus Health asked for by email (INV-3008)."
    )
    result = gateway.handle_call(
        session["token"], "issue_refund",
        {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"},
        uuid.uuid4().hex,
    )
    assert result["verdict"] == "hold"
    return result["approval_id"]


@pytest.fixture
def reviewer(client):
    username = "g1-reviewer-" + uuid.uuid4().hex[:8]
    password = "g1-review-password-123"
    auth.create_user(username, password, "approver")
    cookie = _login(client, username, password)
    assert cookie
    csrf = _csrf(client, cookie)
    assert csrf
    return username, cookie, csrf


def test_get_detail_does_not_mark_view(client, approval_id, reviewer):
    _, cookie, _ = reviewer
    response = client.get(
        f"/approvals/{approval_id}", cookies={"aegis_session": cookie}
    )
    assert response.status_code == 200
    row = approvals.get(approval_id)
    assert row["viewed_at"] is None
    assert row["viewed_by"] is None


def test_post_view_requires_authentication(client, approval_id):
    response = client.post(
        f"/approvals/{approval_id}/view", data={"csrf": "forged"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert approvals.get(approval_id)["viewed_at"] is None


@pytest.mark.parametrize("csrf", [None, "forged"])
def test_post_view_requires_csrf(client, approval_id, reviewer, csrf):
    _, cookie, _ = reviewer
    response = client.post(
        f"/approvals/{approval_id}/view",
        data={} if csrf is None else {"csrf": csrf},
        cookies={"aegis_session": cookie}, follow_redirects=False,
    )
    assert response.status_code == 403
    row = approvals.get(approval_id)
    assert row["viewed_at"] is None
    assert row["viewed_by"] is None


def test_post_view_records_first_view_only(client, approval_id, reviewer):
    username, cookie, csrf = reviewer
    before = time.time()
    response = client.post(
        f"/approvals/{approval_id}/view", data={"csrf": csrf},
        cookies={"aegis_session": cookie}, follow_redirects=False,
    )
    assert response.status_code in (200, 204, 303)
    first = approvals.get(approval_id)
    assert before <= first["viewed_at"] <= time.time()
    assert first["viewed_by"] == username
    assert first["status"] == "pending"
    assert first["decided_at"] is None
    time.sleep(0.01)
    response = client.post(
        f"/approvals/{approval_id}/view", data={"csrf": csrf},
        cookies={"aegis_session": cookie}, follow_redirects=False,
    )
    assert response.status_code in (200, 204, 303)
    second = approvals.get(approval_id)
    assert second["viewed_at"] == first["viewed_at"]
    assert second["viewed_by"] == first["viewed_by"]


@pytest.mark.parametrize("identity", ["creator", "viewer"])
def test_post_view_refuses_creator_and_viewer(client, approval_id, identity):
    username = "g1-" + identity + "-" + uuid.uuid4().hex[:8]
    password = "g1-refused-password-123"
    auth.create_user(username, password, "admin" if identity == "creator" else "viewer")
    if identity == "creator":
        # Avoid confusing creator refusal with the demo password-change gate.
        db.conn().execute(
            "UPDATE agent_sessions SET created_by=? WHERE id=("
            "SELECT a.session_id FROM actions a JOIN approvals ap "
            "ON ap.action_id=a.id WHERE ap.id=?)", (username, approval_id),
        )
        db.conn().commit()
    cookie = _login(client, username, password)
    assert cookie
    csrf = _csrf(client, cookie)
    assert csrf
    response = client.post(
        f"/approvals/{approval_id}/view", data={"csrf": csrf},
        cookies={"aegis_session": cookie}, follow_redirects=False,
    )
    assert response.status_code == 403
    row = approvals.get(approval_id)
    assert row["viewed_at"] is None
    assert row["viewed_by"] is None
