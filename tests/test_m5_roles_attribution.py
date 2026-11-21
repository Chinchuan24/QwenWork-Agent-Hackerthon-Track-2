"""M5 — monitor mode (decides and logs but lets everything through) is an
admin-only mode like 'off', and suite runs are attributed to the person who
actually started them, not hard-coded to 'dana'."""
import re

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as app_module
from aegis import db, redteam


@pytest.fixture(scope="module")
def client():
    app_module.startup()
    # Trusted setup isolates role attribution from forced password change.
    db.conn().execute("UPDATE users SET must_change=0 WHERE username IN ('ops','dana')")
    db.conn().commit()
    with TestClient(app_module.app) as c:
        yield c


def _login(client, u, p):
    r = client.post("/login", data={"username": u, "password": p}, follow_redirects=False)
    return r.cookies.get("aegis_session")


def _csrf(client, cookie, path="/live"):
    r = client.get(path, cookies={"aegis_session": cookie})
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def test_m5_monitor_mode_admin_only(client):
    ops = _login(client, "ops", "demo-ops-2026")
    csrf = _csrf(client, ops)
    r = client.post("/live/run", data={"scenario": "demo:S1", "mode": "monitor", "csrf": csrf},
                    cookies={"aegis_session": ops})
    assert r.status_code == 200
    assert "MONITOR" not in r.text  # monitor skipped for non-admin, like off
    dana = _login(client, "dana", "demo-dana-2026")
    csrf = _csrf(client, dana)
    r = client.post("/live/run", data={"scenario": "demo:S1", "mode": "monitor", "csrf": csrf},
                    cookies={"aegis_session": dana})
    assert r.status_code == 200 and "MONITOR" in r.text


def test_m5_suite_runs_attributed_to_starter(client):
    ops = _login(client, "ops", "demo-ops-2026")
    csrf = _csrf(client, ops, "/redteam")
    r = client.post("/redteam/run", data={"subset": "smoke", "csrf": csrf},
                    cookies={"aegis_session": ops})
    assert r.status_code == 200
    rows = db.conn().execute(
        "SELECT created_by FROM runs ORDER BY created_at DESC LIMIT 30").fetchall()
    assert rows and all(row["created_by"] == "ops" for row in rows)


def test_m5_run_suite_created_by_threaded_through():
    sb = redteam.run_suite("enforce", kind="attacks", subset="smoke", created_by="ops")
    for r in sb["results"]["attacks"]:
        row = db.conn().execute("SELECT created_by FROM runs WHERE id=?", (r["run_id"],)).fetchone()
        assert row["created_by"] == "ops"