"""R7 — speed/load numbers are measured (p50/p95, decisions/sec, per-step),
cold vs warm cache, signer+encryption on, shown on Admin and in the report.
Live timing is waiting for key."""
import re

import pytest
from fastapi.testclient import TestClient

from aegis import bench, config
from aegis.app import app, startup


def test_r7_measure_structure_and_counts():
    res = bench.measure(n=1000)
    assert res["n"] >= 1000
    assert res["machine"]["platform"] and res["machine"]["python"]
    for phase in ("cold", "warm"):
        assert res[phase]["p50_ms"] > 0
        assert res[phase]["p95_ms"] >= res[phase]["p50_ms"]
        assert res[phase]["decisions_per_sec"] > 0
        assert set(res[phase]["steps"]) >= {"signals", "judges", "execute", "shield", "audit_record"}
    assert res["signer"] is True and res["encryption"] is True
    assert res["judge_mode"] in ("standin", "live")


def test_r7_live_timing_waiting_for_key():
    assert not config.live_mode()
    res = bench.measure(n=1000)
    assert res["live_timing"] == "waiting for key"


@pytest.fixture(scope="module")
def client():
    startup()
    from aegis import db
    db.conn().execute("UPDATE users SET must_change=0 WHERE username='dana'")
    db.conn().commit()
    with TestClient(app) as c:
        yield c


def test_r7_admin_bench_endpoint_and_screen(client):
    dana = client.post("/login", data={"username": "dana", "password": "demo-dana-2026"},
                       follow_redirects=False).cookies.get("aegis_session")
    csrf = re.search(r'name="csrf" value="([^"]+)"',
                     client.get("/admin", cookies={"aegis_session": dana}).text).group(1)
    # non-admin refused
    ops = client.post("/login", data={"username": "ops", "password": "demo-ops-2026"},
                      follow_redirects=False).cookies.get("aegis_session")
    assert client.post("/admin/bench", data={"csrf": csrf},
                       cookies={"aegis_session": ops}).status_code == 403
    # admin runs it (small n via env not exposed; endpoint uses 1000)
    r = client.post("/admin/bench", data={"csrf": csrf}, cookies={"aegis_session": dana})
    assert r.status_code == 200
    assert "decisions/sec" in r.text or "p95" in r.text
    assert "stand-in" in r.text or "standin" in r.text