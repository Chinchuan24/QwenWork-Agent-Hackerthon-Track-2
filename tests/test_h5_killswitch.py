"""H5 — the Red Team harness must NEVER write the real kill switch. The
kill-switch scenario is simulated inside its own run; real sessions keep
working while a suite runs, and a real active kill switch stays active."""
from aegis import db, gateway, redteam, suites
from conftest import make_session
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")


def _a41():
    return next(a for a in suites.ATTACKS if a["id"] == "A41")


def test_h5_real_kill_switch_on_stays_on_after_suite():
    db.set_setting("kill_switch", "on", "tests", 0)
    try:
        redteam.run_scenario("enforce", _a41())
        assert db.get_setting("kill_switch", "off") == "on"
        redteam.run_suite("enforce", kind="attacks", subset="smoke")
        assert db.get_setting("kill_switch", "off") == "on"
    finally:
        db.set_setting("kill_switch", "off", "tests", 0)


def test_h5_real_sessions_not_blocked_while_suite_runs(monkeypatch):
    assert db.get_setting("kill_switch", "off") == "off"
    seen = []
    orig = gateway.handle_call
    def spy(token, tool, args, idem=None):
        seen.append(db.get_setting("kill_switch", "off"))
        return orig(token, tool, args, idem)
    monkeypatch.setattr(gateway, "handle_call", spy)
    res = redteam.run_scenario("enforce", _a41())
    assert seen and all(v == "off" for v in seen), "harness wrote the real kill switch"
    # the simulated kill switch still stopped the attack inside its run
    assert res["stopped"]
    assert any(r["rule"] == "HARD-KILL" for s in res["steps"] for r in s["reasons"])
    # a real session works during/after the suite
    _, s = make_session()
    out = gateway.handle_call(s["token"], "list_inbox", {}, None)
    assert out["verdict"] == "allow"


def test_h5_simulated_kill_does_not_leak_across_runs():
    res = redteam.run_scenario("enforce", _a41())
    assert res["stopped"]
    _, s = make_session()
    out = gateway.handle_call(s["token"], "list_inbox", {}, None)
    assert out["verdict"] == "allow"