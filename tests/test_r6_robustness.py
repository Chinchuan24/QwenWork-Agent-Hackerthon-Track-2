"""R6 — robustness: random input (5000+ calls, fixed seed), races (money caps,
double-approve, double-idem), and faults (every pipeline step failing in turn).
Every call returns a verdict; nothing malformed is allowed; every fault ends
in hold/block with a reason. Fail closed is proven, not claimed."""
import math
import random
import sqlite3
import threading
import uuid

import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import audit, config, db, gateway, qwen_client
from conftest import make_session
from test_r3_signer import isolated_failure_stream

TOOLS = list(gateway.TOOL_SCHEMAS) + ["run_shell", "delete_all", "", "send_email "]
VERDICTS = {"allow", "allow_redacted", "hold", "block"}


def _junk_args(rng, tool):
    schema = gateway.TOOL_SCHEMAS.get(tool, {})
    args = {}
    for k in schema:
        choice = rng.randrange(10)
        if choice == 0:
            continue                                   # missing field
        elif choice == 1:
            args[k] = None
        elif choice == 2:
            args[k] = rng.choice([123, -5, 0, 1e308, float("nan"), float("inf"), True, False])
        elif choice == 3:
            args[k] = {"nested": {"deep": [1, 2, {"x": "y"}]}}
        elif choice == 4:
            args[k] = ["a", 1, None, {"b": 2}]
        elif choice == 5:
            args[k] = "x" * rng.choice([0, 1, 25000, 300000])
        elif choice == 6:
            args[k] = "null\x00char \u202eRTL \u0430cme \uff21\uff22 mixed 中文 العربية"
        elif choice == 7:
            args[k] = rng.choice(["rosa@acme.example", "attacker@evil.example", "not-an-email"])
        elif choice == 8:
            args[k] = rng.choice(["INV-3007", "doc_acme_q3", "em_task_note", "acme", "page_portal"])
        else:
            args[k] = "ordinary text " + str(rng.randrange(1000))
    if rng.randrange(3) == 0:
        args["unexpected_field"] = "junk"
    return args


def test_r6_random_input_5000_calls_no_crash_no_malformed_allow():
    rng = random.Random(20261118)
    rid, s = make_session(task="Help Acme Industries with their Q3 report request from Rosa.")
    n = 5000
    malformed_allowed = 0
    no_verdict = 0
    for i in range(n):
        gateway._rate.clear()
        gateway._loops.clear()
        tool = rng.choice(TOOLS)
        args = _junk_args(rng, tool)
        idem = uuid.uuid4().hex if tool in gateway.SIDE_EFFECT else None
        if rng.randrange(4) == 0:
            idem = None                              # sometimes omit required idem
        try:
            out = gateway.handle_call(s["token"], tool, args, idem)
        except Exception as e:
            pytest.fail(f"unhandled error on call {i} ({tool}): {type(e).__name__}: {e}")
        if not isinstance(out, dict) or out.get("verdict") not in VERDICTS:
            no_verdict += 1
        # a malformed side-effect call must never be allowed
        if tool in gateway.SIDE_EFFECT:
            err = gateway._validate_args(tool, args) if isinstance(args, dict) else "bad"
            if (err or not idem) and out.get("verdict") in ("allow", "allow_redacted"):
                malformed_allowed += 1
        if i % 200 == 0:
            rid, s = make_session()
    assert no_verdict == 0, f"{no_verdict} calls returned no verdict"
    assert malformed_allowed == 0, f"{malformed_allowed} malformed side effects allowed"


def test_r6_number_edge_cases():
    _, s = make_session(task="Process the refund Cirrus Health asked for by email.")
    for amt in [-100, 0, 1e308, float("nan"), float("inf"), "250", True, 250.000000001]:
        out = gateway.handle_call(s["token"], "issue_refund",
                                  {"invoice_id": "INV-3007", "amount": amt,
                                   "payee": "Cirrus Health"}, uuid.uuid4().hex)
        assert out["verdict"] in VERDICTS
        if isinstance(amt, float) and (math.isnan(amt) or math.isinf(amt)):
            assert out["verdict"] in ("hold", "block"), f"non-finite amount {amt} allowed"
        if isinstance(amt, bool):
            assert out["verdict"] in ("hold", "block"), "boolean amount allowed"


def test_r6_deep_nesting_and_multibyte_no_crash():
    _, s = make_session()
    deep = {"a": "x"}
    for _ in range(60):
        deep = {"n": deep}
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "x", "body": deep}, "k")
    assert out["verdict"] in VERDICTS
    out2 = gateway.handle_call(s["token"], "send_email",
                               {"to": "rosa@acme.example", "subject": "\x00\u202e",
                                "body": "中文 العربية \u0430cme " + "y" * 300000}, "k2")
    assert out2["verdict"] in VERDICTS


def test_r6_token_edge_cases():
    rid, s = make_session()
    assert gateway.handle_call("expired-or-unknown-token", "list_inbox", {}, None)["verdict"] == "block"
    rid2, s2 = make_session()
    # a token belongs to its own session/run; using it acts only there
    out = gateway.handle_call(s2["token"], "list_inbox", {}, None)
    assert out["verdict"] == "allow"
    gateway.freeze_session(s["session_id"], "test")
    assert gateway.handle_call(s["token"], "list_inbox", {}, None)["verdict"] == "block"


def test_r6_race_refunds_never_exceed_caps():
    # multiple sessions in ONE run share the world and the client-day cap
    rid = gateway.create_run("enforce", "dana")
    invoices = ["INV-3007", "INV-3010", "INV-3011"]
    sessions = [gateway.start_session(rid, "Process the refund Cirrus Health asked for by email.", "dana")
                for _ in range(6)]
    errors = []
    def worker(sess, inv):
        try:
            gateway.handle_call(sess["token"], "issue_refund",
                                {"invoice_id": inv, "amount": 250, "payee": "Cirrus Health"},
                                uuid.uuid4().hex)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(sessions[i % 6], invoices[i % 3]))
               for i in range(18)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    from aegis import world
    w = gateway.get_world(rid)
    paid = {}
    for r in w.refunds:
        paid[r["invoice"]] = paid.get(r["invoice"], 0) + r["amount"]
    for inv, total in paid.items():
        entry = world.SEED["ledger"][inv]
        assert total <= entry["amount"] + 0.01, f"{inv} over-refunded: {total}"
    assert sum(paid.values()) <= config.REFUND_CLIENT_DAY_CAP


def test_r6_race_sends_one_session_cap():
    rid, s = make_session()
    errors = []
    def worker(i):
        try:
            gateway.handle_call(s["token"], "send_email",
                                {"to": "rosa@acme.example", "subject": "x",
                                 "body": f"unique {i}"}, uuid.uuid4().hex)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(gateway.get_world(rid).sent) <= config.SEND_SESSION_CAP


def test_r6_race_double_approve_runs_once():
    from aegis import approvals
    rid, s = make_session(task="Process the large refund Cirrus Health asked for by email (INV-3008).")
    out = gateway.handle_call(s["token"], "issue_refund",
                              {"invoice_id": "INV-3008", "source_email": "em_cirrus_refund_large"},
                              uuid.uuid4().hex)
    assert out["verdict"] == "hold"
    ops = dict(db.conn().execute("SELECT * FROM users WHERE username='ops'").fetchone())
    results = []
    def approver():
        results.append(approvals.decide(
            out["approval_id"], ops, "approve",
            reason="Synthetic human review: approve the requested Cirrus refund."))
    threads = [threading.Thread(target=approver) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in results if r.get("ok")) == 1
    assert len(gateway.get_world(rid).refunds) == 1


def test_r6_race_double_idem_runs_once():
    rid, s = make_session()
    key = "race-idem-" + uuid.uuid4().hex
    errors = []
    def worker():
        try:
            gateway.handle_call(s["token"], "send_email",
                                {"to": "rosa@acme.example", "subject": "x", "body": "once"}, key)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(gateway.get_world(rid).sent) == 1


def test_r6_kill_switch_mid_burst():
    rid, s = make_session()
    errors, verdicts = [], []
    def worker(i):
        try:
            if i == 5:
                db.set_setting("kill_switch", "on", "tests", 0)
            out = gateway.handle_call(s["token"], "send_email",
                                      {"to": "rosa@acme.example", "subject": "x",
                                       "body": f"m{i}"}, uuid.uuid4().hex)
            verdicts.append(out["verdict"])
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    db.set_setting("kill_switch", "off", "tests", 0)
    assert not errors, errors
    assert all(v in VERDICTS for v in verdicts)
    assert "block" in verdicts


@pytest.mark.parametrize("fault", ["signals_error", "judge_unavailable", "judge_bad_reply",
                                   "db_locked", "signer_down", "disk_refused"])
def test_r6_faults_fail_closed(monkeypatch, fault, isolated_failure_stream):
    _, s = make_session(task="Email the Acme Q3 report to Rosa at Acme Industries.")
    args = {"to": "rosa@acme.example", "subject": "x", "body": "y"}
    if fault == "signals_error":
        monkeypatch.setattr(gateway, "_session_signals",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    elif fault == "judge_unavailable":
        monkeypatch.setattr(qwen_client, "judge",
                            lambda *a, **k: (_ for _ in ()).throw(qwen_client.JudgeUnavailable("timeout")))
    elif fault == "judge_bad_reply":
        orig = qwen_client.judge
        def bad(kind, payload, model=None):
            if kind == "intent":
                return {"verdict": "unsure", "reason": "unreadable", "mode": "standin"}
            return orig(kind, payload, model=model)
        monkeypatch.setattr(qwen_client, "judge", bad)
    elif fault == "db_locked":
        class LockedConn:
            def execute(self, *a, **k):
                raise sqlite3.OperationalError("database is locked")
            def commit(self):
                pass
        monkeypatch.setattr(db, "conn", lambda: LockedConn())
    elif fault == "signer_down":
        monkeypatch.setattr(config, "AEGIS_SIGNER_PORT", 1)
        audit._signer_health_cache = {"ts": 0, "ok": False}
    elif fault == "disk_refused":
        monkeypatch.setattr(audit, "checkpoint",
                            lambda: (_ for _ in ()).throw(OSError("disk refuses write")))
    out = gateway.handle_call(s["token"], "send_email", args, "fault-" + fault)
    assert out["verdict"] in ("hold", "block"), (fault, out)
    if fault == "signer_down":
        assert any(r["rule"] == "HARD-SIGNER" for r in out["reasons"])
    audit._signer_health_cache = {"ts": 0, "ok": False}