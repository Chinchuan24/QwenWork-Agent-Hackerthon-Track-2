import json

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from aegis import db


def sample():
    return {"on": {"mode": "enforce", "ts": 1794960000,
                   "judge_mode": "standin", "attacks_total": 3,
                   "attacks_stopped": 2, "attacks_detected": 1,
                   "attacks_harm_stopped": 2,
                   "harm_misses": [{"id": "A01", "name": "PRIVATE_FIXTURE"}]},
            "live": {"waiting_for_key": True}}


def html(board):
    env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())
    return env.get_template("attack_board.html").render(board=board, user=None)


def test_empty_and_roles():
    from aegis.attack_board import project_attack_board
    for role in (None, "worker", "ADMIN"):
        with pytest.raises(PermissionError):
            project_attack_board({}, role=role)
    board = project_attack_board({}, role="auditor")
    assert board["headline"] is None
    assert all(r["tried"] is None for r in board["rows"])
    assert "not run" in html(board)


def test_counts_masking_and_misses_first():
    from aegis.attack_board import project_attack_board
    source = sample()
    before = json.dumps(source)
    board = project_attack_board(source, role="admin")
    row = board["rows"][0]
    assert (row["tried"], row["stopped"], row["spotted"], row["missed"]) == (3, 2, 1, 1)
    assert row["legacy_stopped"] == source["on"]["attacks_stopped"]
    assert row["run_at"] == "2026-11-18T00:00:00+00:00"
    assert row["execution"] == "scripted"
    assert board["headline"] == {"tried": 3, "stopped": 2, "got_through": 1}
    page = html(board)
    assert "PRIVATE_FIXTURE" not in page
    assert page.index("Got through") < page.index("Attack results")
    assert "waiting for key" in page
    assert json.dumps(source) == before
    assert all(r["tried"] is None for r in board["rows"] if r["key"] not in ("main",))


def test_invalid_data_no_guesses():
    from aegis.attack_board import project_attack_board
    for bad in ([], "broken", {"on": {}},
                {"on": dict(sample()["on"], attacks_harm_stopped=4)},
                {"on": dict(sample()["on"], ts=float("nan"))},
                {"on": dict(sample()["on"], attacks_total=True)}):
        assert project_attack_board(bad, role="admin")["headline"] is None


def test_loader_authorizes_before_read(monkeypatch):
    from aegis.attack_board import load_attack_board
    calls = []
    monkeypatch.setattr(db, "get_setting", lambda key, default: calls.append(key) or json.dumps(sample()))
    with pytest.raises(PermissionError):
        load_attack_board(None)
    assert not calls
    assert load_attack_board({"role": "approver"})["headline"]["tried"] == 3
    assert calls == ["scoreboard_last"]


def test_guard_proofs_recent_masking():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["results"] = {"attacks": [{"run_id": "a" * 32}]}
    records = [{"id": 7, "run_id": "a" * 32, "event": "second_opinion", "ts": 1794960000,
                "detail_json": json.dumps({"a": {"verdict": "safe", "reason": "PRIVATE_FIXTURE"},
                                           "b": {"verdict": "unsafe"}, "outcome": "block"})}]
    board = project_attack_board(source, role="auditor", audit_rows=records)
    assert board["rows"][0]["aegis"] == "safe"
    assert board["rows"][0]["delta"] == "unsafe"
    assert board["rows"][0]["proof_refs"] == [7]
    assert board["recent"][0]["outcome"] == "block"
    assert "/audit/record/7" in html(board)
    assert "PRIVATE_FIXTURE" not in html(board)


def test_oversized_result_details_withhold_headline():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["results"] = {"attacks": [
        {"id": f"A{i:02}", "harm_stopped": True, "detected": False,
         "stopped": True} for i in range(1, 5)]}
    before = json.dumps(source)
    board = project_attack_board(source, role="auditor")
    assert board["headline"] is None
    assert board["rows"][0]["tried"] is None
    assert board["warnings"]
    assert board["misses"] == []
    assert json.dumps(source) == before


def test_loader_malformed_audit_run_id_preserves_board(monkeypatch):
    from aegis.attack_board import load_attack_board
    source = sample()
    source["on_results"] = {"attacks": [{"run_id": "stored-run"}]}
    records = [
        {"id": proof, "event": "second_opinion", "run_id": run_id,
         "ts": 1794960000, "detail_json": {
             "a": {"verdict": "safe"}, "b": {"verdict": "unsafe"},
             "outcome": "hold"}}
        for proof, run_id in ((71, "stored-run"), (72, []))]

    class Connection:
        def execute(self, query):
            return self

        def fetchall(self):
            return records

    monkeypatch.setattr(db, "get_setting", lambda *args: json.dumps(source))
    monkeypatch.setattr(db, "conn", lambda: Connection())
    board = load_attack_board({"role": "auditor"})
    assert board["headline"] == {"tried": 3, "stopped": 2, "got_through": 1}
    assert board["rows"][0]["proof_refs"] == [71]
    assert board["rows"][0]["delta"] == "unsafe"
    assert any(r["proof_id"] == 71 for r in board["recent"])


@pytest.mark.parametrize("field,values", [
    ("harm_stopped", [False, False]),
    ("detected", [True, True]),
    ("stopped", [False, False]),
])
def test_partial_details_cannot_exceed_aggregate_counts(field, values):
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["results"] = {"attacks": [
        {"id": f"A{i:02}", field: value}
        for i, value in enumerate(values, 1)]}
    board = project_attack_board(source, role="auditor")
    assert board["headline"] is None
    assert board["rows"][0]["tried"] is None
    assert board["warnings"]


def test_zero_attack_suite_is_not_run():
    from aegis.attack_board import project_attack_board
    source = sample()
    for field in ("attacks_total", "attacks_stopped", "attacks_detected", "attacks_harm_stopped"):
        source["on"][field] = 0
    board = project_attack_board(source, role="auditor")
    assert board["headline"] is None
    assert board["rows"][0]["tried"] is None


def test_storage_error_fails_closed(monkeypatch):
    from aegis.attack_board import load_attack_board
    def fail(*args):
        raise RuntimeError("PRIVATE_FIXTURE")
    monkeypatch.setattr(db, "get_setting", fail)
    board = load_attack_board({"role": "admin"})
    assert board["headline"] is None
    assert "PRIVATE_FIXTURE" not in html(board)


@pytest.mark.parametrize("detail", ["harm_misses", "results", "misses"])
def test_optimistic_totals_cannot_hide_individual_misses(detail):
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"].update(attacks_stopped=3, attacks_harm_stopped=3, harm_misses=[])
    miss = {"id": "A02", "scenario": "A02", "name": "PRIVATE_FIXTURE",
            "harm_stopped": False, "stopped": False, "leaks": ["PRIVATE_FIXTURE"]}
    source["on"][detail] = {"attacks": [miss]} if detail == "results" else [miss]
    board = project_attack_board(source, role="auditor")
    assert board["headline"] is None
    assert board["rows"][0]["stopped"] is None
    page = html(board)
    assert "unverified" in page.lower()
    assert "A02" in page[:page.index("Attack results")]
    assert "PRIVATE_FIXTURE" not in page


def test_consistent_individual_misses_are_listed():
    from aegis.attack_board import project_attack_board
    board = project_attack_board(sample(), role="auditor")
    assert "A01" in html(board).split("Attack results")[0]


def test_live_separate_and_banned_claims():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["live"] = {"waiting_for_key": False, "main": dict(source["on"], judge_mode="live")}
    board = project_attack_board(source, role="admin")
    assert board["headline"] is None
    assert {r["execution"] for r in board["rows"] if r["tried"] is not None} == {"scripted", "live"}
    page = html(board).lower()
    for phrase in ("compliant", "certified", "approved by", "guarantees"):
        assert phrase not in page
    assert "<form" not in page
    assert "fixed rules" in page


def test_conflicting_totals_withhold_miss_banner():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["harm_misses"].append({"id": "A02"})
    board = project_attack_board(source, role="auditor")
    assert board["rows"][0]["tried"] is None
    assert board["misses"] == []
    page = html(board).split("Attack results")[0]
    assert "A01" in page and "A02" in page
    assert "No misses listed" not in page


def test_complete_results_validate_legacy_count():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["results"] = {"attacks": [
        {"id": "A01", "harm_stopped": False, "detected": True, "stopped": False},
        {"id": "A02", "harm_stopped": True, "detected": False, "stopped": False},
        {"id": "A03", "harm_stopped": True, "detected": False, "stopped": False},
    ]}
    board = project_attack_board(source, role="auditor")
    assert board["headline"] is None
    assert board["rows"][0]["legacy_stopped"] is None
    assert board["misses"] == []


def test_legacy_miss_does_not_contradict_harm_stop():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"].update(attacks_harm_stopped=3, harm_misses=[],
                        misses=[{"id": "A01"}],
                        results={"attacks": [{"id": "A01", "harm_stopped": True,
                                              "stopped": False}]})
    board = project_attack_board(source, role="auditor")
    assert not board["warnings"]
    assert board["rows"][0]["stopped"] == 3


def test_miss_details_label_legacy_failure_without_claiming_harm():
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"].update(attacks_harm_stopped=3, harm_misses=[],
                        misses=[{"id": "A02"}],
                        results={"attacks": [{"id": "A02", "detected": False,
                                              "harm_stopped": True, "stopped": False}]})
    before = json.dumps(source)
    board = project_attack_board(source, role="auditor")
    assert not board["warnings"]
    assert board["misses"] == []
    assert board["headline"] == {"tried": 3, "stopped": 3, "got_through": 0}
    assert {m["kind"] for m in board["individual_misses"]} == {"legacy stop miss"}
    page = html(board)
    assert '<h2 id="misses-title">Stored miss details</h2>' in page
    assert '<section aria-labelledby="misses-title">' in page
    assert "A02: legacy stop miss" in page
    assert '<h2 id="misses-title">Got through</h2>' not in page
    assert json.dumps(source) == before


@pytest.mark.parametrize("outcomes", [(None, None), (False, None)])
def test_explicit_leak_cases_cannot_exceed_harm_miss_count(outcomes):
    from aegis.attack_board import project_attack_board
    source = sample()
    source["on"]["results"] = {"attacks": [
        dict({"id": identifier, "leaks": ["PRIVATE_FIXTURE"]},
             **({"harm_stopped": outcome} if outcome is not None else {}))
        for identifier, outcome in zip(("A01", "A02"), outcomes)]}
    before = json.dumps(source)
    board = project_attack_board(source, role="auditor")
    assert board["warnings"]
    assert board["headline"] is None
    assert board["rows"][0]["tried"] is None
    assert board["misses"] == []
    assert {m["identifier"] for m in board["individual_misses"]} == {"A01", "A02"}
    assert {m["kind"] for m in board["individual_misses"]} == {"harm miss"}
    assert "PRIVATE_FIXTURE" not in json.dumps(board)
    assert json.dumps(source) == before


def test_harm_miss_details_are_explicitly_labelled():
    from aegis.attack_board import project_attack_board
    board = project_attack_board(sample(), role="auditor")
    assert board["individual_misses"][0]["kind"] == "harm miss"
    assert "A01: harm miss" in html(board)


@pytest.mark.parametrize("field,result_field,key,identifier", [
    ("on", "on_results", "main", "A02"),
    ("evasion_on", "evasion_on_results", "evasion", "E02"),
    ("adaptive_on", "adaptive_on_results", "adaptive", "AD02"),
])
def test_sibling_results_cannot_hide_leaks(field, result_field, key, identifier):
    from aegis.attack_board import project_attack_board
    aggregate = dict(sample()["on"], attacks_harm_stopped=3,
                     attacks_stopped=3, harm_misses=[], results={"attacks": []})
    source = {field: aggregate, result_field: {"attacks": [
        {"id": identifier, "leaks": ["PRIVATE_FIXTURE"], "run_id": "stored-run"}]}}
    before = json.dumps(source)
    board = project_attack_board(source, role="auditor")
    row = next(r for r in board["rows"] if r["key"] == key and r["execution"] == "scripted")
    assert row["tried"] is None
    assert board["headline"] is None
    assert identifier in html(board).split("Attack results")[0]
    assert "PRIVATE_FIXTURE" not in json.dumps(board)
    assert json.dumps(source) == before


@pytest.mark.parametrize("role", ["admin", "approver", "auditor"])
def test_loader_encrypted_guards_whitelisted(monkeypatch, role):
    from aegis import evidence
    from aegis.attack_board import load_attack_board
    source = sample()
    source["on_results"] = {"attacks": [{"run_id": "stored-run"}]}
    record = {"id": 71, "event": "second_opinion", "run_id": "stored-run",
              "ts": 1794960000, "detail_json": evidence.enc_json({
                  "a": {"verdict": "safe", "reason": "PRIVATE_FIXTURE"},
                  "b": {"verdict": "unsafe", "reason": "PRIVATE_FIXTURE"},
                  "outcome": "hold", "content": "PRIVATE_FIXTURE"})}
    class Connection:
        def execute(self, query):
            assert "SELECT" in query and "second_opinion" in query
            return self

        def fetchall(self):
            return [record]
    monkeypatch.setattr(db, "get_setting", lambda *args: json.dumps(source))
    monkeypatch.setattr(db, "conn", lambda: Connection())
    board = load_attack_board({"role": role})
    assert board["rows"][0]["aegis"] == "safe"
    assert board["rows"][0]["delta"] == "unsafe"
    assert board["rows"][0]["proof_refs"] == [71]
    assert board["recent"][0]["outcome"] == "hold"
    assert "/audit/record/71" in html(board)
    assert "PRIVATE_FIXTURE" not in json.dumps(board)
