"""Read-only, allowlisted projection of persisted red-team measurements."""
import json
import math
import re
from datetime import datetime, timezone

from . import db, evidence

BOARD_ROLES = ("admin", "approver", "auditor")
CATEGORIES = (
    ("main", "Stored main suite", "mixed attacks"),
    ("evasion", "Reworded attacks", "evasion"),
    ("adaptive", "Shape-shifting attacks", "adaptive attacks"),
    ("injection", "Trick emails", "prompt injection"),
    ("exfiltration", "Data theft", "exfiltration"),
    ("fake_approval", "Fake approval", "identity spoofing"),
    ("tampering", "Record tampering", "record integrity"),
    ("overreading", "Quiet over-reading", "scope creep"),
    ("claims", "Made-up numbers", "unsupported claims"),
    ("sponsor", "Sponsor's five scenarios", "business scenarios"),
)


def _authorize(role):
    if role not in BOARD_ROLES:
        raise PermissionError("Attack board access refused")


def _timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def project_attack_board(stored, *, role, audit_rows=()):
    """No execution, writes, text passthrough, or inferred category attribution.

    audit_rows are optional stored audit mappings. Only second_opinion verdicts
    and integer proof IDs are exposed; raw reasons and content are omitted.
    """
    _authorize(role)
    if not isinstance(stored, dict):
        stored = {}
    board = {"headline": None, "rows": [], "misses": [], "recent": [],
             "waiting_for_key": False, "warnings": [], "individual_misses": []}
    live = stored.get("live")
    if not isinstance(live, dict):
        live = {}
    board["waiting_for_key"] = live.get("waiting_for_key") is True
    sources = []
    for key, field in (("main", "on"), ("evasion", "evasion_on"),
                       ("adaptive", "adaptive_on")):
        source = stored.get(field)
        if isinstance(source, dict) and field + "_results" in stored:
            source = dict(source, results=stored[field + "_results"])
        sources.append(("scripted", key, source))
    sources += [("live", key, live.get(key)) for key in ("main", "evasion")]
    records = []
    for record in audit_rows:
        try:
            record = dict(record)
            if record.get("event") != "second_opinion" or type(record.get("id")) is not int or record["id"] <= 0:
                continue
            detail = record.get("detail_json")
            detail = json.loads(detail) if isinstance(detail, str) else detail
            if not isinstance(detail, dict):
                continue
            guards = {}
            for name, field in (("aegis", "a"), ("delta", "b")):
                answer = detail.get(field)
                verdict = answer.get("verdict") if isinstance(answer, dict) else None
                guards[name] = verdict if verdict in ("safe", "unsafe", "unsure", "error", "timeout") else "not recorded"
            records.append({"proof_id": record["id"], "run_id": record.get("run_id"),
                            "run_at": _timestamp(record.get("ts")),
                            "outcome": detail.get("outcome") if detail.get("outcome") in ("block", "hold") else None,
                            **guards})
        except (TypeError, ValueError):
            continue
    records.sort(key=lambda r: r["proof_id"], reverse=True)
    board["recent"] = [{k: v for k, v in r.items() if k != "run_id"}
                       for r in records if r["outcome"] and r["run_at"]][:20]
    for execution, key, source in sources:
        label, technical = next((label, technical) for cat, label, technical in CATEGORIES if cat == key)
        row = {"key": key, "label": label, "technical": technical,
               "execution": execution, "tried": None, "stopped": None,
               "spotted": None, "missed": None, "legacy_stopped": None,
               "run_at": None, "judge_mode": "not recorded", "risk": "not linked",
               "aegis": "not recorded", "delta": "not recorded", "proof_refs": []}
        if isinstance(source, dict) and source.get("mode") == "enforce":
            fields = ("attacks_total", "attacks_harm_stopped", "attacks_detected", "attacks_stopped")
            counts = [source.get(field) for field in fields]
            ts = _timestamp(source.get("ts"))
            if ts and all(type(n) is int and n >= 0 for n in counts) and counts[0] > 0 and all(n <= counts[0] for n in counts[1:]) and source.get("judge_mode") in ("standin", "live"):
                row.update(tried=counts[0], stopped=counts[1], spotted=counts[2],
                           missed=counts[0] - counts[1], legacy_stopped=counts[3],
                           run_at=ts, judge_mode=source["judge_mode"])
                # Only explicit stored result associations can connect guards to a suite.
                results = source.get("results", {})
                attacks = results.get("attacks", []) if isinstance(results, dict) else []
                run_ids = {a.get("run_id") for a in attacks if isinstance(a, dict) and isinstance(a.get("run_id"), str)} if isinstance(attacks, list) else set()
                linked = [r for r in records if isinstance(r["run_id"], str) and r["run_id"] in run_ids]
                row["proof_refs"] = [r["proof_id"] for r in linked]
                for guard in ("aegis", "delta"):
                    verdicts = sorted({r[guard] for r in linked})
                    row[guard] = ", ".join(verdicts) if verdicts else "not recorded"
                if row["missed"]:
                    board["misses"].append({"label": label, "execution": execution,
                                             "count": row["missed"], "run_at": ts,
                                             "proof_refs": row["proof_refs"]})
        if isinstance(source, dict):
            results = source.get("results", {})
            attacks = results.get("attacks", []) if isinstance(results, dict) else []
            inconsistent = False
            details = []
            for field in ("harm_misses", "misses"):
                items = source.get(field, [])
                if not isinstance(items, list):
                    inconsistent = True
                    continue
                details.extend(("harm miss" if field == "harm_misses" else "legacy stop miss", item) for item in items)
                expected = row["missed"] if field == "harm_misses" else (
                    row["tried"] - row["legacy_stopped"] if row["tried"] is not None else None)
                if field in source and expected is not None and len(items) != expected:
                    inconsistent = True
            if isinstance(attacks, list):
                for attack in attacks:
                    if not isinstance(attack, dict):
                        inconsistent = True
                        continue
                    if attack.get("harm_stopped") is False or attack.get("stopped") is False or attack.get("leaks"):
                        details.append(("harm miss" if attack.get("harm_stopped") is False or attack.get("leaks") else "legacy stop miss", attack))
                        if (attack.get("harm_stopped") is False or attack.get("leaks")) and row["missed"] == 0:
                            inconsistent = True
                        if attack.get("stopped") is False and row["legacy_stopped"] == row["tried"] and row["tried"] is not None:
                            inconsistent = True
                if row["tried"] is not None:
                    if len(attacks) > row["tried"]:
                        inconsistent = True
                    if sum(isinstance(a, dict) and bool(a.get("leaks") or a.get("harm_stopped") is False)
                           for a in attacks) > row["missed"]:
                        inconsistent = True
                    # Partial details bound counts without treating unknowns as false.
                    for field, count in (("harm_stopped", row["stopped"]), ("detected", row["spotted"]), ("stopped", row["legacy_stopped"])):
                        known = [a[field] for a in attacks
                                 if isinstance(a, dict) and type(a.get(field)) is bool]
                        if sum(known) > count or len(known) - sum(known) > row["tried"] - count:
                            inconsistent = True
            else:
                inconsistent = True
            seen = set()
            for kind, detail in details:
                if not isinstance(detail, dict):
                    inconsistent = True
                    identifier = "identifier withheld"
                else:
                    identifier = detail.get("scenario") or detail.get("id")
                    # Only harness-style IDs are public; arbitrary names/text stay masked.
                    if not isinstance(identifier, str) or not re.fullmatch(r"(?:A|E|AD|S)[0-9]{1,6}", identifier):
                        identifier = "identifier withheld"
                marker = (identifier, kind)
                if marker in seen and identifier != "identifier withheld":
                    continue
                seen.add(marker)
                board["individual_misses"].append({"identifier": identifier, "kind": kind,
                    "label": label, "execution": execution, "run_at": row["run_at"],
                    "proof_refs": row["proof_refs"]})
            if inconsistent:
                board["warnings"].append(label + " (" + execution + "): unverified stored results; totals conflict with details or miss lists.")
                board["misses"] = [m for m in board["misses"]
                                   if (m["label"], m["execution"]) != (label, execution)]
                for field in ("tried", "stopped", "spotted", "missed", "legacy_stopped"):
                    row[field] = None
        board["rows"].append(row)
    for key, label, technical in CATEGORIES[3:]:
        board["rows"].append(dict(board["rows"][0], key=key, label=label,
                                  technical=technical, tried=None, stopped=None,
                                  spotted=None, missed=None, legacy_stopped=None,
                                  run_at=None, aegis="not recorded", delta="not recorded",
                                  proof_refs=[], judge_mode="not recorded"))
    measured = [r for r in board["rows"] if r["tried"] is not None]
    # Separate suites may overlap. Never sum them or combine scripted/live runs.
    if len(measured) == 1 and not board["warnings"]:
        r = measured[0]
        board["headline"] = {"tried": r["tried"], "stopped": r["stopped"], "got_through": r["missed"]}
    return board


def load_attack_board(user):
    """Authorize before DB access; return only stored settings and audit proof."""
    role = user.get("role") if isinstance(user, dict) else None
    _authorize(role)
    try:
        stored = json.loads(db.get_setting("scoreboard_last", "{}"))
        records = db.conn().execute(
            "SELECT id, run_id, event, ts, detail_json FROM audit "
            "WHERE event='second_opinion' ORDER BY id DESC").fetchall()
        # Decrypt only after authorization; the projection exposes verdicts and
        # proof metadata, never decrypted reasons or attack content.
        records = [dict(record, detail_json=evidence.dec_json(record["detail_json"]))
                   for record in records]
        return project_attack_board(stored, role=role, audit_rows=records)
    except Exception:
        # Storage errors disclose no exception text and never present success.
        return project_attack_board({}, role=role)
