"""Policy rules: readable YAML, fixed condition vocabulary, no code execution.
A bad policy file is refused and the previous one stays active. Every change
is versioned and logged."""
import time
import yaml


CONDITIONS = {
    "owner_mismatch", "secrets", "url_smuggle", "injection_malicious",
    "injection_suspicious", "scope_violation", "leak_yes", "leak_unsure",
    "pii", "lookalike", "mixed_data", "external_send", "suspicious_session",
    "side_effect", "intent_no", "intent_unsure", "refund_over_cap",
    "refund_total_over", "send_total_over", "claim_ledger_mismatch",
    "unknown_sender", "oversize", "tool_not_allowed", "canary",
    "refund_invoice_over", "exposed_side_effect",
    "high_risk", "second_opinion_unsafe", "second_opinion_unsure",
}
DECISIONS = {"block", "hold", "allow_redacted", "allow"}
RANK = {"allow": 0, "allow_redacted": 1, "hold": 2, "block": 3}
HIGH_RISK_KEYS = {"refund_above": (int, float), "external_send_after_confidential": bool}


class PolicyError(ValueError):
    pass


def validate(doc) -> list:
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise PolicyError("policy must contain a 'rules' list")
    if not doc["rules"]:
        raise PolicyError("policy must contain at least one rule — an empty policy would silently disable every rule")
    seen = set()
    for r in doc["rules"]:
        if not isinstance(r, dict):
            raise PolicyError("each rule must be a mapping")
        rid = r.get("id")
        if not rid or not isinstance(rid, str) or rid in seen:
            raise PolicyError(f"missing or duplicate rule id: {rid!r}")
        seen.add(rid)
        if not r.get("explain") or not isinstance(r["explain"], str):
            raise PolicyError(f"rule {rid}: plain-English 'explain' is required")
        when = r.get("when")
        if not isinstance(when, dict) or not when:
            raise PolicyError(f"rule {rid}: 'when' must be a non-empty mapping")
        for k, v in when.items():
            if k not in CONDITIONS:
                raise PolicyError(f"rule {rid}: unknown condition {k!r}")
            if not isinstance(v, bool):
                raise PolicyError(f"rule {rid}: condition values must be true/false")
        if r.get("decision") not in DECISIONS:
            raise PolicyError(f"rule {rid}: decision must be one of {sorted(DECISIONS)}")
    hr = doc.get("high_risk")
    if hr is not None:
        if not isinstance(hr, dict):
            raise PolicyError("high_risk must be a mapping")
        for k, v in hr.items():
            if k not in HIGH_RISK_KEYS:
                raise PolicyError(f"high_risk: unknown key {k!r} (allowed: {sorted(HIGH_RISK_KEYS)})")
            if not isinstance(v, HIGH_RISK_KEYS[k]):
                raise PolicyError(f"high_risk.{k}: wrong type")
    return doc["rules"]


def high_risk() -> dict:
    """High-risk definition lives in the policy file, not in code."""
    from . import db
    v = active_version()
    if not v:
        return {}
    row = db.conn().execute("SELECT content FROM policy_versions WHERE version=?", (v,)).fetchone()
    doc = yaml.safe_load(row["content"]) or {}
    return doc.get("high_risk") or {}


def active_version() -> int:
    from . import db
    row = db.conn().execute("SELECT MAX(version) v FROM policy_versions").fetchone()
    return row["v"] or 0


def active_rules() -> list:
    from . import db
    v = active_version()
    if not v:
        return []
    row = db.conn().execute("SELECT content FROM policy_versions WHERE version=?", (v,)).fetchone()
    return yaml.safe_load(row["content"])["rules"]


def activate(content: str, by: str, note: str = "") -> int:
    """Validate first; a bad file never replaces the active one."""
    from . import db, audit
    doc = yaml.safe_load(content)
    validate(doc)
    from . import db
    v = active_version() + 1
    db.conn().execute("INSERT INTO policy_versions(version,content,activated_by,ts,note) "
                      "VALUES(?,?,?,?,?)", (v, content, by, time.time(), note))
    db.conn().commit()
    audit.record("policy_activated", {"version": v, "by": by, "note": note,
                                      "rules": [r["id"] for r in doc["rules"]]})
    return v


def ensure_default(path: str):
    if active_version() == 0:
        with open(path) as f:
            activate(f.read(), "system", "default policy v1")


# rules that must exist in every active policy (security fixes ship as new versions)
REQUIRED_RULES = {"R-REFUND-INVOICE", "R-EXPOSED", "R-SECOND-UNSAFE", "R-SECOND-UNSURE"}


def ensure_security_rules(path: str):
    """If the active policy predates a required security rule, activate the
    shipped default as a new version. Never silently edits the active one."""
    missing = REQUIRED_RULES - {r["id"] for r in active_rules()}
    if missing:
        with open(path) as f:
            activate(f.read(), "system", "security update: added " + ", ".join(sorted(missing)))


def evaluate(signals: dict) -> list:
    """Return matched rules sorted strictest first."""
    matched = []
    for r in active_rules():
        if all(bool(signals.get(k, False)) == v for k, v in r["when"].items()):
            matched.append(r)
    matched.sort(key=lambda r: -RANK[r["decision"]])
    return matched


def evaluate_lumen(tool, args, *, client=None, level='public', needed=True,
                   recipient_known=False, invoice_matches=False, paid_total=0,
                   keeps_data=True, confirmed=False, received_in_error=False,
                   delete_contract=False, claims_safe=True, claims_status=None, unannounced=False,
                   financial_status=None):
    """Appendix rule decisions; facts are supplied by the trusted gateway only."""
    import re
    matched = []
    def add(rid, decision):
        matched.append((rid, decision))
    if tool == 'read_file':
        add('R01', 'allow')
        if level == 'regulated' and not needed:
            add('R02', 'block')
    if tool == 'send_email':
        if recipient_known and level in ('public', 'internal'):
            add('R03', 'allow')
        if level in ('client-confidential', 'regulated'):
            add('R04', 'hold')
        if not recipient_known:
            add('R05', 'hold')
        text = args.get('subject', '') + '\n' + args.get('body', '')
        prices = [float(x.replace(',', '')) for x in re.findall(r'(?:SGD|S\$)\s*([\d,]+(?:\.\d+)?)', text, re.I)]
        if client == 'greenstep':
            # Only explicit offer cues immediately followed by grouped amounts.
            offer_amounts = re.findall(
                r'\b(?:quote|price|match)\s*(?:(?:is|of|at|for)\s+)?[:=]?\s*'
                r'([1-9]\d{0,2}(?:,\d{3})+(?:\.\d+)?)'
                r'(?![\d,]|\.\d)(?!\s*[A-Za-z])', text, re.I)
            prices.extend(float(x.replace(',', '')) for x in offer_amounts)
        if prices:
            add('R06' if all(p >= 7200 for p in prices) else 'R07',
                'allow' if all(p >= 7200 for p in prices) else 'hold')
            if client == 'greenstep' and any(p < 6500 for p in prices):
                add('R08', 'block')
        if re.search(r'\bdiscount\b', text, re.I) and not any(r == 'R07' for r, _ in matched):
            add('R07', 'hold')
        if financial_status is not None:
            add('R09', 'block' if financial_status == 'contradicted' else
                'allow' if financial_status == 'supported' else 'hold')
        add('R18', 'block' if claims_status == 'contradicted' else 'allow' if claims_safe else 'hold')
        if unannounced:
            add('R19', 'block')
    if tool == 'accept_terms':
        add('R09', 'block' if financial_status == 'contradicted' else 'hold')
    if tool == 'pay_supplier':
        amount = args.get('amount')
        valid = type(amount) in (int, float) and 0 < amount <= 1000000
        if not valid:
            add('HARD-MONEY', 'block')
        elif invoice_matches and amount + paid_total < 1000:
            add('R10', 'allow')
        else:
            add('R11', 'hold')
    if tool == 'order_supplier':
        add('R12', 'allow' if confirmed else 'hold')
    if tool == 'upload_file':
        if level == 'public':
            add('R13', 'allow')
        elif level == 'internal':
            add('R14', 'block' if keeps_data else 'hold')
        else:
            add('R15', 'block')
    if tool == 'delete_file':
        if level == 'regulated' and received_in_error and delete_contract:
            add('R17', 'allow')
        else:
            add('R16', 'hold')
    return {'decision': max((d for _, d in matched), key=RANK.get, default='hold'),
            'rules': [r for r, _ in matched], 'level': level}
