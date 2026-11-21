"""Rule-based detectors. Pure functions; no AI, no network.
Each returns findings: {rule, severity, evidence, redactable}."""
import re
from . import normalize

CARD_RE = re.compile(r"(?:\d[ -]?){13,19}")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
NRIC_RE = re.compile(r"\b[STFG]\d{7}[A-Z]\b")
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|secret|password|passwd|token|bearer)\b\s*[:=]\s*\S{6,}")
AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

INJECTION_PATTERNS = [
    (r"(?i)ignore (?:all |any )?(?:previous|prior|above) instructions", "INJ-01", "instruction override"),
    (r"(?i)disregard (?:the )?(?:system|previous|safety)", "INJ-01", "instruction override"),
    (r"(?i)you are now (?:in )?(?:developer|admin|debug|dan) mode", "INJ-02", "role hijack"),
    (r"(?i)(?:forward|send|email|cc|bcc)\b[^.\n]{0,80}\b(?:all|every|each)\b[^.\n]{0,40}\b(?:invoice|report|document|file|record)", "INJ-03", "bulk exfiltration instruction"),
    (r"(?i)(?:mark|classify|treat|label) (?:this|it|the (?:action|request|content)) (?:as )?(?:safe|benign|harmless|approved)", "INJ-04", "judge manipulation"),
    (r"(?i)do not (?:tell|inform|alert|notify) (?:the )?(?:user|human|admin|auditor)", "INJ-05", "concealment instruction"),
    (r"(?i)system\s*:\s*(?:override|new instructions|admin)", "INJ-06", "fake system message"),
    (r"(?i)<\s*(?:system|instruction|admin)[^>]*>", "INJ-06", "fake system tag"),
    (r"(?i)(?:new|updated) (?:policy|instructions?) (?:from|by) (?:the )?(?:admin|ceo|system)", "INJ-07", "authority spoof"),
]


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def detect_pii(text: str) -> list:
    out = []
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append({"rule": "PII-CARD", "severity": "redact",
                        "evidence": digits[:6] + "…" + digits[-4:], "match": m.group(0)})
    for m in SSN_RE.finditer(text):
        out.append({"rule": "PII-ID", "severity": "redact",
                    "evidence": "national ID pattern", "match": m.group(0)})
    for m in NRIC_RE.finditer(text):
        out.append({"rule": "PII-ID", "severity": "redact",
                    "evidence": "NRIC pattern", "match": m.group(0)})
    return out


def detect_secrets(text: str, known_secrets=()) -> list:
    out = []
    for m in SECRET_RE.finditer(text):
        out.append({"rule": "SEC-01", "severity": "block",
                    "evidence": "credential-shaped text", "match": m.group(0)})
    for m in AWS_RE.finditer(text):
        out.append({"rule": "SEC-02", "severity": "block",
                    "evidence": "cloud key pattern", "match": m.group(0)})
    # registered secret values match exactly however they are phrased
    sk = normalize.skeleton(text)
    for secret in known_secrets:
        ss = normalize.skeleton(secret)
        if ss and (ss in sk or ss[::-1] in sk):
            out.append({"rule": "SEC-03", "severity": "block",
                        "evidence": "registered secret value present", "match": secret})
    return out


def detect_canary(text: str, canaries: list) -> list:
    """Case/space/punctuation-insensitive, forwards and reversed."""
    sk = normalize.skeleton(text)
    out = []
    for c in canaries:
        cs = normalize.skeleton(c)
        if cs and (cs in sk or cs[::-1] in sk):
            out.append({"rule": "CANARY", "severity": "block_freeze",
                        "evidence": "planted canary value present", "match": c})
    return out


def detect_facts(text: str, facts: list) -> list:
    """Protected facts that must not leave, matched in plain, encoded (via the
    caller's decoded variants), spaced, cased and reversed forms."""
    sk = normalize.skeleton(text)
    out = []
    for f in facts:
        fs = normalize.skeleton(f)
        if fs and (fs in sk or fs[::-1] in sk):
            out.append({"rule": "FACT", "severity": "leak",
                        "evidence": "protected fact present in outgoing content", "match": f})
    return out


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def detect_lookalike_domains(text: str, known_domains: list) -> list:
    out = []
    for m in EMAIL_RE.finditer(text):
        dom = m.group(0).split("@", 1)[1].lower()
        if dom in known_domains:
            continue
        for known in known_domains:
            d = _edit_distance(dom, known)
            known_label = known.split(".")[0]
            dom_tokens = dom.split(".")[0].split("-")
            if 0 < d <= 2 or (known_label in dom_tokens and dom != known):
                out.append({"rule": "DOM-LOOKALIKE", "severity": "hold",
                            "evidence": f"{dom} looks like {known}", "match": m.group(0)})
                break
    return out


def detect_url_smuggling(text: str) -> list:
    out = []
    for m in URL_RE.finditer(text):
        url = m.group(0)
        if "?" in url:
            query = url.split("?", 1)[1]
            if len(query) > 20 or normalize.decode_b64_blobs(query):
                out.append({"rule": "URL-SMUGGLE", "severity": "block",
                            "evidence": "data hidden in link parameters", "match": url[:80]})
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            out.append({"rule": "URL-SMUGGLE", "severity": "block",
                        "evidence": "credentials-style URL host", "match": url[:80]})
    return out


def detect_injection(text: str) -> list:
    out = []
    for pat, rule, label in INJECTION_PATTERNS:
        m = re.search(pat, text)
        if m:
            out.append({"rule": rule, "severity": "malicious",
                        "evidence": label, "match": m.group(0)[:100]})
    return out


def injection_score(text: str) -> int:
    """0 clean, 1-2 suspicious, >=3 malicious. Scans every normalised variant."""
    score = 0
    for variant in normalize.scan_texts(text):
        hits = detect_injection(variant)
        score = max(score, 3 if any(h["severity"] == "malicious" for h in hits) else 0)
        if normalize.normalize(variant)["had_invisible"] and re.search(
                r"(?i)(ignore|forward|send|override|instruction)", variant):
            score = max(score, 2)
    return score


def text_overlap(a: str, b: str) -> float:
    """Word 4-gram overlap of a against b — catches pasted document text."""
    def grams(t):
        w = re.findall(r"[a-z0-9]+", t.lower())
        return {tuple(w[i:i + 4]) for i in range(len(w) - 3)}
    ga, gb = grams(a), grams(b)
    if not ga or not gb:
        return 0.0
    return len(ga & gb) / min(len(ga), len(gb))


PASTE_MIN_GRAMS = 5   # 5 shared 4-grams = 8 consecutive words: a paste, not chance


def pasted_text(a: str, b: str) -> bool:
    """Absolute shared-4-gram count: padding the outgoing text cannot dilute
    a pasted paragraph below a ratio threshold."""
    def grams(t):
        w = re.findall(r"[a-z0-9]+", t.lower())
        return {tuple(w[i:i + 4]) for i in range(len(w) - 3)}
    ga, gb = grams(a), grams(b)
    return len(ga & gb) >= PASTE_MIN_GRAMS


def is_paste(a: str, b: str) -> bool:
    """Paste detection used by the firewall, leak checker and stand-in judge:
    absolute count OR high ratio (the ratio covers very short sources)."""
    return pasted_text(a, b) or text_overlap(a, b) > 0.3


def redact(text: str, findings: list) -> tuple:
    """Replace matched sensitive values. Returns (new_text, changes).
    Evidence is partial — full sensitive values never go to storage/audit."""
    changes = []
    for f in findings:
        if f.get("match") and f["match"] in text:
            repl = "[REDACTED:" + f["rule"] + "]"
            text = text.replace(f["match"], repl)
            before = f["match"][:6] + "…" if len(f["match"]) > 12 else "[withheld]"
            changes.append({"rule": f["rule"], "before": before, "after": repl})
    return text, changes