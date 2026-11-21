"""R7 — speed and load measurement. Times each pipeline step and the whole
gateway decision over >=1000 calls, reports p50/p95 and decisions/second,
cold vs warm judge cache, with the signer and encryption ON (the real path).
Live timing is waiting for key. Numbers are measured, never asserted."""
import platform
import statistics
import sys
import time
import uuid

from . import config, db, gateway, qwen_client


def _pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100 * (len(s) - 1)))))
    return round(s[k] * 1000, 3)   # ms


def _instrument(monkeypatch_target=None):
    """Wrap pipeline steps with timers; returns (timings, restore)."""
    timings = {}
    originals = {}
    targets = {
        "signals": (gateway, "_session_signals"),
        "judges": (gateway, "_run_judges"),
        "execute": (gateway, "_execute"),
        "shield": (gateway, "_shield_content"),
        "audit_record": (__import__("aegis.audit", fromlist=["record"]), "record"),
    }
    for name, (mod, attr) in targets.items():
        orig = getattr(mod, attr)
        originals[name] = (mod, attr, orig)
        timings[name] = []
        def make(orig, name):
            def wrapped(*a, **k):
                t0 = time.perf_counter()
                try:
                    return orig(*a, **k)
                finally:
                    timings[name].append(time.perf_counter() - t0)
            return wrapped
        setattr(mod, attr, make(orig, name))
    def restore():
        for name, (mod, attr, orig) in originals.items():
            setattr(mod, attr, orig)
    return timings, restore


def _run_calls(n, seed=7):
    import random
    rng = random.Random(seed)
    rid = gateway.create_run("enforce", "bench")
    sess = gateway.start_session(rid, "Email the Acme Q3 report to Rosa at Acme Industries.", "bench")
    token = sess["token"]
    whole = []
    reads = ["doc_acme_q3", "doc_brochure", "doc_acme_contract"]
    for i in range(n):
        gateway._rate.clear()
        gateway._loops.clear()
        if i % 3 == 0:
            tool, args, idem = "send_email", {
                "to": "rosa@acme.example", "subject": "Q3 report",
                "body": "Please find your Q3 report attached.",
                "attachment_ids": ["doc_acme_q3"]}, uuid.uuid4().hex
        elif i % 3 == 1:
            tool, args, idem = "read_file", {"doc_id": rng.choice(reads)}, None
        else:
            tool, args, idem = "read_email", {"email_id": "em_acme_report_req"}, None
        t0 = time.perf_counter()
        gateway.handle_call(token, tool, args, idem)
        whole.append(time.perf_counter() - t0)
        if i % 250 == 0:
            rid = gateway.create_run("enforce", "bench")
            sess = gateway.start_session(rid, "Email the Acme Q3 report to Rosa at Acme Industries.", "bench")
            token = sess["token"]
    return whole


def measure(n=1000) -> dict:
    n = max(1000, n)
    machine = {"platform": platform.platform(), "processor": platform.processor() or platform.machine(),
               "python": sys.version.split()[0], "cpus": __import__("os").cpu_count()}
    # cold cache
    qwen_client._cache.clear()
    timings, restore = _instrument()
    t0 = time.perf_counter()
    cold = _run_calls(n)
    cold_secs = time.perf_counter() - t0
    cold_steps = {k: {"p50_ms": _pct(v, 50), "p95_ms": _pct(v, 95)} for k, v in timings.items()}
    restore()
    # warm cache (judge answers cached)
    timings, restore = _instrument()
    t0 = time.perf_counter()
    warm = _run_calls(n)
    warm_secs = time.perf_counter() - t0
    warm_steps = {k: {"p50_ms": _pct(v, 50), "p95_ms": _pct(v, 95)} for k, v in timings.items()}
    restore()
    return {
        "machine": machine, "n": n, "judge_mode": "live" if config.live_mode() else "standin",
        "signer": True, "encryption": True,
        "live_timing": "waiting for key" if not config.live_mode() else "measured",
        "cold": {"p50_ms": _pct(cold, 50), "p95_ms": _pct(cold, 95),
                 "decisions_per_sec": round(n / cold_secs, 1), "steps": cold_steps},
        "warm": {"p50_ms": _pct(warm, 50), "p95_ms": _pct(warm, 95),
                 "decisions_per_sec": round(n / warm_secs, 1), "steps": warm_steps},
    }