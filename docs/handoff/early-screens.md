# Early screen remediation handoff

## Fixed, 2026-11-19

- High: viewer approval reasons now use a list-shaped withheld placeholder without decrypting private reasons. Pending, denied, expired and kill-active details render 200 at 1280 and 320 pixels. Encrypted argument and reason sentinels are absent from HTML; viewer approval buttons remain absent.
- Medium: browser unknown routes render the shared error shell with 404 and active kill visibility. JSON requests and API paths retain framework errors.
- Medium: browser malformed audit record IDs render a human-readable shell with 422 and active kill visibility. JSON validation remains 422 with structured details; anonymous malformed-ID behavior still returns 422 without authenticated navigation, not a new login bypass.
- Low: audit export links appear only for admin/auditor. Endpoint role restrictions unchanged.

One app writer. Before continuing, diff inspection confirmed only this lane's imports in the app; subsequent app diffs were reviewed before edits. User clarified that own dirty edits are permitted. No protected core file edited. Prior blocked patch is now implemented, not pending handoff.

## Measured evidence

Baseline command: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest tests/test_early_screens_fixes.py -q --tb=short`.
Original RED: 14 failed, 3 passed. After template edits: 12 failed, 5 passed. Strengthened tests added encrypted argument sentinel and blocked service workers before app fixes; actual RED repeated: 12 failed, 5 passed.

Final command: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest tests/test_early_screens_fixes.py tests/test_r12_browser.py -q --tb=short`.
Actual GREEN: 48 passed, 4 existing lifecycle deprecation warnings, 40.13 seconds. New suite: 17 browser cases; existing relevant suite: 31 browser cases, including actual second-person approval, password reauthentication kill toggle, logout/session expiry, roles, small-window reflow and contrast checks.

Fresh conftest data, key, external anchor and signer configuration precede imports. New contexts block service workers and intercept requests using exact scheme/netloc origin comparison; no external requests or page errors observed. Existing browser suite retains its original guard. No real data, live-model requests, network research, installs, full suite or commits.

## Current recheck, 2026-11-19

At HEAD `11d664e`, the saved repair `cf9a975` remains supported: no later commits touch its app/template/regression files, and a fresh isolated run of `tests/test_early_screens_fixes.py` returned **17 passed, 4 lifecycle warnings in 9.28s**. Command: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest -p no:cacheprovider tests/test_early_screens_fixes.py -q --tb=short`. This is not a rerun of the historical 48-case combined result. Current handlers are at `aegis/app.py:117-134`, viewer withheld reasons at line 547, and unpopulated incident/alarm routes at lines 296-297. No code or tests edited in this document-only triage. See `docs/handoff/section-5-document-contracts.md` for the separate measured document RED and external-owner contracts.

## Remaining gaps

New denial is function-level; expiry and kill are synthetic DB setup. Existing browser suite covers actual approval and kill actions, but not every denial/freeze/reviewer-error combination at both widths. Sentinel tests cover encrypted reasons and arguments, not every private data source. No OS-wide network isolation or complete API confidentiality certification. Populated incident/alarm wiring, all expanded disclosure combinations and exhaustive all-state acceptance remain open. Original audit evidence and scope are preserved in `docs/final-audit/early/screens.md`.
