# Independent Chromium Screen Audit

HIGH | Viewer approval details return HTTP 500 instead of redacted content or controlled denial | Log in as viewer and visit /approvals/c9be3598ed33 or /approvals/fdd92aac40f1; repeats at 320/1280px, after decision/expiry and with kill active | aegis/app.py:524-526; fresh evidence.jsonl:413-416,545-546,553-554,745-748. dec_for returns a redaction dictionary for viewer; iterating it produces string keys on which r.get is invalid. Browser proves 500; server traceback was not captured.
MEDIUM | Unknown HTML route loses human-readable shell and active kill status | Turn sandbox kill on via admin browser form then directly visit /not-a-route; raw JSON 404, no heading, branding or kill banner, for all roles and anonymous | aegis/app.py:24; fresh evidence.jsonl:623-624,693-694,763-764,833-834,877-878. Visibility defect, not proof of enforcement failure.
MEDIUM | Invalid audit ID yields framework validation JSON instead of human-readable error and kill status | Directly visit /audit/record/not-an-int with kill on; raw 422 includes int_parsing/loc/input; anonymous also receives validation before login | aegis/app.py:587-588; fresh evidence.jsonl:621-622,875-876; anonymous baseline:45-46.
LOW | Audit displays exports unavailable to approver and viewer | Log in with either role, open /audit and navigate Export CSV/JSON; both endpoints return 403, CSV plain text | templates/audit.html:8; aegis/app.py:599-611; fresh evidence.jsonl link records for /audit/export.csv and /audit/export.json in approver/viewer contexts. Authorization denial is correct; presenting unusable links is the defect.

## Execution And Evidence

Independently read the workspace-local `screens_probe.py` FIRST, then current app routes/startup, config, signer manager, redteam.run_scenario, tests/conftest.py, tests/test_r12_browser.py and docs/browser-check-existing.md. Existing report was not treated as execution evidence.

Actual command, working directory the project root:

```sh
PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B ../screens_probe.py
```

Command completed and printed:

```text
EVIDENCE=<temporary-audit-root>/screens-6vuq5yuy/evidence.jsonl
COUNTS={"browser": 1, "cleanup": 1, "isolation": 1, "kill_restored": 1, "link": 365, "login": 4, "screen": 890, "seed": 8}
```

All references to fresh evidence.jsonl above resolve to that absolute file, not prior-agent artifacts. Chromium 159.0.8154.6 launched successfully (line 2). No blocker/screen_error/pageerror/external_blocked event was recorded; the probe catches exceptions, so completion was checked against event counts and cleanup rather than assuming process completion means audit success. Cleanup line 1271 confirms server_stopped=true and signer_stopped=true; line 905 confirms sandbox kill restored off. Four defects reproduced; NOT release approval.

## Safety Assessment

The inspected probe sets fresh temporary data, external anchor, signer state and random 32-byte evidence key before any aegis import. Removes live-model key and evidence key-file/keyring settings; disables bytecode in parent and inherited signer child. Temporary root screens-6vuq5yuy; data/, external/anchor.json and signer/ are separate paths within it. Config imports create only those temporary data directories. SignerManager starts an owned loopback signer with inherited environment, not a live signer. Fresh app origin http://127.0.0.1:54303 and signer port 54290 are recorded at evidence line 1; live=false. AEGIS_HTTPS=0 ensures synthetic HTTP login works despite ambient HTTPS configuration.

Fresh browser contexts block service workers and intercept all requests with exact scheme/netloc origin comparison. External requests are aborted; none were observed. Source review confirms scripted scenario execution uses isolated world copies; startup model verification is skipped without a key. This is browser network guarding plus reviewed stand-in execution, not an OS-wide network sandbox. No live worker, external account, real action, dependency install, full suite, network research or commit. No screenshot/trace/video capture. Only repository write in this turn is this report; original probe and product/core code unchanged. Synthetic runtime evidence retained outside project.

## Exact Coverage

- All current HTML GET screen routes: /, /live, /approvals, /audit, /policies, /redteam, /compliance, /admin, /change-password, /error, /attack-board, /helper-cards, /rule-match, /incident-report, /alarm, /login. Each measured at 1280x800 and 320x640 in admin, approver, viewer, auditor and anonymous contexts, including kill-active visits. Owner maps to admin/task creator, not a separate role.
- Missing/error direct routes: /run/missing, /approvals/missing, /audit/record/999999, /audit/record/not-an-int and /not-a-route. Valid details: eight generated run routes, two generated approval routes and three recent audit records for every role and anonymous; /audit?verify=1 for authenticated roles after seeding and with kill active.
- Eight existing Scripted enforce scenarios S1, S2, S4b, S5, S9, N22, A01, A02; allow/block/hold states, approve_held=False. Synthetic random-password accounts log in through browser forms. Empty means zero runs/approvals before seeding, NOT no audit/default-policy records: startup/login already records activity.
- 890 measurements and 365 unique-per-role internal-link navigations; no harness exception. Four role logins; eight seeds. Seed and screen results are actual browser/data observations, not execution of the full test suite.
- Admin wrong-password kill, invalid-YAML activation and password-change error forms; anonymous bad credentials; approver real Approve once; all-role post-decision and expired-approval detail visits. Admin uses real password reauthentication to enable and disable kill; setting assertions confirm both. Kill phase revisits every inventory and detail/error route. Successfully rendered application-shell screens display kill status; raw 404/422/500 surfaces do not.
- DOM measurements include document overflow at both widths, headings/branding, text contrast against nearest opaque ancestor, natural Tab focus indicator presence, links and labelled placeholders. No document-level overflow or bad solid-color contrast reported. No blanket accessibility or visual-quality pass: unresolved compositing, input values/placeholders, pseudo-elements and indicator contrast are not certified. Collapsed/disabled descendant candidates cannot reliably establish keyboard reachability.
- Protected HTML direct addresses reach login except pre-handler invalid-ID validation. Viewer governance screens except /rule-match deny access with branded 403; /admin denies non-admin. /login and /error are public. This is not complete API authorization/confidentiality coverage.

## Explicit Gaps

- /incident-report is always supplied report=None and /alarm helpers=[]/alarm=None in current routes (app.py:273-275). Populated report/alarm, countdown/overdue and populated helper branches not exercised. Honest not-connected notices are not findings of fake functionality.
- Populated redteam scoreboard not executed; no full scenario suite or live model mode. No deliberately damaged evidence key, audit tamper state, policy success/version switch, admin benchmark/default-mode result, forced password-change or session expiry/logout-back journey.
- Expanded run arguments/reasons and all disclosure reflow, local clipping/overlap, screenshots/pixel comparisons, zoom, screen readers and complete keyboard-only action journeys not covered. Tab traversal bounded to 180 and stops at repeated focus; long tables and collapsed links remain gaps.
- Deny/freeze/reviewer-error combinations and actions while kill is on not executed. Kill coverage proves screen visibility and setting readback, not end-to-end enforcement.
- /healthz, /api/run/{id}, /compliance/trust-report.json and /openapi.json not treated as HTML screens; complete API boundaries not checked. Exports navigated for authenticated roles, not anonymous direct-address tested; download payload contents not audited. Every historical record and every possible data value not covered.

## Current bounded recheck, 2026-11-19

HEAD `11d664e`: saved repair `cf9a975` remains supported by a fresh isolated `tests/test_early_screens_fixes.py` run: **17 passed, 4 lifecycle warnings in 9.28s**. Command: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest -p no:cacheprovider tests/test_early_screens_fixes.py -q --tb=short`. No later commits touch the repair's app/template/regression files. Historical 48-case evidence below was not rerun. Current error handlers are at `aegis/app.py:117-134`, withheld viewer reasons at line 547; populated incident/alarm gap is still visible at lines 296-297. Original findings and source locations above are historical. This focused recheck does not establish exhaustive screen or confidentiality acceptance. Separate document/path/claim RED handoffs are in `docs/handoff/section-5-document-contracts.md`.

## Authorized remediation, 2026-11-19

All four findings FIXED in this scoped remediation. Viewer reasons use a withheld list without decryption; browser HTML404 and malformed audit-ID422 use the shared shell with kill visibility; export links appear only for admin/auditor. JSON/API validation and authorization status remain unchanged. Prior ownership blocker resolved by user clarification and diff confirmation that app changes were this lane's own. Historical findings above describe pre-fix observations.

Focused command: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest tests/test_early_screens_fixes.py -q --tb=short`.

Actual baseline RED: 14 failed, 3 passed across 17 real browser cases. Post-template change: 12 failed, 5 passed. Stronger encrypted argument sentinel and service-worker blocking were added test-first; repeated RED: 12 failed, 5 passed. After app root and handler fixes, combined command `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest tests/test_early_screens_fixes.py tests/test_r12_browser.py -q --tb=short` returned 48 passed, 4 existing lifecycle deprecation warnings in 40.13 seconds: 17 new and 31 existing browser cases. Eight viewer state/width cases now return 200 with placeholders and no argument/reason sentinel; four HTML404/422 cases retain status and show headings/kill banner. Four export role cases and JSON/auth boundary case pass.

Fresh conftest configuration precedes imports, no real data or live-model key used. New browser contexts block service workers and permit only the exact owned loopback origin; no external traffic or page errors observed. Existing suite retains its original guard and covers actual second-person approval, kill reauthentication, session expiry/logout, roles, reflow and contrast. No network research/install/commit/full-suite activity. No complete confidentiality proof: sentinels cover reasons and arguments; new denial is function-level and expiry/kill are synthetic state setup. Full denial/freeze/error combinations, populated incident/alarm wiring and exhaustive API confidentiality remain open. Original audit coverage and gaps above remain historical, not remediation pass counts.
