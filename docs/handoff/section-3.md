# Section 3: G2 screen integration handoff

## Hub concurrent-run handback
- After copied-card core fix, full run:2 failed1483 passed28 expected-fail172 subtests. Owner-side tests now require `complete_assessment`: `tests/test_g2_breach_incident.py::test_explicit_completion` fails missing API; `::test_reserved_completion_text` fails DID NOT RAISE ValueError. Please finish your owned component implementation before main reruns acceptance. No core change or test relaxation requested.

## Follow-up: completion and diary prefill (19 November 2026)

The hub handback above described an intermediate RED state. Both named regressions now pass. Current focused command: `.venv/bin/python -m pytest tests/test_g2_breach_clock.py tests/test_g2_breach_incident.py tests/test_g2_breach_views.py tests/test_g2_breach_prefill.py -q` — 63 passed, 47 subtests passed, one existing Starlette/httpx warning. No full suite or scoreboards run here.

- Explicit human non-notifiable completion requires reason, time, confirmation, authenticated admin and CSRF. It stops even an existing notification reminder, preserves original triggers/deadlines and records a terminal human step. No automatic outcome or reopening.
- `breach_incident.complete_assessment(token, csrf, incident_id, *, reason, completed_at, human_confirmed=False)` writes a dedicated bound audit intent through the existing API, then an encrypted append-only step; `project` verifies the dedicated receipt before accepting completion. Intent without a committed verified step is not completion. Existing audit/evidence/db modules were only called, never edited.
- `breach_prefill.pdpc_fact_prefill(verified_incident)` reads only stored count/data/harm facts in append order. Unknowns are blank; zero/False survive; explicit empty/malformed values blank rather than resurrecting stale facts. It never counts audit events or parses narrative text.
- G2 router already passes prefill and completion to its own template. Mount it once using the exact include_router below; no further core edit is needed for G2's own prefilled screen. For an existing alarm/report handler: authenticate the real human, resolve its server-authorized incident ID (not an audit ID), call `incident_store.get_incident(user, incident_id)`, then `pdpc_fact_prefill(stored)` and pass the result as `prefill`. Never accept request-supplied decoded history; keep unknown fields blank and do not persist prefill automatically. Report-to-incident linkage remains hub-owned.
- Blank count/Unknown harm on save mean no update to prior saved facts because existing storage cannot encode clearing them. UI labels say this. Explicit blank data is persisted and clears data prefill.
- No production mounting, full-app/browser acceptance, cross-process serialization or raw-audit-to-incident linkage is claimed. Process-local race protection uses the existing shared reentrant lock. All direct human writers must use this adapter, not raw storage.

RED evidence: missing completion API and reserved-text rejection; running-clock completion refused; forged direct-storage completion accepted; missing separate completion form; stale prefill retained explicit malformed/empty data; cleared browser data resurrected. Fixes preserve existing assertions. Three useful helper lanes: completion/screens owner, prefill owner, independent checker, with targeted rechecks and repairs. Skill used: python-testing. Built by Qwen.

## Original section 3 scoped save receipt (historical)

Main-agent quick verification: `.venv/bin/python -m pytest tests/test_g2_breach_clock.py tests/test_g2_breach_incident.py tests/test_g2_breach_views.py -q` — 45 passed, 17 subtests passed, one existing Starlette/httpx warning. No full suite or scoreboards were run, per the side-task instruction. Six useful helper lanes covered persistence, screens, initial independent review, final independent review, official PDF verification and race repairs through resumed owners. Shared progress.md was already modified by another task and was left untouched.

3a: calendar component/source verified; 3b: encrypted persistent human facts/log adapter prepared and tested; 3c: isolated router/screens prepared and tested, production integration BLOCKED by shared-file ownership. Exact wiring below. Automatic diary-to-PDPC fact prefill and explicit non-notifiable assessment completion remain open; current completion display covers an explicit notifiable human determination only. No automatic determination, report or send exists.

Built by Qwen.

## Owned files

- aegis/breach_views.py
- templates/breach_clock.html
- tests/test_g2_breach_views.py
- docs/handoff/section-3.md

No existing shared app, template, gateway, policy, audit, database, signer or evidence files were edited. The screen calls existing incident_store storage rather than introducing storage or notification services.

## Required production wiring (not applied)

Production breach-clock routes are NOT mounted. There is no automatic router discovery in the existing app. In aegis/app.py, after render is defined, add exactly:

```python
from .breach_views import make_router

app.include_router(make_router(render))
```

This exposes GET /breach-clock, GET /breach-clock/{incident_id}, POST /breach-clock and POST /breach-clock/{incident_id}/steps. Existing application middleware and render context remain in use.

In templates/alarm.html, inside the existing Incident report card after its explanatory paragraph, add:

```html
<p><a href="/breach-clock">Breach clocks and human incident log</a></p>
```

In templates/incident_report.html, immediately after the opening notice banner, add the same link:

```html
<p><a href="/breach-clock">Breach clocks and human incident log</a></p>
```

These edits belong to the shared app/template owner, not this delivery. R9 prefill is NOT complete: the screen displays persisted human-supplied facts, not an automatically resolved R9 report or audit-evidence prefill. The links do not imply report-service integration.

## Behavior and limits

Both reminders use the existing breach_clock projection with Asia/Singapore calendar dates. A confirmed human notifiable determination displays assessment completed, on time or late, preserving the assessment deadline instead of showing an active overdue assessment countdown. Notification remains a reminder only.

Projection rejects conflicting confirmed trigger values rather than picking the first. Future, reversed, negative and out-of-range stored dates yield a safe HTTP 422 detail without incident content. Epoch conversion failures are normalized before rendering. Explicit confirmation/date mismatches also fail. Identical repeated confirmed timestamps are not conflicts. Step records remain in stored sequence.

Authentication uses the human web-session cookie; helper-token requests are refused. Reads require admin/approver/auditor with the password-change gate satisfied. Writes require admin and valid CSRF; existing storage rechecks identity, role and integrity. No decision, reporting or sending is performed. The screen says reminder, not legal advice and reminds about affected people as soon as practicable, at the same time as or after the PDPC. Existing base styling and Built by Qwen remain inherited.

## Write race boundary

The route awaits and parses the form before entering any lock. Writes now delegate to the hardened breach_incident adapter rather than duplicating history validation. Its add_step holds the existing audit._LOCK (threading.RLock) continuously across authoritative history read, trigger validation and incident_store.add_step's committed append; nested storage/audit acquisitions are reentrant. There is no await in this critical section.

Remaining limitation: this is process-local coordination, not a cross-process transaction lock. Every competing writer in this process must use the same adapter/lock boundary; direct storage callers can bypass canonical-trigger validation. Multiple workers/processes do not share this RLock. Cross-process serialization/transactional validation is not implemented or claimed by these owned files.

## Official source receipt

Public-source verification was reported by a separate helper today (19 November 2026); this section records that supplied receipt, not a new fetch by this screen agent. No claim is made that this is the newest revision.

PDPC Guide on Managing and Notifying Data Breaches under the PDPA, revised 15 March 2021:

https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/guide-on-managing-and-notifying-data-breaches-under-the-pdpa-15-mar-2021.pdf

- Printed page 22: conduct a reasonable and expeditious assessment within 30 calendar days of credible grounds to believe a data breach occurred.
- Printed page 25: notify the Commission as soon as practicable, no later than 3 calendar days after determining the breach is notifiable.
- Footnote 6: day 1 is the day after determination; determination on January 1 gives a January 4 notification ceiling.
- Affected individuals: notify as soon as practicable, at the same time as or after notifying the Commission, where individual notification is required.

The product remains a reminder, not legal advice; humans determine notification obligations and perform reporting/sending.

## Verification evidence

Only the owned quick test file was run:

```sh
.venv/bin/python -m pytest tests/test_g2_breach_views.py -q
```

Before the projection/template fixes: 9 failed, 8 passed. Five invalid stored-date cases returned 200 instead of 422; two out-of-range cases raised OverflowError; both assessment-completion cases lacked completed/on-time/late output. This was a genuine regression RED run against the previous implementation.

Race regression RED: 1 failed, 17 passed in 2.22s after correcting test endpoint discovery. The deterministic two-thread test observed history reads and append outside audit._LOCK (ownership values all False). It coordinates the first append and competing submission with events, requires exactly one committed step and a 303/422 result pair, and checks that form parsing happens outside the lock. GREEN after delegation: 18 passed, 1 warning in 2.17s.

Earlier projection fixes: 17 passed, 1 warning in 2.17s. The warning is the existing Starlette/httpx deprecation. Tests mount the router in an isolated FastAPI app and use existing incident storage for save/read checks; malformed stored rows are injected at the storage boundary to verify GET failure handling. No full suite, production startup, internet, staging or commits were performed.
