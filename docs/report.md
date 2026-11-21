# Twinguard — final report (updated 2026-11-17 after the review fix pass)

> Historical report, superseded for current acceptance by `docs/final-audit/board.md` and the scoped `docs/final-audit/section-7.md` review. Completion language, counts and open items below describe the 2026-11-17 checkpoint only, not current release acceptance. Preserved as history. Current container packaging has static repairs but no container runtime verification in this Section 7 review. Approved-prototype S5 expects BLOCK; original sponsor HOLD remains a historical mismatch.

One continuous build (phases 0–7), then a full fix pass over the external review's
22 items (B1, H7, H1–H6, H8, B2, M1–M12). Every fix was written test-first:
a failing test reproducing the defect, then the fix, then the full check suite.
No existing test was weakened, skipped or deleted; no outcome is hard-coded.

## Review items — status

| Item | Status | Evidence |
|---|---|---|
| B1 live Qwen path (nested limits, unsure verdict, tool types, leak text, endpoint/retry) | **Fixed in code; live confirmation waiting for key** | `tests/test_b1_live_path.py` (9 tests) drive the real live path with a simulated transport: nested limits parsed, unreadable injection verdict → withhold + `shield_unsure` audit + Hold, typed worker tool schemas, leak judge receives confidential text in random markers, retry-with-pause then fail-closed, model listing verifies names. Real endpoint/model confirmation and a live Acme session need `AEGIS_QWEN_API_KEY` |
| H7 worker spending cap | **Fixed** | one `_chat` transport for every Qwen call; worker path adds per-session budget + payload size limit; refusals audited; `app.py` makes no direct model calls (6 tests) |
| H1 refund cap bypass | **Fixed** | totals count the amount actually paid (executed results, incl. day-cap query); per-invoice refunded totals; hard over-value rule no approval can override; A13 uses ledger-matching amounts and stops via totals rules (8 tests) |
| H2 cross-client email leak | **Fixed** | read scope lock, scoped inbox/contact listings, client emails count in mixed-data and as protected paste/leak sources; attack A49 (6 tests) |
| H3 canary/secret evasions | **Fixed** | all 7 proven evasions blocked: NFKC, base64/hex/URL/HTML decoding (depth 3), skeleton matching forwards+reversed, registered vault secrets, joined-field scan; normal text unaffected (11 tests) |
| H4 injection outside email body | **Fixed** | every text field of every tool result shielded; cleaned/decoded scoring; overlapping 4k chunks; over-cap withheld; suspicious/unsure withheld; real sanitisation; all results wrapped as DATA (8 tests) |
| H5 red team kill switch | **Fixed** | run-local simulation only; real setting never written; stays on through suites; real sessions unaffected (3 tests) |
| H6 audit tampering | **Fixed (+ follow-up)** | checkpoint with every record, chained signatures; Verify catches deleted newest records, deleted checkpoint file + truncated log, removed last/middle lines, reordering; **follow-up:** coordinated rollback (newest N records + newest N checkpoint lines together) now caught by a forward-only external anchor outside the data folder; README/trust report state the exact remaining limits; legacy log migrated (7 + 5 tests) |
| H8 one-time key replay | **Fixed** | key remembered at first call (any verdict); replay returns stored answer; no second action/approval; executed actions never re-run (3 tests) |
| B2 scoreboard as evidence | **Fixed in code; live rows waiting for key** | 25 attacks declare protected facts checked plain+encoded in everything that left; 24 pattern-free evasion injections (reworded, 6 languages, role-play, split, judge-manipulation); every miss listed; scripted/live/evasion rows separate; live worker runner built on the real HTTP path (8 tests) |
| M1 auth | **Fixed** | 600k PBKDF2 + transparent legacy upgrade, hashed web tokens, login throttling, forced change of published demo passwords before privileged actions, /change-password (7 tests) |
| M2 clear secrets in storage/audit | **Fixed** | args masked before storage/audit (encoded forms too), held actions execute masked args, partial redaction evidence (6 tests) |
| M3 intent judge markers | **Fixed** | payload inside random unguessable markers (1 test) |
| M4 empty policy / re-auth | **Fixed** | empty rule set refused; policy activation requires re-authentication (3 tests) |
| M5 monitor role / attribution | **Fixed** | monitor admin-only; suite runs attributed to the actual starter (3 tests) |
| M6 compliance references | **Fixed** | verified against official sources; wrong mappings corrected; unverifiable ISO clause numbers dropped (8 tests) |
| M7 worker launch | **Fixed** | POST+CSRF, concurrency cap 3, cleanup + shutdown termination, token via env never argv; pre-existing session_id KeyError fixed (4 tests) |
| M8 hardcoded clients / empty limits | **Fixed** | client identities defined once in the world; empty client list = no client data may leave, on every path (6 tests) |
| M9 approval facts / revalidation | **Fixed** | reviewer facts on screen (recipient/client, attachment owners, ledger values, redaction state); NEW hold rules at execution void approvals (5 tests) |
| M10 atomicity | **Fixed** | audit append+checkpoint and the whole decide-execute-total path under locks; races reproduced pre-fix and eliminated (3 tests) |
| M11 separation test honesty | **Fixed** | renamed to its true scope; same-user DB access documented as a stated limit with its own test |
| M12 paste check | **Fixed** | absolute 4-gram count (padding-proof) + subject scanning in firewall, leak checker and stand-in judge; dilution evasion reproduced pre-fix (5 tests) |

## Measured numbers — SCRIPTED (stand-in judge, real pipeline, full suites)

| Measure | Twinguard OFF (baseline) | Twinguard ON (enforce) |
|---|---|---|
| Main attacks stopped (49 total) | 10/49 | **49/49 = 100%** |
| Main attack runs with data leaked | **26/49** | **0/49 = 0%** |
| Normal tasks completed (22 total) | 22/22 | **22/22 = 100%** |
| Normal actions wrongly held | — | **0/22 = 0%** |
| Main-suite misses | — | **0** |
| Evasion injections stopped (24 pattern-free texts) | 0/24 | **5/24** |
| Evasion runs with protected facts leaked | 24/24 | **19/24 — all 19 listed as misses** |

The 19 evasion misses are honest and expected: reworded meaning that matches no
pattern can only be caught by a live model judge (or by the rule layers when the
exfiltration touches a canary, a secret, scope or a suspicious session — that is
how the 5 stops happen: E04 intent, E09/E14 hidden-character heuristics, E23
registered secret, E24 canary). They are shown on the scoreboard, never dropped.

## Measured numbers — LIVE (Qwen worker + Qwen judges)

**Waiting for key.** No `AEGIS_QWEN_API_KEY` is present in this environment, so no
live number exists yet and none is invented. The live runner is built and runs the
injection, normal and evasion suites through the real worker code over HTTP against
a real gateway server; with a key set, the scoreboard's live row fills in and every
live miss is listed. Live latency must be measured at that time.

## Checks

| Check | Result |
|---|---|
| Automated tests | **191 passed** (was 65; +126 review-fix tests, none removed or weakened) |
| Dependency audit (`pip-audit`) | clean |
| Audit Verify on the real log | **OK** — 3,740 records, 3,051 per-record chained checkpoints + external anchor outside the data folder |
| Full-suite runtime (scripted) | ~1 s; live runtime to be measured with a key |

## Still open (said openly)

1. **Live confirmation (needs the key):** B1 endpoint/model listing against the real
   account, a live Acme session with live-derived limits, live worker email-with-
   attachment and refund, and the B2 live suite rows + latency. Everything that does
   not need the key is done and tested.
2. **M13 (not built, per the cut line):** second-opinion judge for high-risk actions,
   a held-back tuning set, the adaptive attacker.
3. **Attribution wording:** the "everything built by Qwen" claim covers this repo's
   implementation, tests and docs. The external design brief and review input are not
   part of the build. Confirm this framing fits the hackathon rules before submission.
4. **Container image build** was prepared but not test-run (no Docker on the build
   machine); the first `docker compose up --build` on a VM is the verification step.
5. Stated limits unchanged and still true: reworded leaks beyond fact-matching depend
   on the AI judge (best-effort); slow small-piece information leaks only partly
   covered; typed task treated as trusted; sender identity from the sandbox mail
   system; process-level separation on one machine. Audit: a coordinated data-folder
   rollback IS detected via the external anchor; NOT detected is an attacker who
   controls the database, signing key, checkpoint file AND the external anchor
   location together, or a rollback that predates the external anchor's creation.

## Where things are

- Code: repository root (`.`) (git history: one commit per review item)
- Run: `.venv/bin/python run.py` → http://127.0.0.1:8080 (change demo passwords first)
- Checks: `./check.sh`
- Logs: `docs/progress.md` (one line per item), `docs/decisions.md` (D13–D20 for this pass)

---
*Everything in this project was built by Qwen.*