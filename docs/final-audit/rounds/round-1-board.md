# Overnight Round 1: Partial Audit

Single assistant, fresh security/runner review, not independent agents. Fix owner: main. Source baseline a12366b. Existing handoff, website, todo-board and team-room edits preserved and excluded.

| ID | Area | Severity | File / reproduction / cause | Related / owner | Status |
|---|---|---|---|---|---|
| ON-001 | Evidence reliability | Low | scripts/run_test_shards.py:250,370: output JSON under docs changes the JSON-inclusive revision fingerprint during planning; execution then refuses | ON-002 / main | External output workaround verified; fail-closed check preserved |
| ON-002 | Runner reliability | Medium | Default file partition places browser/adaptive files in large lanes; two lanes exceeded the 300-second cap with jobs=2 | ON-001 / main | Unchanged-revision per-node resume passed; scheduling limitation retained |
| ON-003 | Claim honesty | Medium | README.md:83-94,117 and docs/submission.md report old counts and integration status rather than current evidence | ON-001 / main | Open; no edits made |

## Actual Execution

Initial in-repository receipt: ../overnight-evidence/round-01/aegis-test-shards-hopujv64.json. Inventory2081, collection union verified, execution refused due to changed fingerprint. NOT executed coverage.

External receipt: aegis-overnight-round-01/aegis-test-shards-i8etbq88.json, delivered separately. All30 shards,2081 nodes. Initial execution806.698 seconds with two timed-out shards; unchanged-revision resume completed successfully, using isolated per-node subshards for those two lanes. No timeout cap or test assertions weakened. Receipt includes complete reports and retained log paths. This is one suite cycle, NOT ten audit rounds.

Fresh inspection: auth.py uses parameterized SQL, hashed session tokens, serialized login admission, and verified password-snapshot checks before issuance/change. No new auth vulnerability established. Read team-room rules, README, final-prelaunch-audit, submission, demo-shot-list, runner source/tests and production tests. Full suite includes production/HTTPS, route-role, five-story, financial authority, dual-guard and prior-fix regressions. Passing tests are not exhaustive security proof or fresh reviewer coverage of every area.

## Area Acceptance

| Area | Verdict | Evidence / limit |
|---|---|---|
| Security/auth/session/CSRF/headers/injection/SSRF/traversal | FAIL full acceptance | Scoped regressions passed; only auth freshly inspected, remaining fresh review incomplete |
| Secrets/privacy | FAIL full acceptance | Fresh release scan pending |
| Abuse/quotas/cost | FAIL full acceptance | Suite passed; fresh source review incomplete |
| Reliability/crash | FAIL full acceptance | Suite passed; ON-002 limitation; fresh rehearsal receipts not independently inspected |
| Integrity/chain | FAIL full acceptance | Suite passed; fresh source review incomplete |
| Policy/disagreement/HOLD/BLOCK/R09/S5 | FAIL full acceptance | Suite passed; original sponsor S5 HOLD mismatch preserved; fresh review incomplete |
| Five stories | FAIL full acceptance | Synthetic regressions passed; new scoreboard not separately measured |
| Public isolation | FAIL full acceptance | Suite passed; fresh closure review incomplete |
| UX | FAIL full acceptance | Current recording walkthrough not performed |
| WCAG/keyboard | FAIL full acceptance | No exhaustive fresh keyboard/WCAG audit |
| Performance | FAIL full acceptance | Fresh production-entrypoint p95/errors not measured |
| Docs/fresh clone/env/single command | FAIL full acceptance | Suite setup checks passed; no separately inspected fresh clone receipt |
| Render/Fly/Railway | FAIL full acceptance | Static regressions passed; fresh config inspection incomplete; no deploy |
| Dependencies/licences | FAIL full acceptance | a12366b inherited closure; fresh full review incomplete |
| Claim honesty | FAIL | ON-003 open |
| Release/large files/manifest | FAIL full acceptance | Final refresh/scanner pending |

## Blocker And Handoff

Manual patch attempt failed before any edit: apply_patch executable is absent (shell exit127). No executable source changes, release refresh, or commits made. This board is a documentation artifact created with the available file writer, not a claimed code repair. No Docker, push, signup, deploy, publish, external delivery or key inspection performed.

Minimum ten rounds and two consecutive zero-new-finding rounds NOT met. Part B NOT completed. Existing release left intact. Continue from this receipt and board; do not count retries as additional audit rounds or reuse this one result as ten separate suite executions.
