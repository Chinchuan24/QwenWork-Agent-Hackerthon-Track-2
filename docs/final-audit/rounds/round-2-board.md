# Overnight Round 2

Method: same assistant, fresh public-boundary and model-accounting lens; not independent agents. Read round-1-board.md and cross-linked ON-001/002/003 before assessing fixes. Single fixer owner: main. No code fixes accepted this round.

| ID | Area | Severity | Source and reproduction | Cause / grouping / owner | Status |
|---|---|---|---|---|---|
| ON-004 | Abuse/cost | High | aegis/qwen_client.py:118-137: response with valid choices/message but negative completion_tokens raises JudgeUnavailable; unlike missing usage, it never sets model_usage_unknown. Next call remains admissible | Group with usage/accounting failure handling; main | Open, reproduced with patched local transport and disposable DB: JudgeUnavailable, usage_unknown=false, subsequent_admission=allowed. No real API call. |
| ON-005 | Public audit claim | Medium | aegis/production.py:243-256 reports signer=true from an in-process HMAC digest, not a separate signer; page correctly says simulated, readiness field can mislead operators | Group with ON-003 claim honesty; main | Open |

Read production.py entire367 lines, qwen_client.py entire543 lines, public_evaluator.py41 lines, production and HTTPS tests and prelaunch tests. Public routes use strict host/HTTPS boundary, allowed simulated roles only, CSRF and exact form-field checks; no executor/model imports. Source review does not certify every injection/traversal variant.

All30 shards rerun fresh:2081 nodes, receipt aegis-overnight-round-02/aegis-test-shards-fb8el3hy.json. Initial753.610s failed because oversized lanes timed out; unchanged-revision per-node resume returned passed. Prior timeout scheduling problem recurred; no weakening or dropped nodes. Production HTTPS browser/restart, fresh-clone setup, dual-guard/R09 and prior-fix regressions included, not separate fresh scoreboard measurement.

| Area | Acceptance | Evidence / limit |
|---|---|---|
| Security/auth/session/CSRF/headers/injection/SSRF/traversal | FAIL broad acceptance | Fresh public boundary + auth review and full regressions; private input surfaces not all freshly reviewed |
| Secrets/privacy | FAIL | Release scan pending; public code no live-key imports |
| Abuse/quotas/cost | FAIL | ON-004; regressions passing do not cover every accounting fault |
| Reliability/crash | FAIL broad acceptance | HTTPS SIGKILL and storage regressions passed; scheduling ON-002 persists |
| Integrity/chain | FAIL broad acceptance | In-process public chain differs from private signer; fresh private review pending |
| Policy/disagreement/HOLD/BLOCK/R09/S5 | FAIL broad acceptance | Full suite passed; original sponsor mismatch retained |
| Five stories | FAIL broad acceptance | Public evaluator inspected, full synthetic tests passed; separate scoreboard pending |
| Public isolation | PASS scoped | Full suite + complete entrypoint inspection; no outside dispatch |
| UX | FAIL | Fresh interaction checklist pending |
| WCAG/keyboard | FAIL | Public HTML lacks explicit skip navigation; comprehensive audit pending |
| Performance | FAIL | Fresh p95/error workload pending |
| Docs/clone/env/singlecommand | FAIL broad acceptance | Full setup regressions passed; Part B pending |
| Render/Fly/Railway | FAIL broad acceptance | Full config tests passed; fresh source review pending |
| Dependencies/licences | FAIL broad acceptance | Native closure inherited; fresh review pending |
| Claim honesty | FAIL | ON-003/005 |
| Release/largefiles/manifest | FAIL | Final refresh pending |

New findings2 (high1,medium1). High/critical open; stopping rule NOT met. apply_patch still absent: command -v returned exit1 with no path. MCP discovery returned zero file tools; no fake repair claimed. This is not a reason to count unexecuted rounds or mark Part B complete.
