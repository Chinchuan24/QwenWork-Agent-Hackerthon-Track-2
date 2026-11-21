# Section 6b Evidence Tables

No completion score is asserted. Execution is scripted stand-in, not live. The demo and normal runner were not rerun. This is a focused working-tree snapshot, not release acceptance. A component means a local function or rendered template; gateway means the tested logged action boundary; browser means a real interactive screen journey. Passing one does not establish the others.

## Measured Commands

Executed from the repository root with the existing temporary-state fixtures:

```sh
.venv/bin/python -m pytest tests/test_t2_sensitivity.py tests/test_t6_claims.py tests/test_t3_office_actions.py tests/test_t4_lumen_policy.py tests/test_c1_policy_floor.py tests/test_c3_enforcement_review.py tests/test_c5_rule_match.py tests/test_c6_alarm.py -q
```

Result: **231 passed in 0.58s**. This is a test count, not an attack or submission score. No full suite, demo, normal runner, real data or external service was used. `tests/conftest.py` creates temporary DB, anchors, signer state and a random evidence key before imports, removes the live model key and initializes the existing policy. Actions use invented in-memory worlds. Local signer IPC is used, not external network access. Tests were not modified; selected gateway tests share only this process's temporary state. C5 export parity stubs authorization, integrity and audit writing; C6 management uses a fake adapter. Neither proves operational export or freeze integration.

Documentation test-first command:

```sh
.venv/bin/python -m pytest tests/test_section6_evidence_tables.py -q --tb=short
```

Before this table existed: **3 failed in 0.20s**, all missing-document errors. These are documentation RED checks, not product failures. First post-write validation: 1 failed, 2 passed in 0.18s because the table used a capitalized scope label. The table wording was corrected without relaxing assertions. Final validation: **3 passed in 0.17s**. The validator checks requirement inventory, measured-scope labels and prohibited claim/path patterns; it does not measure product behavior.

## Remaining Track Requirements

Rows describe remaining enforcement or evidence obligations. "Not measured here" is not a claim that implementation is absent.

| ID | Fresh evidence in this lane | Remaining requirement and handoff |
|---|---|---|
| T1 | Not measured here; world fixtures inspected indirectly | Preserve second world and four traps; independently prove file count, identical reset and seed provenance. |
| T2 | Component: `test_t2_sensitivity.py` covers four levels, header conflicts, attachments, mixed data, missing inputs and exact-line provenance | Ground-truth comparison if available; owner-screen labels everywhere; preservation of legacy protections across actual outgoing paths. |
| T3 | Component schemas, bad amounts and changed-document fingerprint; gateway missing/changed-card denial in `test_t3_office_actions.py` | Per-action allow/hold/block, malformed fields, replay, signer-down and exposure matrix; three attacks and two normal tasks per new action; approved-release effects and audit binding. |
| T4 | Component discount/floor precedence and 999/1000/1001 payment checks; selected gateway R15/R18/R02 and scope-log checks | R01-R19 each needs trigger and near-miss proof, all matching rules and exact source lines; split payments, unmatched invoices, unknown recipients and direct non-release of NEVER on all entrypoints. |
| T5 | Gateway: unneeded regulated read blocked; internal overread recorded by `test_t4_lumen_policy.py` | Arguably-needed and finance-needed no-false-alarm cases, many small reads, search/list scope, audit-to-briefing visibility and stricter-outcome disclosure. |
| T6 | Component: `test_t6_claims.py` covers formats, derived totals/days, wrong currency/client/time, attachments, quotes and semantic failure; selected gateway unsupported amount intercepted | Current send/release evidence parity, multi-message context, briefing self-check and owner proof display. No standalone benchmark totals or live judgments measured here. |
| T7 | Not rerun; `tests/test_section6_normal_acceptance.py` and `docs/handoff/section-6.md` belong to the normal-work owner | Earlier owner receipt: 13/16 complete, 81.25%; three false holds, 18.75%; N14/N15/N16 and premature deletion-success notices remain repair handoffs. This is reported prior evidence, not this lane's measurement. Exact five-scenario decision/rule/citation score and zero missed violations still need accepted current gateway receipts. |
| T8 | Not measured here; briefing is dirty and owned elsewhere | Audit-only lines, real proof links, no sensitive repeats, waiting-item deduplication, persisted daily/on-demand generation, large/empty-day tests, injection/number checking and reading-ease proof. |
| T9 | Not measured here | Verified source briefing, at most 150 spoken words, actual 55-65 second media with matching figures and recorded runtime ability. |
| T10 | Not measured here | Owner-only briefing/queue screen, role and reauthentication tests, no yes action for NEVER, real proof links, plain wording and browser journey evidence. |
| T11 | Not measured here | Real worker-session adapter with every action through the logged boundary, reusable watcher skill, tested morning schedule, live model receipts when authorized, evidence-backed runtime-usage claims. |
| T12 | Not rerun; demo owner handles failures | Four ordered moments, exact contrary source lines, clean reset, two-run automated equality and three clean demo repeats, timing/script/recording and submission drafts. No demo score inferred here. |
| T13 | Not measured here; website content is dirty and untouched | Every published figure must match accepted current measurements; screenshots, sample briefing/media and customer copy need review. External sign-in/publication remains operator-only. |
| T14 | Existing scorecard inspected, not edited | Refresh each brief ask, demo moment, deliverable, all 19 rules, five scenarios and four traps against accepted scoped receipts. Keep all missing proof explicit. |

## Remaining Security Requirements

C requirements are inventoried from the existing `docs/track2-scorecard.md`, `docs/proof-pack-check.md`, `docs/rule-match.md` and related tests. The supplied Track planning document defines T requirements, not the complete original C planning specification; exhaustive C-spec reconciliation remains with the lead.

| ID | Fresh evidence in this lane | Remaining requirement and handoff |
|---|---|---|
| C1 | Gateway: six safe-boundary cases in `test_c1_policy_floor.py` stop email execution when either independent guard is unsure/unsafe/errors despite empty policy results | Every outside action and model-egress path, distinct guard inputs, current facts at release, paired recorded verdicts and measured latency. `test_c1_model_egress.py` inspected but not run; mocked transport is not live service proof. |
| C2 | No fresh execution; `test_c2_attack_board.py` inspected | Stored-result equality, visible individual misses despite optimistic totals, run/guard/risk links and route/browser proof. Synthetic projection results must not be quoted as actual attack totals. |
| C3 | Gateway: `test_c3_enforcement_review.py` proves changed-card approved-send refusal, restricted discovery/inbox, folder bounds, off-mode freeze/never/money restrictions and cumulative cap | Full ask/alone/never permissions across all tools and modes, expiry/revocation races, authenticated versioned changes, current release facts and permanent history integration. Dirty approvals work is another owner's lane. |
| C4 | Component only: C5 tests exercise real projection/seal with boundary stubs and unreadable-source parity | Authorized date-range route, dedicated trusted signing-key delivery, actual audit-integrity failure warning, historical card/rule bindings, no unsupported coverage promotion and browser export. A valid seal is not proof of truthful history. |
| C5 | Component: exact risk catalog, missing-proof/unreadable-source state, detached rows, source metadata and inert template tested | Readable official-source extraction and version/publication resolution; independently validated mitigation receipts and authorized routes. No sources fetched here. Catalog provenance is recorded research, not fresh legal verification. |
| C6 | Component: Singapore calendar deadline, invalid/future/naive clocks, no automatic determination, inert escaped template and fake-adapter commands tested | Trusted human assessment, real helper-specific freeze/global stop, agent unfreeze refusal, incident links/history, integrated reminder and browser proof. No notification or automatic legal determination established. |

## Proof Boundaries And Handoffs

- No browser acceptance, deployed application, live judgment, external action or framework mitigation score was measured.
- Selected tests run against the concurrent working tree, including read-only dependencies in dirty approvals/briefing. Results are a snapshot, not proof that concurrent integration or the complete suite is green.
- Lead owns shared gateway/policy/audit repairs and broader preservation verification. This lane does not alter shared core, suites, progress, demo, normal-work tests or other agents' files.
- Normal-work owner retains N14/N15/N16 and premature success-notice regressions. Demo owner retains demo failures; no duplicate runner was launched.
- Original C planning-spec reconciliation, official-source resolution, live/runtime/schedule/media and browser evidence remain unresolved handoffs. No score is fabricated from file existence or old progress totals.
- Only this table and `tests/test_section6_evidence_tables.py` are created. No commits. `apply_patch` was unavailable in PATH; dedicated file tools were used without installing tooling.
