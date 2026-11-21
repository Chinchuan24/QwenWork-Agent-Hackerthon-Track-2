# Section 2 — G1 scoped receipt and core handoff

Built by Qwen. No complete G1 acceptance claim.

## CURRENT STATUS CORRECTION (2026-11-19)
- This addendum supersedes stale missing-API and global helper-capability blockers below; earlier receipts remain historical evidence, not current acceptance status.
- The historical shared-core API request is implemented in `8a836c1`: approvals use `audit.record_decision` with one trusted timestamp, no post-record projection rewrite, and strict `checkpoint_ok` before release. The continuation records 186 scoped integration tests passing after caller interruption rollback repair. This documentation task performed read-only checks, not a test repeat or full-suite run.
- Remaining acceptance is NOT VERIFIED: full integration/full suite and scoreboards, real browser visibility/timing and home approval usability, and signed detection of coordinated database/history rollback. Scoped transaction/checkpoint evidence is not proof of whole-database rollback resistance. Keep 2d/2f unticked; do not describe the implemented API itself as missing.
- Read-only caller classification: `tests/test_h1_refund_caps.py:102` is the only confirmed high-risk omitted-reason candidate. It approves an `issue_refund` for 5000 (lines 98-102), then checks only failure and zero refunds (103-105). `aegis/approvals.py:157-161` rejects a refund approval without a reason before the intended cap check, allowing a silent coverage false positive. The refund caller/test owner must supply a valid synthetic reviewer reason while preserving the cap assertions; no production or test files were changed here.
- Other earlier candidates are NOT proven mandatory-reason failures: `test_m9_approval_facts.py:78` creates email (decision 84); `test_c3_final_gate.py:61,76` holds/releases email; `test_m2_no_clear_secrets.py:68` creates email (decision 73); `test_r1_containment.py:211` creates email (215 approval, 219 replay); `test_c3_card_permissions.py:125` asks for search (129 approval, 130 replay). These are email/search or replay paths, not evidence of a missing mandatory high-risk reason. The broader earlier static list must not be treated as confirmed failures.
- Orchestration correction: the prior zero-helper statement describes only that worker's local lack of delegation, not a global platform limitation. Main launched two helpers this turn (implementation and independent checker); this documentation worker is the third session, for 3 sessions total at this documentation completion. Parent orchestration was used. Launching a checker does not itself establish a passed independent acceptance result.
- Commit scope: only this addendum and the matching todo-board addendum; preserve preexisting document hunks and all other task edits. No production/test edits, test reruns, full suite, or completion claim.

## Done in this side task
- Canonical encrypted, append-only first-view and human-decision events; accepted approvals remain counted after failed release.
- Decision reason/action writes roll back when audit insertion refuses before commit. Post-commit faults preserve history, prevent release and cannot rewrite the accepted decision on replay.
- All current highest-risk approval callers require a short reason. Existing execution tests now supply reasons without changing assertions.
- Morning briefing uses canonical daily decision history ahead of mutable projections, with legacy stored-row fallback, matched reviewer timing and one calm informational warning. Changed work is terminal, never counted as successful execution.
- Real authenticated home regression verifies ten stored approvals, timing samples, private-reason exclusion and terminal link removal.

## Measured evidence
- Persistence RED: 15 failed, 2 passed; one fixture defect corrected separately, not counted as business RED.
- Briefing RED: 7 failed before each relevant implementation round.
- Existing approval callers: 2 failures reproduced, fixed by valid reasons; assertions unchanged.
- Existing home query fixtures: 2 failures reproduced; mocks updated for the new SELECT, assertions unchanged.
- Final scoped command: `.venv/bin/python -m pytest tests/test_g1*.py tests/test_approvals.py tests/test_t8_briefing.py tests/test_owner_home_wiring.py tests/test_t10_owner_home.py -q`
- Result: 174 passed, 34 deprecation warnings. No full suite or scoreboards run by this task.
- Five helper sessions: persistence writer, briefing writer, requirements auditor, independent checker and follow-up final checker. Writers were isolated by file; reviews were read-only.
- Skills: tdd-workflow; helper reviews inspected existing Python/security contracts. No installation or internet operations.

## BLOCKED — exact shared-core changes
1. `aegis/audit.py`: `record()` commits SQLite before checkpointing, and checkpoint refusal may not raise. Provide a transaction-aware decision recording interface with an explicit trusted timestamp and an explicit durable checkpoint success result. Do not bypass triggers, rewrite immutable ciphertext, erase committed events or reset anchors.
2. `aegis/approvals.py`: once that interface exists, remove the post-record timestamp projection update crash window; require checkpoint success before approved release. Pre-commit failure rolls back local writes; post-commit failure retains the canonical decision and must refuse release. Test insertion refusal, checkpoint refusal, process interruption between commit/projection/release, retry and changed/denied compatibility events.
3. Gateway/audit owner: establish signed detection of coordinated database/history rollback using the existing outside anchor. These focused tests establish durable append-only records and local rollback handling, not universal rollback resistance or atomic side effects.
4. Home owner: direct home approval button must route through the review screen or provide equivalent mandatory reason and visible-review telemetry. Do not weaken reason validation.

## Open acceptance
- Full suite and actual scoreboards belong to the main task, not this side task.
- Real browser visibility/timing and home approval usability remain unverified here.
- Shared-core atomic checkpoint acceptance and whole-database rollback detection remain BLOCKED on the above interface. Complete G1 2d/2f must stay unticked until integrated proof exists.
- Existing `tests/test_g1_remaining_acceptance.py` was read/run unchanged and is not included in this task's commit because it was already untracked at arrival.

## G1 continuation receipt (2026-11-19T16:41:07+0800)
- Arrival HEAD: `11d664e`, following wired but unaccepted `8a836c1`. Status/log inspected; no pull/reset, core edits, full suite, scoreboard or installs.
- Baseline decision API/persistence/race command: `.venv/bin/python -m pytest tests/test_g1_decision_record_api.py tests/test_g1_decision_persistence_side.py tests/test_g1_decision_races.py -q`: 30 passed. Integration already uses the trusted timestamp and strict checkpoint result.
- New pre-recording interruption regression RED: 1 failed because caller writes remained in a transaction after KeyboardInterrupt. G1 decide now rolls back BaseException before re-raising; committed history remains intact on postcommit interruption. No reason rule or assertions weakened.
- Scoped GREEN: `.venv/bin/python -m pytest tests/test_g1*.py tests/test_approvals.py tests/test_t8_briefing.py tests/test_owner_home_wiring.py tests/test_t10_owner_home.py -q`: 186 passed, 34 warnings. Existing untracked remaining-acceptance test read/run unchanged, not staged. Decision-record API test was tracked and clean at arrival, read before editing.
- Owned reason caller scan: approval_review.py and briefing.py do not call decide. Owned G1 valid high-risk decisions supply reasons. test_approvals.py:31,38,44,64 intentionally omit reasons to test replay, self/role rejection and expiry before acceptance. No caller repair needed there; owner-home tests already route to review and pass unchanged.
- Nonowned omitted approve-reason candidates for caller owners to classify/repair without weakening rules: tests/test_h1_refund_caps.py:102; tests/test_m9_approval_facts.py:84; tests/test_c3_final_gate.py:76; tests/test_m2_no_clear_secrets.py:73; tests/test_r1_containment.py:215,219; tests/test_c3_card_permissions.py:129,130. Some intentionally test earlier rejection; this is a static candidate list, not a claim these tests fail. Runtime app.py:595 forwards caller reason; redteam.py:49,222 supplies reason. No nonowned callers changed.
- PROBLEM/BLOCKED 2d/2f: scoped checks pass but independent helper acceptance, full integration, browser visibility and coordinated rollback gates remain unverified. No completion ticks. No helper launch tool or installed qwen/claude/codex CLI was available; helper count 0, required independent read-only audit/checker not satisfied. Parent must arrange both independent checks and remaining core/full/browser gates.
- Existing hub additions above preserved; only this appended receipt is staged by this continuation. Main progress log untouched.

## G1 scoped correction (2026-11-20T03:45+0800)
- Arrival status inspected first; no AGENTS.md found at repository or ancestor paths (including /). Loaded tdd-workflow. Existing full pytest PID 99634 was active initially; no tests started until pgrep returned no pytest processes. No installs, full suite, live data, anchor resets or nonowned edits.
- Current API exists at audit.py:146-168; decide already uses it at approvals.py:205-215. Email is currently high-risk at approvals.py:157-158. Prior missing-API and email-not-high-risk prose is historical, not current truth. docs/todo-board/main.md:4 records historical 1586 passed/174 subtests/no xfails, not today's execution.
- RED command: `.venv/bin/python -m pytest tests/test_g1_view_transaction.py tests/test_g1_snapshot_restore.py -q` gave 7 failed, 1 passed in 2.26s. First-view faults reproduced the missing transaction API boundary and mismatched committed timestamps. Saved RED tests in 164ff15.
- Owned mark_view now uses one timestamp and record_decision, strictly checks checkpoint_ok, catches BaseException for rollback, and has no postcommit timestamp rewrite. Retained committed view replay is idempotent; it does not certify a previously failed checkpoint on retry.
- Focused command: `.venv/bin/python -m pytest tests/test_g1_view_transaction.py tests/test_g1_snapshot_restore.py tests/test_g1_browser_continuation.py -q`: 9 passed, 1 failed. Seven first-view cases GREEN; isolated signed snapshot/advance/restore GREEN; real Chromium visibility/decision timing GREEN; home allow-once flow genuinely RED. No coverage/full-suite claim. New full suite PID 6331 detected after this run; stopped further execution to avoid competition.
- Restore test closes/reopens SQLite, snapshots data only, keeps dedicated signer and external anchor outside data, verifies healthy history before restoring, requires exact signer count rollback diagnostic, preserves encrypted change reason after reopen/restore, and refuses terminal replay. This is coordinated data restore evidence, not an actual app-process kill/restart or universal rollback protection.
- Visibility semantics: static/approval-review.js:6,22-33 observes the first data-review-view-url form and positive intersection while document is visible. templates/approval_detail.html:57 marks the decision form, not every fact. Browser proof establishes marker visibility, not that the human read every fact; no stronger acceptance invented.
- PROBLEM/BLOCKED home: templates/owner_home.html:53-57 submits Allow once directly to /approvals/{id}/decide without reason or visible-review telemetry; app.py:932-944 forwards empty reason and rejects high-risk approval. Chromium landed at /decide instead of review. Safe owner wiring: replace home Allow once with a GET link to /approvals/{id} (keep Deny separately if needed), requiring review/reason on the existing detail screen. Never weaken reason enforcement. Template/app/static remain untouched.
- 2d/2f remain unticked. Independent checker not launched because changed acceptance checks are not all green; home defect requires nonowned owner repair. Existing untracked test_g1_remaining_acceptance.py untouched and unstaged. Preexisting handoff additions preserved and excluded from this checkpoint.
