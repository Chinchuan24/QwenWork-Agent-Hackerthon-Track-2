# Section 4 — G3 tool passport handoff

Built by Qwen. Scope: sandbox tools only, not real outside tool servers.

## Measured component evidence

- Existing passport: 32 focused tests passed.
- New registry: RED 34 missing-module setup errors; GREEN 34 tests passed. No assertion-based bug reproduction is claimed for this new module.
- Independent checker: `.venv/bin/python -m pytest --noconftest tests/test_g3_tool_passport.py tests/test_g3_passport_registry.py -q` — 66 passed.
- Read-only adaptation of the current gateway tool definitions produced 14 comparison rows. Approval baseline deliberately empty: all blocked as unknown, approved fingerprints null, gateway_enforced false. This does not approve any tool or measure gateway enforcement.
- No full suite or scoreboard was run by this side task.

## Ordered integration steps — main task only

Follow steps 1–7 below, then steps 8–12. Shared core, evidence, existing tests and runtime labels remain lead-owned. This side task does not implement those changes.

### Step 0 — pending regression contract

New owned file: `tests/test_g3_gateway_pending.py`. Proposed test seam: `gateway._sandbox_tool_registry()` returns a fresh `SandboxToolRegistry` from trusted approvals and current manifests. Tests inject that seam with `raising=False`; the current gateway ignores it, so failures are behavioral, not missing imports. Implement this seam or adapt the injection point without weakening any behavioral assertions.

Measured focused run: `.venv/bin/python -m pytest tests/test_g3_gateway_pending.py -q` produced 3 passed, 15 strict xfailed. `.venv/bin/python -m pytest tests/test_g3_gateway_pending.py -q --runxfail` produced 3 passed, 15 failed: actual allow versus expected block/hold. The strict xfail marker explicitly labels pending wiring; it is NOT enforcement evidence. Run with `--runxfail` during integration and remove the marker when wiring passes. Do not retain xfails as acceptance. Cases cover empty approvals, unapproved executable tool, description drift, input-schema drift and detected injection in enforce/off/monitor, with three unmarked approved-normal controls. They assert exact passport reason, no executor call, no world mutation, no sent mail and no executed action row.

### Steps 1–7 — gateway wiring

Use `SandboxToolRegistry.from_tool_schemas(approved_records=trusted_approved_records, tool_schemas=tool_schemas())`. Approval records must come from an explicitly reviewed trusted snapshot, NEVER from the action caller and NEVER automatically from current definitions. Missing approval state fails closed. Reconstruct the current registry at each final check; a startup snapshot alone cannot notice later drift.

1. Import `SandboxToolRegistry` from `.tool_passport_registry`.
2. Resolve the tool by name and call `registry.check_tool(tool)`. Its allow means manifest match only; retain every existing authorization check.
3. Add the initial hard check after argument validation and before action execution/off-mode handling (`gateway.py:1111-1113`). Unknown/invalid/injected descriptions block; changed manifests hold. Do not relax this check in off or monitor modes.
4. Recheck at approval release (`gateway.py:1411-1426`). Non-allow refuses release independently of previously held policy rules. Ordinary action approval must not approve drift. Explicit tool review plus a fresh action review is required.
5. Immediately before each `_execute`, recheck current definitions: normal path (`gateway.py:1272-1287`), off path (`gateway.py:1146-1153`), approved path (`gateway.py:1458-1465`). These anchors are inspection-time locations; find their surrounding functions if concurrent edits move them.
6. Bind approved/candidate fingerprints and approval version to action evidence and approval binding. Lead owns approvals/audit/evidence changes. Log status/reason/digests and action linkage, not raw potentially malicious descriptions.
7. Before model exposure, validate exact definitions at `gateway.py:57-76`. The separate descriptions in `worker.py:18-28,43-48` must be consolidated or independently checked too.

### Step 8 — approval authority and atomic dispatch

The seam must load a trusted persisted, versioned approval baseline, including current revocations, at final checks. Missing/corrupt approvals or malformed/duplicate catalogs must deny execution and model exposure with sanitized linked evidence, not uncaught errors. Catalog-construction exceptions occur before `check_tool` returns a decision; explicitly handle them at initial call, release and model exposure. Choose and document whole-catalog rejection for malformed catalog state.

Synchronize definition/baseline updates with final check and dispatch. Bind action identity, tool name, candidate digest, approved digest and approval version to the same execution snapshot. Reapproval or version change invalidates prior action approval: require fresh action review. Only allow definitions reach structured model tools AND textual worker tool listings, from the same reviewed snapshot; do not expose held/blocked definitions. Fingerprints cover name/description/inputs, NOT implementation code integrity.

### Step 9 — proof pack rows and measured rule match

`registry.proof_rows()` lists the sorted union of approved/current tools with name, candidate_sha256, approved_sha256, status, reason, scope, notice and gateway_enforced=False. Missing approved tools remain visible. Render these rows as escaped text; never interpret descriptions as instructions or HTML. Maker/provenance is not measured: show Not recorded, not an invented publisher.

Connect these comparison rows to `proof_pack.py:181-190,233-244`; preserve the component-only label. Runtime enforcement claims need validated linked receipts through the trusted coverage validator (`proof_pack.py:211-227`). Signed exports alone do not prove enforcement.

Keep broad supply-chain/real server allowlist rows in `rule_match.py:34-37,70-76` NOT COVERED. A narrow G3 row may state: Sandbox manifest comparison tested; gateway enforcement and exported runtime receipts pending. Do not promote it to covered until measured gateway rejection, approval/replay rechecks and actual exported receipts pass.

## Baseline wording after G3 integration — main task only

Required screen, report and scoreboard wording: **Policy-off baseline: policy checks disabled; mandatory G3 sandbox tool-passport checks and existing hard gates remain active.** Do not label this mode fully unprotected or say no checks applied. Monitor mode also retains mandatory G3 checks; it does not execute unknown, changed or detected-injected tools merely to observe them.

This is the required integration contract, not a claim that G3 is enforced today. The empty approval baseline in the component measurement above must block every tool in every mode after integration. Normal baseline comparisons require explicitly reviewed approved sandbox manifests, never automatic approval of current definitions. Record the approval version and G3 state alongside new baseline measurements; do not relabel historical results as measurements of the new contract.

Lead acceptance must verify the new wording and that unknown/missing tools block, changed manifests hold, and detected description injections block in off and monitor modes without side effects. Preserve existing tests; add focused regressions for the changed contract. Update shared runtime labels and regenerate baseline evidence only after integration tests pass.

### Step 10 — fix the three baseline risks without masking existing checks

1. Runtime label risk: inspection found contradictory strings at `aegis/gateway.py:152,154,1160`; also review `aegis/redteam.py:14` and `templates/run.html:8`. Replace off labels with the policy-off wording above and monitor labels with: Monitor: policy decisions observed; mandatory G3 sandbox passport checks and existing hard gates remain active. Check surrounding functions because concurrent edits can move lines.
2. Empty-baseline risk: `tests/test_pipeline.py:179,187,190`, `tests/test_r1_containment.py:195-202` and `tests/test_suites.py:23` expect off/monitor execution or policy-off leaks. Preserve those policy tests with explicit reviewed matching test manifests. The new empty-approval cases remain separate and must block. Never auto-approve current production definitions to preserve test outcomes.
3. Masked-card-reason risk: early unknown-tool blocks can mask card expectations in `tests/test_c3_card_permissions.py:61-77,87,94` and `tests/test_c3_enforcement_review.py:69-70,102`. Give those existing card tests trusted matching passport fixtures so they still reach and assert the intended card reason, hold and no-side-effect behavior. Do not remove exact reason assertions or reinterpret a passport block as proof the card gate worked.

### Step 11 — strengthen non-admin off-mode assertion

`tests/test_security_app.py:153` checks only absence of the old label. Preserve it where applicable and add behavioral assertions around the POST: capture the count/IDs of off-mode runs before the request, wrap or spy on the run-creation execution entry point without changing behavior, then assert no call with mode=off and no new off-mode run after the request. Also assert absence of the new policy-off heading. Keep the existing status assertion. Inspect the current route/database contract to choose the real run table/entry point; do not invent column names. A changed label alone must never make access-control acceptance pass.

### Step 12 — integration verification and save

Run the pending file with `--runxfail`; remove its strict marker only when every behavioral assertion passes. Run the G3 component files and lead-owned focused off/monitor/card/security regressions. Add lead-owned approval-release, replay, model-exposure, corrupt-baseline and final-check race tests before claiming complete enforcement. Then the main task performs its full-suite/scoreboard/export gates, records fresh approval version/G3 state and actual results, and saves its own integration. Do not relabel historic baselines, promote coverage from xfails, or claim signed rows establish enforcement.

## Required lead acceptance checks

Unknown tool cannot execute; changed description/schema holds without side effects; injected description blocks even if baseline-approved; normal approved sandbox action still completes; manifest changes during judging or before approval release cannot execute; off/monitor cannot bypass G3; revoked/missing baseline cannot execute; every registered tool and its actual digest appears in the proof pack with honest missing data.

## Open limits

Description scanning uses the existing finite heuristic, not semantic proof of safety. Paraphrases, oversized/encoded text and schema text remain limits; trusted review of all model-visible text is necessary. No real external discovery, server validation, persistent approval UI, runtime receipt or gateway protection was implemented here. Lead integration and full acceptance remain open; external credentials/publication are waiting for Chin.

Helper lanes: two read-only integration reviewers, one two-file TDD implementer (resumed with the existing virtual-environment interpreter), one independent checker. Skills: tdd-workflow; implementation helper consulted python-testing. Shared core and evidence files were not edited by this task.
