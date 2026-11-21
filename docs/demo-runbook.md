# Demo Runbook

## Immediate Local Workflow

Run from the repository root. Use Python 3.12 and approved locally available dependencies; public package installation needs network permission. No API key is needed.

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/local_setup.py init
.venv/bin/python scripts/local_setup.py run
```

Open http://127.0.0.1:8080. If occupied, use `scripts/local_setup.py run --port 8081` through `.venv/bin/python` with a free port; do not stop another task. The helper binds localhost, strips inherited AEGIS settings and disables live model calls. Preserve the private `.local-runtime/` state and keys.

1. Sign in as local admin `dana` with `demo-dana-2026`, then change the password on the Password page before privileged actions.
2. Open `/admin/tools/review`. Review the displayed names, descriptions, input schemas, fingerprints and snapshot digest. Enter the changed password, explicitly confirm the exact displayed sandbox snapshot, and select **Approve reviewed snapshot**. Require a saved approval audit receipt. A changed snapshot requires a reload and fresh review. Do not import test manifests or substitute test approvals.
3. Open `/admin/demo`. Select **Reset demo**, then **Run five stories**. Both use a newly allocated synthetic child with private evidence state. No production reset: never change real data, keys or anchors to make the demo pass.
4. Follow this session's **Proof** links. Match `bindings` to `record_projection`, including `run_ref`, `session_ref`, verdict and executed status. Normalized references are not ordinary browser database IDs.
5. Open **Source**, **Guard**, **Briefing** and **Results**. Source JSON is emitted evidence only, not a complete source-comparison interface. Follow briefing `proof_ids` to the matching saved records. State the actual outcomes and missing facts; HOLD is not BLOCK.

Say: “This is a local scripted stand-in. These are its saved decisions, not live AI results or a complete sponsor score.” Known sponsor outcomes do not establish full sponsor acceptance. Live execution, full-suite verification and full narrated recording acceptance are deferred.

## Evidence Boundaries

The dated 2026-11-19 receipt `docs/section-6-demo-evidence.json` is historical backend evidence, not today's execution. It reports `mode` = `scripted stand-in`, `live` = `ready for key; not run`, ten fresh starts and five matching runs. Check fresh output separately; do not overwrite the receipt or narrate it as a current result.

For each historical result, require `audit_ok` true and `sent` zero. Zero sent does not mean all work completed. S2/S4 end HOLD rather than the required BLOCK; S2 lacks R07/R08; S1 has no emitted source-line evidence. S4 emits 25% versus 20%, five days versus two, and 5,250 versus SGD 5040. Inspect the emitted file/line facts; missing evidence stays missing. Saved guard pairs show Aegis safe / Delta unsure, not Delta unsafe, and are not complete guard coverage.

### Everyday read

In the historical receipt, S2 step 1 binds to `record-14`: `read_file`, `clients/proposal_greenstep_tuition.md`, allowed and executed, `run_ref` = `run_id-3`, `session_ref` = `session_id-4`. Match the task at `record-10`. This is not a universal guarantee of ordinary completion: the later send is held and scope-creep records mark reads `needed: false`. Prior normal-work evidence remains 13/16 complete with three false holds, not a new measurement.

Five verified clickworkflow durations supplied for this handoff are 15.17, 13.70, 14.73, 15.32 and 15.30 seconds. Their scope is the click workflow only, not narration, full recording or all proof inspection. Historical backend durations of 0.440-0.466 seconds are separate; `browser_shot_seconds` in that receipt is null. “Actual clicks, load time and scrolling remain unmeasured” applies to that historical receipt, not the later clickworkflow measurements.

## Quick Documentation Gate

Run only the existing standalone documentation tests for this writing task; no application imports, shared pytest fixtures or full suite:

```sh
.venv/bin/python tests/test_section6_runbook.py
```

The independent backend rehearsal command remains `.venv/bin/python -m aegis.demo_repeatability`. It is not the browser reset action and is not requested in this writing task. It uses newly allocated state and local loopback signer IPC, not live services. A nonzero exit requires stopping and handing the error to the core owner.

## Failure Gate

Stop if a control is absent, access is denied, verification fails, proof is missing or results differ. Do not use a mock screenshot. Never approve a held send to keep the story moving. Do not repair or clear real history. If no disagreement appears, say “This run did not produce a disagreement.” Keep the observed result.

The current isolated proof routes exist; do not label them missing. Ordinary `/audit` has **Verify** and detail links `/audit/record/{rid}`, but those IDs are not isolated normalized references. Verify checks history, not full sponsor acceptance. Full narrated recording acceptance and remaining owner work are **BLOCKED waiting core owner**, not a blocker for the immediate local scripted workflow. Existing recording gates remain: five consecutive full browser rehearsals, ten reset clicks checked for isolation, and failure/access/proof checks. No such gate is claimed passed here.

## Historical Recording Plan

Retained only for the existing documentation gate: 165 seconds was a planned narration allocation, not a measured duration or an instruction to record now.

| Planned seconds | Historical allocation |
|---|---|
| 0-15 | Introduction |
| 15-45 | Stories |
| 45-70 | S1 proof |
| 70-105 | Emitted source evidence |
| 105-120 | Saved guard pair |
| 120-140 | Everyday read |
| 140-155 | Morning note |
| 155-165 | Results pause |
