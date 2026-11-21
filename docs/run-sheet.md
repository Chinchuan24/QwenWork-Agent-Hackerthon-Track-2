# Twinguard Run Sheet

Immediate scope: runnable local scripted demo only. Live execution, full suites, submission and full narrated recording acceptance are deferred. This checklist is not execution evidence.

## Start And Review

1. From the repository root, follow README's Python 3.12 venv/dependency steps, then run `.venv/bin/python scripts/local_setup.py init` and `.venv/bin/python scripts/local_setup.py run`.
2. Open http://127.0.0.1:8080. If occupied, launch with `.venv/bin/python scripts/local_setup.py run --port 8081` on a free port. Never stop another task or substitute direct live startup.
3. Sign in as admin `dana / demo-dana-2026`; change the password on the Password page first.
4. Open `/admin/tools/review`. Inspect the displayed tool definitions, schemas, fingerprints and snapshot digest. Reauthenticate with the changed password, explicitly confirm that exact sandbox snapshot, and select **Approve reviewed snapshot**. Require its saved audit receipt. Reload/review if the snapshot changes. No test manifests or imported approvals.

## Run And Inspect

1. Open `/admin/demo`, select **Reset demo**, then **Run five stories**. Both allocate fresh synthetic children; neither clears production history.
2. Follow the saved **Proof** links and match decision, verdict, executed status and run/session bindings to this session's result.
3. Open **Source**, **Guard**, **Briefing** and **Results**. Source JSON contains emitted evidence only, not full comparison coverage. Follow briefing proof references; do not map normalized references to ordinary audit numeric IDs.
4. Say “local scripted stand-in”, report actual HOLD/BLOCK outcomes and missing evidence, and stop on errors. Never approve a held send to finish the demo.

Known historical sponsor outcomes are not a full sponsor score: S2/S4 HOLD, S2 lacks R07/R08, and S1 lacks emitted source-line evidence. Aegis safe / Delta unsure is not Delta unsafe. Zero sent is not ordinary-work completion. Prior normal-work evidence remains 13/16 complete with three false holds; the regression handoff remains 6 failed, 4 passed. The earlier 9-pass closeout covered demo repeatability and evidence-table checks only.

Five verified clickworkflow durations supplied for this handoff: 15.17, 13.70, 14.73, 15.32 and 15.30 seconds. These measure the click workflow, not narration or the full recording. See `demo-runbook.md` for historical evidence boundaries.

## Stop And Defer

- Missing control, denied access, failed verification, missing proof or differing outcomes: retain the result and hand it to the core owner. Do not mock success or clear history.
- Preserve the complete private runtime and historical keys; a fresh demo is not recovery. See `deployment.md`.
- Writing-task quick gate: `.venv/bin/python tests/test_section6_runbook.py`. No application imports or full suite in this task.
- Existing local setup and sponsor CLI test gates remain separate: `.venv/bin/python -m pytest tests/test_local_setup.py -q` and `.venv/bin/python tests/test_sponsor_story_cli.py`. They are not claimed run here. The disposable `scripts/sponsor_story.py` safety story is not complete sponsor acceptance.
- `./check.sh` belongs to later full verification. A skipped/unavailable dependency audit is not a passing audit, even if the script exits successfully.
- Full recording gates remain five consecutive full browser rehearsals, ten reset clicks checked for isolation and failure/access/proof checks. Clickworkflow timings do not satisfy all those gates.
- Sole/universal authorship and interception are not established. Qwen-assisted repository work does not imply authorship of dependencies, references or external review inputs; gateway protection does not cover arbitrary external agents/tools.
