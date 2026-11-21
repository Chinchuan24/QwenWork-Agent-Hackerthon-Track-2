# Section 5 document contract triage

Date: 2026-11-19, Singapore time. HEAD: `11d664e`. Scoped verification, not release acceptance.

## Ownership

This lane owns only `docs/final-audit/early/screens.md`, `docs/handoff/early-screens.md`, `docs/handoff/section-5.md`, `docs/todo-board/section-5.md` and this new handoff. No core, template or test edits. Other dirty files are left untouched. Status was checked before each write; owned destinations were clean before this task.

## Discovered and executed targets

Document/path/claim targets: `tests/test_t9_t12_documents.py`, `tests/test_section6_evidence_tables.py`, `tests/test_repository_portability.py`, `tests/test_section6_claim_repairs.py`, `tests/test_section6_runbook.py`, `tests/test_t13_website.py`, `tests/test_t14_scorecard.py`, `tests/test_t11_capabilities.py`, `tests/test_t11_skill_package.py`, `tests/test_twinguard_branding.py`.

Run the above explicit targets with `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest --noconftest -p no:cacheprovider`, followed by the target paths and `-q --tb=short`. Document checks require no application fixtures. Actual initial result: **11 failed, 35 passed, 9 subtests passed in 0.25s**. A diagnostic repeat with `--tb=line` returned **11 failed, 35 passed, 9 subtests passed in 0.24s**. These are separate executions, not additive coverage.

Screen recheck: `PYTHONDONTWRITEBYTECODE=1 AEGIS_HTTPS=0 .venv/bin/python -B -m pytest -p no:cacheprovider tests/test_early_screens_fixes.py -q --tb=short`. Actual **17 passed, 4 lifecycle warnings in 9.28s**. Fresh process loaded `tests/conftest.py:6-14` before app imports: temporary data, separate external anchor and signer state, random evidence key, live-model key removed. Browser contexts block service workers and abort non-owned origins (`tests/test_early_screens_fixes.py:14-37`). No full suite, installs, external research or commits.

## Exact RED handoffs

All document failures below are outside this lane. Responsible owner: section 6 document/release contract owner; coordinate portability prose with the fresh-machine audit owner and negative-marker tests with their test owner. Never weaken a validator merely to make a score green.

| Failing node (prefix is test file) | Actual failure and source | Required owner decision |
|---|---|---|
| `test_t9_t12_documents.py::test_documents_exist_and_make_no_unmeasured_success_claim[demo-shot-list.md]` | assertion line 18 matches `15/15` in `docs/demo-shot-list.md:9`, even in a negative statement | Preserve the no-achieved-score meaning without ambiguous numeric wording. |
| `test_t9_t12_documents.py::test_documents_exist_and_make_no_unmeasured_success_claim[submission.md]` | assertion line 16: missing pending marker; `docs/submission.md:3,25,31` instead describe draft/open gates | Make current pending status explicit and factual. |
| `test_t9_t12_documents.py::test_demo_timing_and_required_moments` | line 39 raises ValueError: expected five columns, got four; `docs/demo-shot-list.md:6-15` | Resolve shot-table contract with actual measured decisions and pending browser production, not invented narration/outcomes. |
| `test_t9_t12_documents.py::test_submission_word_limits_and_honest_engine_status` | line 64: missing waiting-for-key phrase; `docs/submission.md:21-25` | State live engine status accurately; a key is not integration proof. |
| `test_t9_t12_documents.py::test_current_source_gate_distinguishes_builder_from_measured_briefing` | line 72: expected briefing-component link label differs from `docs/briefing-video-script.md:7` | Link-label mismatch is repairable; later line 73 requires absent saved evidence, conflicting with saved evidence at line 7 and `test_section6_claim_repairs.py:35-39`. Strengthen provenance verification rather than erase the artifact. |
| `test_t9_t12_documents.py::test_documents_keep_media_and_release_gate_explicit[demo-shot-list.md]` | line 83: exact media gate absent; `docs/demo-shot-list.md:24` only says recording pending | Keep the verified-source and human-release gate explicit. |
| `test_t9_t12_documents.py::test_demo_preserves_sponsor_moment_order` | line 90 raises ValueError: required beat absent; `docs/demo-shot-list.md:8-15` uses different names | Resolve required story order while retaining actual HOLD/unsure/citation limitations. |
| `test_repository_portability.py::test_tracked_files_have_no_mac_home_paths` | line 17 lists `docs/final-audit/early/fresh-machine.md:39`, `tests/test_section6_claim_repairs.py:53`, `tests/test_section6_demo_repeatability.py:22`, `tests/test_section6_evidence_tables.py:25`, `tests/test_section6_runbook.py:16` | Literal home-root marker is detected even in negative checks; construct negative-test marker and rephrase prose, retaining the tracked-file scan. No owned file is listed. |
| `test_t14_scorecard.py::ScorecardTests::test_complete_coverage_and_explicit_limits` | line 34: M4 row lacks integration word; `docs/track2-scorecard.md:24` | Describe missing integrated daily delivery, without implying absent backend briefing. |
| `test_t14_scorecard.py::ScorecardTests::test_no_forbidden_selfclaims_or_invented_scores` | line 57 matches historical ratio at `docs/track2-scorecard.md:11`; also line 92 | Preserve dated measured baseline and distinguish it from an invented/current acceptance score. |
| `test_t11_capabilities.py::T11CapabilitiesTests::test_observation_is_not_integration_proof` | line 30 requires stale numeric citation; stable heading evidence is at `docs/qwenwork-capabilities.md:13,22,53`; actual heading `docs/progress.md:80` | Verify the real heading and reported-use limits; do not restore a false line reference. |

The diagnostic reports the first failing assertion per node. Later assertions were not proven green. In particular the briefing absent-artifact assertion and additional shot-table requirements remain contract decisions, not additional measured failing nodes.

## Screen history and current scope

`git show --stat cf9a975` identifies the saved four-finding repair. `git log cf9a975..HEAD -- aegis/app.py templates/audit.html templates/error.html tests/test_early_screens_fixes.py` returned no commits. Current handlers are at `aegis/app.py:117-134`; viewer withheld reasons at line 547. The fresh 17-case GREEN supports retaining the saved repair citation. Historical 48-case GREEN is not a rerun here. Original audit source line numbers describe the earlier commit, not current file locations.

Current populated-screen gap remains visible in source: `aegis/app.py:296-297` supplies no incident report and empty alarm/helpers. No populated incident/alarm, exhaustive screen, API confidentiality, keyboard journey or integrated G4 acceptance is claimed. `test_r12_browser.py` was inspected as the imported local server/login dependency, not separately collected. Runtime section-6 acceptance, repeatability, rule matching and release parity suites were discovered but excluded because this job is document/path/claim triage, not product acceptance.

## Final selected-target recheck

After concurrent external-owner edits, the same ten explicit targets with `-q --tb=no` returned **1 failed, 45 passed, 9 subtests passed in 0.24s**. Only `tests/test_repository_portability.py::test_tracked_files_have_no_mac_home_paths` remains RED. The earlier table retains all 11 actual initial failures as a historical handoff, not a claim they all remain failing. External test/doc edits caused the changed contract snapshot; this lane did not alter or independently approve those changes. The owned documentation does not cause the remaining failure. `git diff --check` returned clean. Fresh screen GREEN remains 17 passed; no exhaustive acceptance inferred.

## Concurrent work and closeout

Initial dirty files: section-2 and section-6-demo handoffs, progress, website content and website tests; untracked main boards and remaining-acceptance tests. Before writing, scorecard and capability tests also became dirty. Those external owner edits were not changed, reverted or accepted by this lane. The RED numbers above are the executed snapshot before subsequent owner changes; no current external GREEN is inferred.

Owned factual corrections only: timestamped screen recheck, historical-versus-current scope, saved repair citation and this exact contract handoff. Document-path failures remain external handoffs until their owners rerun the explicit targets. No automated validator specifically covers this new handoff; source/status review supplies that bounded verification.
