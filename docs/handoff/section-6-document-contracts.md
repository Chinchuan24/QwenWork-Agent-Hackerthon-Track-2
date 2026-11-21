# Section 6 document contracts

## Correction receipt: 2026-11-19T16:44:57+08:00

User confirmed ownership of tests/test_section6_demo_repeatability.py and tests/test_section6_evidence_tables.py. Changed only their detector construction to identical prefix components; no assertions removed or platform branches changed. Earlier Scope and Failure handoff below are historical, superseded for these two files by this receipt.

Git status was read before edits. apply_patch was attempted but unavailable; exact replacement tool used. Offline AST evaluation proved 2 exact detector equalities and executed the existing assertion nodes against 6 rejection/control cases: demo Mac-path rejection and clean control; evidence Mac, Applications and Windows rejection and clean control. No product imports, real state, loopback runtime, external network, core edits or full suite.

Command: `PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest --noconftest -p no:cacheprovider -q tests/test_section6_evidence_tables.py tests/test_repository_portability.py`.

Exit 1: 3 passed, 1 failed in 0.05s. Evidence contracts GREEN; repository portability remains BLOCKED solely by `docs/final-audit/early/fresh-machine.md`, left untouched for its owner. Recent RED path evidence was not duplicated before repair. No product acceptance inferred. Named commit scope: the two tests, this handoff, and docs/todo-board/section-6.md only.

## Scope

This handoff is the only authored file. Existing documents, core and tests were read only. Dirty tests/test_t13_website.py belongs to another owner and was not edited. Git status was checked before inspection and immediately before writing; concurrent changes were preserved. No network, commits, full suite or runtime acceptance execution.

Excluded the five already delegated targets: test_t14_scorecard.py, test_t11_capabilities.py, test_t9_t12_documents.py, test_section6_claim_repairs.py and test_section6_runbook.py. Their execution was not duplicated.

Shared tests/conftest.py was read: it starts a signer, initializes a database and migrates evidence. All executed modules were read first. --noconftest bypassed that setup; plugins, cache and bytecode writes were disabled.

## Measured results

Exact command from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest --noconftest -p no:cacheprovider -q tests/test_repository_portability.py tests/test_twinguard_branding.py tests/test_t13_website.py tests/test_section6_evidence_tables.py tests/test_t11_skill_package.py::SkillPackageTests::test_metadata_and_boundaries tests/test_t11_skill_package.py::SkillPackageTests::test_paths tests/test_t11_skill_package.py::SkillPackageTests::test_source_entrypoints tests/test_t11_skill_package.py::SkillPackageTests::test_pending
```

Exit 1: **1 failed, 13 passed in 0.08s**. Current-worktree static evidence only, not product acceptance or a committed snapshot.

| Target | Scope | Result |
| --- | --- | --- |
| test_repository_portability.py | Every tracked regular file, forbidden Mac-home-prefix bytes | 1 failed |
| test_twinguard_branding.py | Visible template titles and source naming, source read only | 1 passed |
| test_t13_website.py | Customer sections, unsupported claims, asset/contact placeholders, draft and measurement boundaries | 5 passed |
| test_section6_evidence_tables.py | Requirement IDs, measurement scope, paths and focused commands | 3 passed |
| test_t11_skill_package.py, four explicit nodes above | Metadata/boundaries, contained relative existing paths, AST entrypoint signature parity, pending claims | 4 passed |

SkillPackageTests.test_actual_pure_callable was excluded because it executes briefing product code.

## Failure handoff

Exact node: tests/test_repository_portability.py::test_tracked_files_have_no_mac_home_paths.

Failing assertion, tests/test_repository_portability.py:17:

```python
assert not offending, f'Mac-specific paths in tracked files: {offending}'
```

Observed offending list:

```text
docs/final-audit/early/fresh-machine.md
tests/test_section6_claim_repairs.py
tests/test_section6_demo_repeatability.py
tests/test_section6_evidence_tables.py
tests/test_section6_runbook.py
```

Cause: the scanner rejects the contiguous prefix slash + Users + slash throughout tracked bytes, including negative path-leak assertions and historical prose. fresh-machine.md:39 embeds the literal while explaining negative assertions. The listed tests embed the detector literal. This failure does not establish an actual developer-specific path leak.

Requested fixes by existing owners, without weakened tests:

- Fresh-machine audit owner: reword docs/final-audit/early/fresh-machine.md:39 to describe the prefix without contiguous forbidden bytes. Preserve historical scope and the negative finding.
- Claim-repair owner: construct the identical forbidden prefix from separate string fragments in tests/test_section6_claim_repairs.py; preserve regex alternatives and rejection behavior. Coordinate with the already running worker.
- Demo owner: split the identical detector string in tests/test_section6_demo_repeatability.py:22; preserve report rejection. Do not run demo runtime for this static repair.
- Evidence-table owner: split the identical detector string in tests/test_section6_evidence_tables.py:25; retain all platform-path regex branches and rejection behavior.
- Runbook owner: split the identical detector string in tests/test_section6_runbook.py:16; preserve assertNotIn behavior. Coordinate with its existing worker.
- Do not exempt tests, exclude tracked documents, relax portability, or remove path-leak coverage. test_repository_portability.py:6 already demonstrates split-byte construction.

Focused owner verification:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest --noconftest -p no:cacheprovider -q tests/test_repository_portability.py
```

## Remaining inventory

Searches covered test Python files for README, docs paths, absolute paths, text/byte reads and fixture references. Additional relevant matches were read and classified, not indiscriminately executed:

| Target | Relevant contract | Exclusion |
| --- | --- | --- |
| test_h6_followup_rollback.py::test_h6f_readme_and_trust_report_state_the_case | README rollback/external-anchor wording | Mixed node imports app, calls startup and HTTP route; module imports audit/config/db |
| test_c5_rule_match.py::test_owned_outputs_have_no_self_endorsement | Document/template/catalog must not self-certify | Executes product rule_match_table; not static-only |
| test_t1_lumen_world.py::test_files_traps_and_evidence | 28 fixture documents, metadata, sensitivity, contract/invoice/deadline/pricing content, ledger totals | Executes world fixture methods |
| test_t1_lumen_world.py::test_reserved_domains_invalid_identifiers | Reserved fixture domains and invalid identifiers | Executes fresh world state |
| test_t6_claims.py | N11 fixture price, matching sources, currencies, deadlines, attachments, scope | Product claim-checker execution |
| test_g4_normal_work.py | Relative fixture document IDs and synthetic action counts | Product helper-pattern/normal-plan replay |
| test_section6_demo_repeatability.py | Report path rejection and user-path safety | Launches demo runtime/reset runs |
| test_separation.py | README isolation limitation referenced as context | Worker/security tests, not README content assertions |
| test_g1_visibility_script.py | Browser-document visibility static source | JavaScript behavior, not documentation/fixture content |

No excluded mixed/runtime target is reported as passed. Naming result covers visible static naming, not all internal identifiers. Portability covers tracked files only, not untracked files or history. The handoff itself avoids embedding the forbidden contiguous prefix.

apply_patch was unavailable in this environment; creation used the file-writing tool after the failed command. No existing file was changed by this review.
