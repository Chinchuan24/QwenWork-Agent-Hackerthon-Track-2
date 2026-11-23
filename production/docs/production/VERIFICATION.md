# Local Verification Receipt

Source commit used: `7efc4657a5e92712319573fe8b456ed3ce3bd186`; source was clean at inspection. Selected files extracted using git archive against that immutable commit, not working-copy files. Production destination did not exist; no prior folder was overwritten or moved. No release files edited.

Final-tree follow-up: release HEAD `c17a0196f31c460863513b21ce94afa450f71c2c` verified. Only three local smoke/workflow test files changed; all production inputs and four source test files used are byte-identical between commits. See PROVENANCE.json. Repeat package test run: **108 passed, 1 warning, 8.54 seconds**. No platform operations performed.

## Actual Results

Python 3.12.15 isolated temporary environment: hash-required installation of all 18 locked runtime distributions succeeded. Initial system Python 3.9 pip resolution failed for opentelemetry-api; no lock relaxation occurred. Switching to Python 3.12/uv resolved it.

Final pytest: **108 passed, 1 warning, 10.51 seconds**. Warning: Starlette httpx TestClient deprecation, not suppressed. Initial relocated test run: 99 passed and 7 failures due solely to source tests computing fly.toml relative to their temporary path. Harness reference corrected to the production package; hostname expectations aligned with the replacement template. Final run included both HTTPS browser cases.

Tests were read from committed source via git show into a disposable harness outside the package. No source conftest or legacy fixtures imported. Production and mixed tests ran against production modules via explicit PYTHONPATH and clean process environment. Pure policy tests extracted by AST selection from mixed legacy test source (financial comparison/current authority and deterministic money floors only). Additional package tests verify subprocess module closure, malicious synthetic .env ignored, provider key absent without environment and selected only from injected synthetic environment, exclusions/syntax, and quiesced disposable backup/restore. HTTPS tests exercise all roles, four pages, three widths, no outside requests, secure cookies, rate limits, hard-kill/partial POST recovery and unchanged stored key. No real provider keys or endpoints were used for acceptance.

## Closure and Inventory

Eight Python modules: __init__, production, public_evaluator, claims, policy, sensitivity, mixed_demo, provider. Production entry is `python -m aegis.production`. HTML is generated inline; no static files, templates or policy YAML files are required by the reachable entrypoint. Five bounded fictional excerpts are embedded in public_evaluator; no filesystem fixture dataset is shipped. The policy module retains dormant legacy helpers referring to db/audit, intentionally not part of the public reachable API. Calling those helpers is unsupported in this isolated package; real public startup/actions exercise no config/app/db/audit imports. No legacy run.py or local demo launcher is included.

Docker image copies only eight modules, the hash lock and all three license/notice files. The package also carries platform templates, placeholder-only environment reference, deployment/verification documents and scan tool. Docker, Fly, Render, push, provider billing, backup services and other actual operations were NOT invoked. Docker Linux build/architecture checks are pending, not inferred from local tests.

## Secret Scan Disposition

VERIFY.py scans every current regular package file including hidden configuration, except .git internals. Any unexpected .env file is refused by name WITHOUT reading its contents. No real .env was opened. Symlinks, fixtures, caches, tests and virtual environments are refused. Patterns cover recognizable provider tokens, private-key delimiters and assigned quoted credential literals. Zero unresolved candidates found. This bounded pattern scan is not a proof that all possible secret formats are detectable.

Synthetic in-memory self-tests: provider-shaped token detected; quoted synthetic password detected; private-key marker detected; placeholder-only environment value not flagged. All three candidates are intentionally constructed scanner probes, remain in memory and are not actual keys. Their exact dispositions are synthetic positive controls, not a blanket allowlist of secrets. No candidate plaintext output. Runtime code generates a Fernet storage key only on disposable/test or future approved volume, never into the package.

MANIFEST.json inventories file paths, bytes and SHA256; it excludes itself to avoid self-referential hashing. Every other delivery file, including this receipt and scanner, is covered. SCAN.json records scan outcome and source. It is covered by the manifest; scanner verification also inventories manifest itself on subsequent read-only runs. Git object storage is not counted as package content. No unconditional production-readiness label is warranted; DEPLOY.md checklist gates remain unchecked.
