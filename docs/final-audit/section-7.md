# Section 7 scoped review

## Parent Integration Gate

The parent/user reports actual independent audit outputs from these30 lanes, not newly launched or self-declared reviewers in this integration session: audit01 auth;02 roles;03 transactions;04 identity;05 R09 authority;06 terms;07 removal;08 audit;09 signer;10 locks;11 crypto;12 incident;13 clocks;14 calibration;15 helper;16 budget;17 model;18 passport;19 proof;20 arithmetic;21 upload;22 sponsor;23 disagreement;24 browser;25 accessibility;26 demo;27 runner;28 packaging;29 claims;30 adversarial. Full session IDs remain with the parent for independent confirmation; none are fabricated here.

Integrated repairs were reviewed in the original checkout and verified by execution, not accepted from artifact-only summaries. Final code fingerprint `1ea16945f12098650d37d3129e5198e55250c580eb29f17c7646c7b1675e843b`: all30 shards passed,2042 collected nodes with exact union and complete ordinary execution phases, no skipped reports. Receipt basename `aegis-test-shards-02o1hhn9.json`. Initial inventory plus first six-shard batch108.711s is not total wall time.

Six isolated stand-in scoreboards and Lumen normal measurement completed in142.325s: enforce main49/49, normal22/22, evasion24/24, adaptive168/168; Lumen16/16 and zero false holds. Audit3306 records/checkpoints verified with no problems. Off controls: main11/49 stopped, evasion0/24, adaptive0/168. These results do not prove every financial-language variant, real-human calibration, live models or production recovery. Unknown financial authority remains HOLD; original sponsor S5 HOLD mismatch remains disclosed alongside approved prototype BLOCK.

The two final gate faults were test-owner reuse under correct owner-wide money accounting, and runner self-tests monkeypatching report state during a real plugin run. Isolated owner fixtures and separately retained live reports fixed them without dropping execution-phase checks or subtests. No unresolved reproduced Blocker/High failure remains in this executed newly authorized scripted-prototype gate; broader release limitations remain outside that statement.

The historical owner report below is retained as narrower evidence, not the final gate.

Scope: templates/base.html, templates/attack_board.html, templates/rule_match.html, static/app.css, docs/deployment.md, docs/report.md, docs/final-audit/board.md and the existing coverage index. Parent integration-board.md was not edited. No independent30 review, full suite or commit was performed.

## Medium findings and repairs

- Shared header lacked a home link and keyboard bypass. Twinguard now links to `/` with an explicit home name; the first link skips to the focusable main-content target. External CSS reveals the skip link on focus and gives links, buttons and tabindex targets a visible outline.
- Attack board and rule match scrolling depended on inline styles blocked by the application's `style-src 'self'` CSP. Both now use an external table-scroll class and named, keyboard-focusable regions. Scoped table CSS keeps a 960px minimum readable width and auto layout, overriding mobile fixed layout without changing other tables. CSP was not weakened.
- Deployment text incorrectly said Compose mounts and Docker context exclusions were missing. It now describes the actual persisted data/signer/anchor volumes, required read-only external secret mount, UID 10001 preparation, scripts copy and exclusions. Image build, startup, ownership, health timing and recovery remain runtime-unverified here.
- Old report completion claims are prominently marked historical and superseded, not deleted. Board preparation paragraphs and the original S5 HOLD finding are explicitly historical. Approved-prototype S5 BLOCK remains accepted only for its stated gate; original sponsor mismatch and independent review remain open.

## Plain evidence

- `.venv/bin/python -m pytest tests/test_container_config.py tests/test_c2_attack_board.py tests/test_c5_rule_match.py -q`: 42 passed, 4 failed in 0.36s. All four failures were rule-match export parity cases raising `TypeError: _ref() missing 1 required positional argument: 'key'` at aegis/proof_pack.py:268. That module and its tests were outside this ownership scope and were not changed. No clean combined-suite result is claimed.
- Same focused command with `-k 'not export_parity'`: 42 passed, 4 deselected in 0.31s. Deselection is disclosed, not a fix for the four failures.
- Direct Jinja base rendering and both child-template compilation passed. Source assertions passed for the home link, skip target, focus selectors, named tabindex regions, absence of inline styles in both owned tables and scoped external overflow/min-width/auto-layout rules.
- `git diff --check` passed before this report was added. Each test command used a 180-second tool timeout. No full suite was run.

These are source/render assertions and focused Python tests, not browser screenshots, keyboard scrolling, screen-reader acceptance, live-model evidence or container runtime tests. UI runtime recheck remains pending. Existing unrelated worktree changes were preserved.
