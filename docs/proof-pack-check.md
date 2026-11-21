# C4 Proof Pack Check

## Contract

Only `aegis/proof_pack.py`, `tests/test_c4_proof_pack.py` and this document belong to this work. No shared core, history or progress-log changes. No commits or external actions.

Call `verify_export_context(token, csrf, password)` from a trusted human POST boundary. It checks the existing live session, CSRF, current admin/auditor role, forced-password-change state, login throttling and password. It returns an opaque, process-local, single-use context valid for five minutes. The builder checks session expiry, logout, changed password and changed role again. User-supplied role/reauthentication booleans are not accepted. Contexts must never be exposed to agents or persisted. Multiple server processes must verify and consume in the same process.

Call `build_proof_pack(start, end, context=ctx, signing_key=dedicated_key, rule_match=rows, card_versions=rows)` to receive UTF-8 JSON bytes. Bounds are finite UTC epoch seconds, inclusive on both edges. Convert local calendar selections to these bounds in the route; do not silently guess a timezone. Audit entries and stored actions are ordered by time and ID. Approvals are selected when requested or decided in the range, with stable opaque references linking to actions. The policy snapshot immediately before the range and changes during it are included.

Private free text, arguments, results, reasons, names, paths and unknown fields are omitted or masked by a field/value allowlist. Rule identifiers are separately constrained. Identity references are SHA-256 pseudonyms, not anonymisation; known low-entropy identifiers could be guessed. Versions are retained but policy/card contents are masked. Guard verdicts and modes are retained; free-text reasons are masked. No regex-only content scrub is relied upon.

The export checks the whole audit history, not just the chosen range, with `audit.verify()`. It also asks the separate signer for its latest record, checks its signature and compares count/hash/ID to the database. Actual failed check categories and record numbers are retained without copying unsafe error messages. An unreadable verifier or unavailable signer is a failure, never a pass. Failed integrity still produces a sealed export with `FAILED: THE RECORD CHECK DID NOT PASS` at the top of the payload. A UI must show that warning prominently before the summary.

Making the export appends `proof_pack_exported` through the existing audit API, with bounds, exporter, artifact digest and integrity outcome. That receipt is after the exported snapshot and cannot recursively include itself. An audit-write exception prevents returning the artifact. The existing audit API may return despite checkpoint failure; this builder does not claim that the export receipt itself acquired a signer checkpoint.

## Seal Verification

1. The integrator supplies a dedicated Ed25519 private key using the installed cryptography library. This module never generates persistent keys, reads the audit signing key, reuses the evidence key or stores keys.
2. Give the auditor the matching public key through a separately trusted channel. Record its SHA-256 fingerprint separately from the downloaded pack. Do not trust a key or fingerprint delivered only inside the artifact.
3. Load that trusted key as an `Ed25519PublicKey` and call `verify_seal(artifact_bytes, trusted_public_key)`. A true result means the signed JSON values match the signature for that key. Duplicate JSON keys, edits and the wrong key fail verification.
4. Inspect the integrity warning even when the seal passes. A sealed failed history is still failed history.

The signature covers payload, algorithm and key fingerprint using sorted UTF-8 canonical JSON. Whitespace and object-key ordering are not signed byte-for-byte; meaningful value changes are detected. The separately supplied key is essential: a party controlling that private key can mint a replacement pack. A signature does not establish the truth of the log, legal standing, signer host isolation or an independently established identity. Existing audit/signer deployment limits still apply.

## Integration Gaps

No HTTP routes, UI button or key provisioning were added; these belong to the integrator. No safe dedicated artifact-signing protocol exists in the current audit signer, so this implementation uses a caller-provided dedicated Ed25519 key rather than altering the audit stream.

Current gateway decision records do not consistently bind action IDs, helper IDs, policy versions, card versions or two named guard results. The builder never infers those bindings from the current policy or neighbouring entries. Missing fields say `not recorded`. Second-opinion records with `a` and `b` are projected as Aegis and Delta but remain separate timeline entries.

C3 card history remains an explicit masked input, not a fabricated database table. C4 reads the C5 worker's `rule_match_table()` catalog without modifying it. Omitting `rule_match` embeds all 15 reviewed rows; explicitly supplying rows (including an empty list) preserves the existing caller-selected input behavior. Rows matching the catalog's source, number and heading receive the complete reviewed table fields: official heading, plain summary, candidate check, official URL, read date, version, publication status, source-verification state and limitation. These public fields always come from the reviewed catalog, never caller text. Unknown rows retain the masked legacy projection.

C4 does not validate supplied proof references. Unsupported `covered` or `partly` claims become `not covered`, even with a nonempty reference. `not verified`, an explicit false source-verification flag, and an unreadable catalog source take precedence and remain `not verified`; source labels stay visible. Reviewed rows have empty proof lists because no executed mitigation receipt was validated. Positive coverage requires a future independently verified C5 evidence contract. The table shows how Twinguard helps you meet rules; it is not legal advice or a certification.

## Evidence

Tests were written before the module. Initial red run: collection failed with `ImportError: cannot import name 'proof_pack'`. First green run: 11 passed in 2.05 seconds, scripted local tests.

Coverage: inclusive date edges, ordering, broad range, 2,000-entry range without truncation, arbitrary private prose masking, two guards, version metadata, supplied rule-match/card inputs, tampered history export, unavailable signer export, edited artifact, wrong trust key, role downgrade, wrong password/CSRF, forged booleans, single-use context, expiry and malformed ranges. Synthetic large-range corruption is isolated and restored without signing a corrupt checkpoint.

Follow-up reviewed the owner's private planning notes (kept outside this repository); they are not needed to build or verify a proof pack. C5 source, tests and documentation were inspected read-only. New table tests were run before the implementation change: 2 failed, 22 passed in 5.45 seconds (missing full fields and lost unreadable-source state). After implementation and additional session invalidation checks: `.venv/bin/python -m pytest tests/test_c4_proof_pack.py tests/test_c5_rule_match.py -q` produced 35 passed in 6.13 seconds, scripted local tests. This is catalog/export behavior evidence, not evidence of mitigation coverage.

Additional checks cover complete/default catalog embedding, caller text substitution masking, unreadable-source precedence, malformed seal input, logout, password change and forced-password-change denial without an export receipt. Existing tampered-log, signer-down, trust-key and large-range tests remain passing. Tests use temporary database, recordings, anchors and signer state, not production copies or external services.

`apply_patch` was unavailable on this host (`which apply_patch`: not found); dedicated file tools were used as the local editing fallback. Test-scenario guidance was read. No review-probes were accessed. No commits, production copies, publication, network research or external business actions were performed. Shared core and other workers' files were not edited.
