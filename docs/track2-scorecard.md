# Track 2 Evidence Scorecard

Inspection snapshot: 18 November 2026, with document-only claim repairs on 19 November 2026. This is a conservative missing acceptance assessment, not a submission score or proof that current implementation is absent. Other writers are active; rerun checks after integration. File existence alone is not proof.

Scope: component tests inspect local functions and fixtures; saved scripted gateway runs inspect the logged gateway boundary in a fictional, simulated world. Neither establishes interception of every file access or every action by a same-user process, runtime QwenWork worker routing, or browser navigation. Fail-closed evidence is limited to selected enforce-mode fault cases; off/monitor behavior must be reported separately, not described as universal fail-closed protection. No current runtime acceptance is established by this document repair.

The owner's planning notes are private material kept outside this repository, not submission files or runtime dependencies. This snapshot uses repository evidence; it does not claim exhaustive sponsor requirement coverage.

Product direction: Twinguard: two AI guards, Aegis and Delta, that check what your AI helpers do. This describes the requested product, not completed delivery.

The sponsor tests use synthetic adapters returning expected decisions and observations. Their fixture score is not a measured gateway score. 19 November 2026 section 6 receipts supersede blanket unmeasured wording only within their scope: prior normal work completed 13 of 16 with three false holds (intentional regression handoff: 6 failed, 4 passed); isolated demo histories match across five runs and ten resets, including two saved safe/unsure guard pairs. Closeout checks: 9 passed in 4.15s for demo repeatability and evidence-table validation only. No exact sponsor acceptance, browser, two-guard coverage or live score is asserted here. The claim benchmark is a standalone checker, not proof of interception before sending.

## Sponsor Coverage

| ID | Requirement | Status | Inspected evidence | Missing proof or reason |
|---|---|---|---|---|
| A1 | Log every action and data access | not done | [gateway](../aegis/gateway.py), [office schema test](../tests/test_t3_office_actions.py#test_office_actions_have_validated_schemas), [app](../aegis/app.py) | Office actions now appear in schemas, side-effect handling and executor dispatch. Schema assertions do not prove Lumen integration or complete action logging. |
| A2 | Check numbers and policy violations | not done | [claim checker](../aegis/claims.py#check_message), [S4 test](../tests/test_t6_claims.py#test_s4) | Standalone evidence matching exists; send-path integration and owner proof presentation are not established. |
| A3 | Stop or escalate risk before completion | not done | [gateway](../aegis/gateway.py), [sponsor runner](../aegis/lumen_sponsor.py#run_sponsor) | No real executor supplied by the sponsor runner; full Lumen integration not measured. |
| A4 | Plain daily owner briefing | not done | [briefing tests](../tests/test_t8_briefing.py#test_default_audit_reader), [source gate](briefing-video-script.md) | Tests include synthetic audit rows; a saved S1-S5 backend briefing exists in section-6-demo-evidence.json. Daily scheduling, persistence and browser proof-route integration remain unverified. |
| M1 | Bad worker through oversight | not done | [scripts](../aegis/lumen_sponsor.py), [fixture](../tests/test_t7a_sponsor.py#measured_reply) | Synthetic fixture is not real worker integration. |
| M2 | Risk caught and explained before completion | not done | [shot list](demo-shot-list.md) | Integrated screen and clean-run proof pending integration. |
| M3 | Made-up number beside contrary evidence | not done | [S4 checker](../tests/test_t6_claims.py#test_s4) | Checker component exists; demo/send integration pending. |
| M4 | Morning briefing over coffee | not done | [video source gate](briefing-video-script.md) | Saved backend briefing exists; accepted daily delivery integration and authenticated owner-screen proof remain unverified. |
| D1 | Live database-backed QwenWork application | not done | [app](../aegis/app.py), [capability limits](qwenwork-capabilities.md) | Local database app is not proof of live QwenWork worker integration or deployment; release waiting for Chin. |
| D2 | Daily briefing as a short video | not done | [holding script](briefing-video-script.md) | Saved backend briefing exists; accepted daily source integration and verified media file/duration remain missing. |
| D3 | Demo video | not done | [conditional shots](demo-shot-list.md) | Five saved backend histories match across ten fresh starts; authenticated browser repetition, demo integration and recording acceptance remain unverified; no upload performed. |

## Owner Policy

These are sponsor policy requirements, not the existing legacy rules with similar identifiers. None is counted complete without the Lumen policy and real action integration, including near-miss tests.

| ID | Requirement | Status | Inspected evidence | Missing proof or reason |
|---|---|---|---|---|
| R01 | Needed reads allowed; other reads reported | not done | [S5 script](../aegis/lumen_sponsor.py) | Task-needed classification and briefing integration unverified. |
| R02 | Unneeded regulated reads never allowed | not done | [classifier tests](../tests/test_t2_sensitivity.py#test_content) | Classification is not read enforcement; integration pending. |
| R03 | Internal/public mail to known parties allowed | not done | [sandbox send](../aegis/lumen_world.py#send_email) | World contact validation is not policy integration; paired rule tests missing. |
| R04 | Sensitive email asks owner | not done | [gateway](../aegis/gateway.py) | Existing confidentiality blocks are not proof of sponsor approval integration. |
| R05 | Unknown recipient asks owner | not done | [sandbox send](../aegis/lumen_world.py#send_email) | World rejects unknown recipients; required held-action integration unverified. |
| R06 | Published-list price allowed | not done | [seed price list](../aegis/lumen_world.py) | Data exists, quote enforcement integration unverified. |
| R07 | Discount asks owner | not done | [S2 script](../aegis/lumen_sponsor.py) | Email discount extraction and integration not measured. |
| R08 | Price below owner floor never allowed | not done | [S2 fixture](../tests/test_t7a_sponsor.py#measured_reply) | Fixture copies expected rules; non-releasable NEVER integration unverified. |
| R09 | Reduced payment, fee waiver or contract change asks | not done | [S4 script](../aegis/lumen_sponsor.py) | Accept-terms integration and close-but-safe tests unverified. |
| R10 | Matching supplier invoice below threshold allowed | not done | [supplier seed](../aegis/lumen_world.py) | Supplier payment integration and boundary tests unverified. |
| R11 | Large or unmatched payment asks | not done | [extra-case tests](../tests/test_t7b_attacks.py#test_all_twelve_requirements_have_scripts_and_exact_source_evidence) | Split-payment scripts are not payment integration; threshold equality needs explicit safe interpretation. |
| R12 | Unconfirmed new supplier spend asks | not done | [S5 script](../aegis/lumen_sponsor.py) | Email commitment/order integration unverified. |
| R13 | Public upload allowed | not done | [tool seed](../aegis/lumen_world.py) | No real upload-policy integration proof. |
| R14 | Internal upload to non-retaining tool asks | not done | [tool seed](../aegis/lumen_world.py) | Target retention data is not upload integration proof. |
| R15 | Sensitive outside upload never allowed | not done | [S1 script](../aegis/lumen_sponsor.py) | Synthetic sponsor callback is not upload integration. |
| R16 | File deletion asks | not done | [S3 script](../aegis/lumen_sponsor.py) | Deletion approval integration unverified. |
| R17 | Received-in-error deletion followed by reports allowed | not done | [trap evidence test](../tests/test_t1_lumen_world.py#test_files_traps_and_evidence) | Contract text exists; delete-and-notify integration not proved. |
| R18 | Client facts require a source | not done | [checker](../aegis/claims.py#check_message), [unsafe cases](../tests/test_t6_claims.py#test_unsafe) | Standalone matching exists; gateway and briefing integration pending. |
| R19 | Unannounced client news never shared | not done | [extra scripts](../tests/test_t7b_attacks.py#test_all_twelve_requirements_have_scripts_and_exact_source_evidence) | Script/citation tests do not establish enforcement integration. |

## Scenarios And Traps

Trap paths below are virtual document IDs in the in-memory world, not claimed disk files. The linked seed and tests inspect their content and reset behavior.

| ID | Requirement | Status | Inspected evidence | Missing proof or reason |
|---|---|---|---|---|
| S1 | Client list upload; CSV must be regulated | not done | [scenario](../aegis/lumen_sponsor.py), [common-miss test](../tests/test_t7a_sponsor.py#test_common_misses_are_independent_not_inferred_from_verdict) | Real upload integration and independently observed no-upload result missing. |
| S2 | Discount plus below-floor NEVER, not approvable | not done | [scenario](../aegis/lumen_sponsor.py), [fixture](../tests/test_t7a_sponsor.py#measured_reply) | Expected-answer fixture does not prove floor/approval integration. |
| S3 | Hold deletion; explain unpaid money | not done | [scenario](../aegis/lumen_sponsor.py) | Actual deletion hold and owner money explanation integration missing. |
| S4 | Wrong surcharge, days and total caught | not done | [checker evidence](../tests/test_t6_claims.py#test_s4) | Component comparison exists; real worker send-block integration missing. |
| S5 | New order held; unneeded reads noticed | not done | [strictness test](../tests/test_t7a_sponsor.py#test_s5_stricter_block_is_not_silently_counted_as_sponsor_hold) | Synthetic stricter decision is correctly scored differently, but real read/order integration missing. |
| P1 | Nimbus patient attachment is regulated | component verified | [seed](../aegis/lumen_world.py), [attachment test](../tests/test_t2_sensitivity.py#test_attachment_trap_and_provenance), [world test](../tests/test_t1_lumen_world.py#test_files_traps_and_evidence) | Virtual inbox/2026-11-13_nimbus_patient_data_in_error.md; delete-and-report execution not proved. |
| P2 | Ferro fundraising is client-confidential | component verified | [seed](../aegis/lumen_world.py), [content tests](../tests/test_t2_sensitivity.py#test_content) | Virtual clients/proposal_ferro_logistics.md; outside-tool enforcement not proved. |
| P3 | Owner cash-flow is regulated | component verified | [seed](../aegis/lumen_world.py), [content tests](../tests/test_t2_sensitivity.py#test_content) | Virtual finance/cashflow_notes_nov2026.md; scope/card enforcement not proved. |
| P4 | Publication-permitted Harbourbean case is public | component verified | [seed](../aegis/lumen_world.py), [world test](../tests/test_t1_lumen_world.py#test_files_traps_and_evidence), [mixed-content test](../tests/test_t2_sensitivity.py#test_public_approval_does_not_erase_private_lines) | Virtual marketing/case_study_harbourbean.md; normal public-send path not proved. |

## Security Room

| ID | Requirement | Status | Inspected evidence | Missing proof or reason |
|---|---|---|---|---|
| C1 | Independent Aegis and Delta on every outside action | not done | [gateway](../aegis/gateway.py) | Existing second checks run only on high-risk signals; all-action integration, claim recheck, paired scoreboard and timing absent from inspected path. |
| C2 | Attack board from stored runs with visible misses | not done | [board projection](../aegis/attack_board.py), [miss honesty test](../tests/test_c2_attack_board.py#test_optimistic_totals_cannot_hide_individual_misses), [guard proof test](../tests/test_c2_attack_board.py#test_guard_proofs_recent_masking) | Projection tests inspect synthetic stored-result and audit inputs, including visible misses and conflicting totals. Actual stored-suite equality, route integration and C5 risk links remain unverified. |
| C3 | Stored helper cards enforced on every action | not done | [display contract](../aegis/card_view.py#project_cards), [display tests](../tests/test_c3_card_view.py#test_exact_detached_projection_and_same_names_unique_ids) | Read-only projection explicitly excludes storage and gateway integration; versioned writes and no-card refusal not proved. |
| C4 | Sealed date-range proof export | not done | [export](../aegis/proof_pack.py#build_proof_pack), [tamper test](../tests/test_c4_proof_pack.py#test_tampered_log_exports_warning), [seal test](../tests/test_c4_proof_pack.py#test_seal_edit_and_wrong_key), [check instructions](proof-pack-check.md) | Export component exists; route/key-custody integration and authoritative historical card/rule-match inputs not proved. |
| C5 | Official PDPA, IMDA, CSA and OWASP rule match | not done | [research catalog](../aegis/rule_match.py#rule_match_table), [no-proof test](../tests/test_c5_rule_match.py#test_missing_proof_is_not_covered), [source limits](rule-match.md) | Catalog keeps all OWASP risks and source gaps visible without coverage claims. IMDA version and CSA final/draft status remain not verified; source metadata records another writer's research, not an independent fetch here. Route and proof-pack integration remain pending. |
| C6 | Helper freeze, global stop, incident and reminder | not done | [alarm contract](../aegis/alarm.py), [reminder test](../tests/test_c6_alarm.py#test_midnight_singapore_calendar_deadline), [delegation test](../tests/test_c6_alarm.py#test_management_delegation_and_failure) | Alarm explicitly supplies no adapter; freeze tests use a synthetic adapter, not real helper enforcement integration. PDPC source not independently fetched in this task. |

## Verification And Blockers

Owned files only: this document and [its validator](../tests/test_t14_scorecard.py). Refresh tests were added first: direct execution failed because the current office-schema evidence link was absent. The validator checks all 45 rows, local nonempty link targets, Python function symbols, allowed path scope, forbidden self-claim wording, invented score patterns, and refusal to promote component evidence to integration coverage. It does not treat a valid link as behavioral proof.

Refresh direct validator run: five tests passed. Component test files were inspected, not executed in this refresh; their assertions and synthetic inputs are evidence of test scope, not fresh execution receipts. The four trap component labels retain the earlier in-memory seed/classifier inspection only, not product completion. Current additions in other writers' working files are inspection evidence and may change before integration.

Direct execution avoids tests/conftest.py, which starts a signer and creates runtime state. No production history, logs, policies or core files were changed. No accounts, publishing, schedules, remote actions or media generation were performed. Full application tests, dependency audit, normal suites, browser journeys and current live models were not run here; these remain integrator checks.

F20 repair: the earlier prohibited-wording line references had drifted and are withdrawn, not reused as current blockers. See [early claims inventory](final-audit/early/claims-inventory.md), findings F05/F06/F18/F19, for scoped concerns in other owners' documents. Those documents remain untouched. Valid local references are navigation aids, not behavioral proof.

Normal work is a historical baseline dated 2026-11-19, not current acceptance: [section 6 claims](section-6-claims.md) and [normal-work handoff](handoff/section-6.md) report 13 of 16 completed and three false holds. Concurrent core repairs were not rerun here. Saved [backend evidence](section-6-demo-evidence.json) includes a briefing; daily persistence, schedule delivery and authenticated browser proof remain missing acceptance.

Integration remains not done for the four asks, four moments, three deliverables, owner-policy enforcement, five scenarios and six security-room requirements. Component evidence is kept visible without promoting it to product completion. QwenWork runtime usage remains unproved beyond the limited capability inventory. The briefing video and demo are source-gated drafts. Release and Hashmeta sign-in remain waiting for Chin.
