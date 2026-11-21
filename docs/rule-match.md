# C5 Rule Match

This table shows how Twinguard helps you meet rules. It is not legal advice or a certification.

## Scope And Decisions

The owner's planning notes are kept outside this repository and are not runtime dependencies. The initial catalog task did not establish exhaustive requirement coverage from those notes. No core, route, navigation, proof-pack, progress or decisions files changed. No sign-in, upload, publication or commit performed. Skills used: web-search and ux-writing.

The module is a read-only catalog and the template is ready for the integrator. Call `rule_match_table()` and render `rule_match.html` with `table`, `sources=SOURCES`, and `notice=NOTICE`. Route authorization and navigation remain unconnected. C4 `build_proof_pack()` preserves the full reviewed catalog by default and when supplied matching rows. Matching uses source, number and heading; public text and provenance come from the catalog, not caller text. Coverage claims are downgraded to not covered without validated proof; not verified status or false source verification takes precedence. Unknown rows use masked summaries and opaque references instead of exposing arbitrary caller text. This preservation does not establish route authorization or navigation integration.

No coverage has been established merely by locating a test or naming a control. No executed evidence receipt was validated for a framework risk. All candidate mappings therefore remain not covered; unreadable requirements remain not verified. This deliberately does not manufacture test or scoreboard links. The C5 tests prove catalog behavior, not mitigation of all ten risks.

## Prototype Financial Rule

R09 compares complete structured financial snapshots against current human-agreed source authority. All 15 term categories in `aegis.claims.FINANCIAL_TERM_TYPES` are covered, including removals and nonnumeric payment/bank terms. Missing authority requires HOLD; proven source contradictions BLOCK. Unchanged terms pass only this comparison, not independent hard rules, helper cards, scope or R18. Keyword detection is not authority and is not used to certify absence of changes.

Gateway authority consumes an integrity-verified `financial_terms_agreed` audit receipt bound to the exact action, session, source version/body/term hashes and distinct authorized reviewer. No worker-provided expected label grants approval. Trusted task ingress and the authenticated admin source-message-scope route publish explicit quote-only message receipts bound to current full source snapshots and exact arguments. Partial mentions are not contractual removals in that human-authorized scope. Replacement agreement intent cannot use that scope. Messages lacking either appropriate source scope or agreement authority HOLD conservatively. This is not a claim of normal-task zero false holds or live-model calibration.

S5 approved-prototype acceptance expects BLOCK while `sponsor-original` preserves HOLD and reports the mismatch. Scripted results remain synthetic contract evidence, not live verification.

## Official Research Evidence

Read date: 18 November 2026. Discovery used host web search, followed by public page reads. Search returned URLs only, not substantive extracts; a search result alone was never treated as verified wording.

| Source | Actual readable evidence | Version/status conclusion |
|---|---|---|
| Personal Data Protection Act, overseen by PDPC | Reporting guidance says it helps assess, manage and report breaches, and mentions a three-day deadline. Published 22 Apr 2026. Three step headings were readable. | Act revision not verified. Detailed deadline trigger and 500-person threshold not verified from readable text. |
| Model AI Governance Framework for Agentic AI | Official updated-framework page says SINGAPORE - 20 MAY 2026 and last updated 21 May 2026. Body did not render. Official PDF returned binary text, not extracted document text. | Current numeric version not verified. Do not label January 2026 as the current edition. |
| Securing Agentic AI: An Addendum to the Guidelines and Companion Guide on Securing AI Systems | Publication page dated 17 June 2026 says released for public consultation; also says consultation was conducted 22 Oct-31 Dec 2025. Links a PDF without Draft in its displayed title. Older release explicitly announces consultation. | Conflicting page signals: final versus draft not verified. A consultation end date is not proof of final publication. Document version not verified. |
| OWASP Top 10 for Agentic Applications 2026 | Official release announcement dated 9 Dec 2025 names each ASI risk. Resource page also dated 9 Dec 2025 calls it the 2026 list. | Released 2026 edition. The announcement's Threats and Mitigations 1.1 is a separate taxonomy, not an Agentic Top 10 version number. |

Public official URLs actually read:

- PDPC reporting: https://www.pdpc.gov.sg/organisations/e-services/report-your-organisations-data-breach
- PDPC threshold page, title only: https://www.pdpc.gov.sg/required-to-notify-the-pdpc
- PDPC obligations page, title only: https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act/data-protection-obligations
- IMDA update: https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/updated-model-ai-governance-framework-for-agentic-ai
- IMDA PDF, unreadable binary response: https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf
- IMDA AI landing page, body unexpanded: https://www.imda.gov.sg/about-imda/emerging-technologies-and-research/artificial-intelligence
- CSA publication: https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/
- CSA consultation release: https://www.csa.gov.sg/news-events/press-releases/csa-releases-an-addendum-to-support-system-owners-in-securing-agentic-ai-system/
- OWASP edition: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP exact identifiers and headings: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/

## Exact OWASP Rows

| Official number | Official heading | Candidate control, not evidence | Status |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Exposed-session containment | not covered |
| ASI02 | Tool Misuse | Tool limits and human holds | not covered |
| ASI03 | Identity & Privilege Abuse | Task limits and helper cards | not covered |
| ASI04 | Agentic Supply Chain Vulnerabilities | No verified mapping | not covered |
| ASI05 | Unexpected Code Execution | No verified mapping | not covered |
| ASI06 | Memory & Context Poisoning | No verified mapping | not covered |
| ASI07 | Insecure Inter-Agent Communication | No verified mapping | not covered |
| ASI08 | Cascading Failures | Fail-closed checks | not covered |
| ASI09 | Human-Agent Trust Exploitation | Approval evidence and claim checker | not covered |
| ASI10 | Rogue Agents | Freeze and stop controls | not covered |

PDPC rows use only the readable official headings: Step 1: Assess Whether the Breach is Notifiable; Step 2: Notify the PDPC and Affected Individuals; Step 3: Beyond Reporting the Breach. They remain not covered. IMDA and CSA use document titles as visible placeholders, not guessed clause headings, and remain not verified.

## Verification

Test-first execution: system `python3` lacked pytest. Existing `.venv/bin/python -m pytest tests/test_c5_rule_match.py -q` then produced eight failures, each ModuleNotFoundError for aegis.rule_match, before implementation.

Tests enforce exact ten ASI identifiers and headings, missing proof, unreadable source precedence, unknown version/status honesty, provenance, fresh independent row data, template gap visibility, and no self-endorsement wording in owned output. No live model or remote action is needed.

For each call, `unreadable_sources` overrides prior catalog readability: affected rows have `source_verified=False`, `status='not verified'` and empty proof. Other rows and later calls without the override remain unchanged. This effective verification flag agrees with C4's exported rows; it is not a new official-source verification.

Local regression checks exercise unreadable OWASP and PDPA rows and full-row export parity for default, unreadable OWASP, unreadable PDPA, and already-unverified IMDA/CSA inputs. Export tests use C4's real projection and seal but stub authorization, integrity checking and audit recording; they do not verify those boundaries. No official sources were accessed for this correction.

Remaining work: readable official document extraction to settle IMDA version and CSA publication state; executed mitigation evidence with scoped limitations; authorized route wiring. No global screen/document wording audit has been claimed.
