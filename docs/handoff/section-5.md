# Section 5 — G4 counted helper alarm

Built by Qwen. Component handoff, not integrated enforcement proof.

## Document triage, 2026-11-19

At HEAD `11d664e`, ten explicit document/path/claim targets returned 11 failed, 35 passed and 9 subtests passed. These failures are outside section-5 ownership, not G4 runtime failures. Exact failing nodes and source lines are in `docs/handoff/section-5-document-contracts.md`; concurrent external repairs require their owner's fresh verification. Screen repair `cf9a975` remains supported by a fresh isolated 17-case GREEN in 9.28s with four lifecycle warnings. Historical counts below remain prior component receipts; no G4 runtime, full-suite or exhaustive screen acceptance was rerun here.

## Exact core changes for the lead

1. Capture one trusted event per attempted gateway action: stable helper identity, aware timestamp, canonical tool, actual accessed folder (not allowed scope), action category, and refused boolean from the actual decision. Join session IDs to stable helper IDs explicitly. Never accept these values or baseline selection from helper-controlled text. Do not count approval execution twice.
2. Establish independently reviewed normal runs before monitoring. `build_normal_baselines(runs)` counts supplied observations by helper and Singapore calendar day, using maxima across run/day samples; it rejects refused training events. Freeze/version these baselines; never silently retrain from monitored actions. Missing samples remain unknown. This API does not certify trust or sample completeness.
3. Keep minute and daily baselines separate. Daily output has `period=singapore_day`; `helper_pattern` rejects it. Supply independently counted `period=60_seconds` maps to `helper_pattern`. Supply daily output only to `daily_volume_pattern`. Never scale plan totals into a claimed normal day.
4. Under the existing serialized gateway action boundary, evaluate both functions including the candidate attempt, apply their results with `apply_alarm`, atomically persist state, then check `helper_is_frozen` immediately before execution. High must stop the triggering action and subsequent actions for that helper only, including approval release. Never use a global kill switch. Recheck after concurrent owner/card changes. Storage failure must fail closed. The side component does not implement this persistence or enforcement.
5. Feed `briefing_alerts` into the next morning briefing. Low alerts are due on the next Singapore calendar date, deduplicated by helper/reasons/date; overdue alerts remain available. Low does not add a hold. Normal/unknown never clear an existing hold.
6. Owner release must be authenticated and authorized by the existing owner route, not a submitted boolean. Call `release_helper(..., owner_authorized=True)` only after that check and persist under the same lock. It releases only the named helper. Preserve audit evidence and baseline versions; no automatic expiry/release.

## Counted thresholds

Existing minute rule: at least five refused attempts in inclusive trailing 60 seconds; unseen tool/folder is low; known dimension count at least 20 and strictly over three times normal is high. Daily rule: at least 20 total observations and strictly over three times normal daily total. All are counting, not learned predictions.

## Evidence and remaining acceptance

Focused command: `.venv/bin/python -m unittest discover -s tests -p 'test_g4*.py'` — 30 tests pass. Independent review exposed runtime annotation compatibility and day/minute mixing; both were repaired with regression checks. No full suite run in this side task.

Canonical Lumen suite-plan replay: 25 calls; finance 3, marketing 8, ops 3, sales 3, support 8. At each call, separate minute and daily projections produced zero high/low signals (25 checks each). These are synthetic plan counts, not observed normal-day telemetry, and source/replay use the same plan distribution. They do not prove integrated zero extra holds.

OPEN for lead: timestamped trusted normal-run capture, independent baseline calibration, durable latch/briefing storage, authenticated release wiring, real gateway trigger/isolation checks, and measurement of extra G4 holds on the normal-work suite. Existing non-G4 holds must remain separately reported. Do not claim G4 acceptance until these pass.

Files: `aegis/helper_pattern.py`, `aegis/helper_alarm.py`, `tests/test_g4_helper_pattern.py`, `tests/test_g4_counted_baselines.py`, `tests/test_g4_helper_alarm.py`, `tests/test_g4_normal_work.py`.
