# Overnight Final Report

Local bounded review completed through round11. Rounds10 and11 each established zero new findings; minimum10 and two consecutive zero-new stopping condition met. One assistant, sequential source/check lanes, NOT independent agents or exhaustive penetration testing.

| Round | New | Tests | Shards | ASGI p95 ms | Errors | Receipt |
|---|---|---|---|---|---|---|
| 4 | 1 |2089|30|3.901|0|`aegis-complete-round-04/aegis-test-shards-09c2f_vw.json`|
| 5 | 0 |2089|30|5.119|0|`aegis-complete-round-05/aegis-test-shards-c1ofkqgr.json`|
| 6 | 0 |2089|30|1.817|0|`aegis-complete-round-06/aegis-test-shards-cqmz_8hb.json`|
| 7 | 0 |2089|30|2.544|0|`aegis-complete-round-07/aegis-test-shards-5ctmb8mp.json`|
| 8 | 0 |2089|30|3.932|0|`aegis-complete-round-08/aegis-test-shards-fmjvwxcw.json`|
| 9 | 1 |2089|30|1.706|0|`aegis-complete-round-09/aegis-test-shards-gzizq9vy.json`|
| 10 | 0 |2089|30|4.639|0|`aegis-complete-round-10/aegis-test-shards-hexzb9pb.json`|
| 11 | 0 |2089|30|2.277|0|`aegis-complete-round-11/aegis-test-shards-34ccdiaz.json`|

Rounds1-3 are historical2081-test cycles; all rounds4-11 independently reran the complete2089-node inventory. Each new round contains16 bounded source rereads with path/SHA256/line inventories, six fresh OFF/enforce scoreboards, five-story stored-evidence checks, audit verification and production low-heat ASGI reads. Mechanical rereads are not independent human adjudication. Full-suite timeout resumes preserve exact revision and all nodes; round9 failed docs receipt retained and complete post-fix suite rerun.

## Findings And Scope

ON-001 external-receipt workaround preserves revision guard. ON-002 oversized-lane timeout handled with unchanged-revision node subshards; scheduling cost retained. ON-003 stale claim wording refreshed. ON-004 invalid token types/counts latch admission; b0c1aa1. ON-005 public readiness now signer=false and simulated_hmac=true. ON-006 malformed received choices/messages latch admission; three failing reproductions then17 focused passes, round4 commit62b5eee. ON-007 introduced round9 document literal regression repaired without test weakening; e9e4957. Current known limitations: estimated billing, no live-model/independent-guard measurement, same-user OS custody, original S5 HOLD versus stricter BLOCK, managed-host validation not run. These limits are not waived.

## Demo Kit

Tested one command: `.venv/bin/python scripts/demo_rehearsal.py --approve-sandbox --output-dir /absolute/empty/evidence-directory`. Fresh committed-source clone, changed generated demo credentials, current14-tool name/schema snapshot review, exact digest and real CSRF browser submission, owned server only. Reset0.206s/five-story run0.623s, audit verified, zero sent effects,25 actual private screenshots at1440/390. No existing runtime erased. Timed180-second voiceover/shot plan is a video kit, NOT a narrated recorded video.

## Verdict

PASS for bounded local regression/rehearsal and stopping criterion. Not release-ready for live managed-host operation; no deployment, publish, signup, Docker or push. Fresh immutable source export and strict scanner receipts are supplied separately to avoid self-hash cycles.
