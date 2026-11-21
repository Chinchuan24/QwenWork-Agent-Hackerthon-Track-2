# Presentation Recording

## Start And Accounts

Run `./run-local-demo.sh --scripted` in the release folder. The actual readiness URL is printed: default `http://localhost:8000`; the verified recording used `http://localhost:8001` because 8000 was already occupied. Do not stop the other port owner. Open the printed origin plus `/login?present=1`. Owner login: `admin` with the owner-known local credential; other-role credentials remain private in `.local-demo/passwords.json`, never in this script or screenshots. The alias keeps Dana's existing internal identity and administrator/task-giver role. Ops and riley remain distinct approvers, audi auditor, view viewer.

Sign in as `admin`. Open `/admin/tools/review?present=1`. Review all 14 schemas and fingerprints, enter the private password, check the explicit snapshot confirmation, click **Approve reviewed snapshot**. Require the saved audit receipt before continuing. Presentation mode collapses raw evidence, raises base text by 15%, and retains the scripted/synthetic banner.

## Optional Local Live Settings

For a local live demonstration start normally with `./run-local-demo.sh`, not `--scripted`. Sign in as `admin` and open `/local-demo/settings` on the printed origin. Paste the selected provider key BEFORE recording, submit, and confirm the blank password box plus masked last-four hint. Never record key entry or take a screenshot while it is populated. Test connection performs one tiny capped call; HOLD means do not claim a verified live connection. Every refreshed page shows the current provider/model badge. Forget removes only the pasted override, not an existing environment fallback. Eight-hour monotonic expiry and process restart forget the pasted override. The presentation stories remain explicitly synthetic/scripted; a live provider badge does not turn saved story evidence into live results.

Local Settings verification receipt: `scripts/verify_local_key_browser.py` passed 31 headless Chromium and actual-server checks, including real password-field paste, one tiny fake connection call, masked-only response, storage/cookie checks, role/CSRF/rate denials, timeout HOLD, actual stop/restart forgetting, and release/clone filesystem canary scans with zero matches. All test servers stopped; zero real provider calls. The supplementary focused test command passed 31 tests. No secret-entry screenshots or recordings were produced.

## Owner Login Verification

The owner alias change passed 22 focused tests across local control styles, role attribution, and local finishline integration. Actual scripted and fake-provider launcher rehearsals verified authentication, five-role route access, ops/riley action quorum, stop and archive reset. No real provider credential was used. Existing authenticated scene identity remains Dana, so scene captures were not regenerated. Historical setup/login captures still show the prior username; they are historical evidence, not current login instructions.

## Exact Scene Timings

These are Section C storyboard edit durations, not invented processing timings. Do not pretend saved outcomes are live animated processing. Actual processing occurs on each button click.

| Scene | Storyboard interval | Duration | Exact path | Click and expected display |
|---|---|---|---|---|
| S06 | 0:38–0:48 | 10 seconds | `/present/s06?present=1` | Click **Reset recording dataset**: 0/5 processed, five queued. Click **Process next queued behaviour** five times: each actual saved result appears with reasons and a real audit ID. |
| S07 | 0:48–1:15 | 27 seconds | `/present/s07?present=1` | Review outside recipient, client list and zero sends. Open **Open exact saved decision** to `/audit/record/{actual-id}?present=1`. Important: existing rules HOLD the email; the follow-up upload is BLOCKED under R15. Do not narrate this as a BLOCKED email receipt. |
| S09 | 1:22–1:50 | 28 seconds | `/present/s09?present=1` | Compare proposed S$4,800 with source S$6,200. Open **Check evidence receipt {actual-id}**. HOLD is an actual saved draft-review state after the deterministic evidence check fails, not a relabelled gateway BLOCK. The unsupported draft was never submitted for sending. |
| S11 | 1:57–2:12 | 15 seconds | `/present/s11?present=1` | Dana clicks **Request corrected contract review**. Actual Greenstep probe shows Aegis safe / Delta unsure. The separately labelled corrected Ferro reply enters actual contract approval. Dana's approval attempt is rejected. Sign in in separate browser contexts as ops then riley; open this same path, enter **Review reason**, click **Approve corrected contract reply**. First held; duplicate ops rejected; second distinct riley executes only the corrected synthetic reply. |
| S13 | 2:20–2:40 | 20 seconds | `/present/s13?present=1` | Inspect Needs you / Stopped / Good to know / Went fine. Counts come from saved gateway audit attempts. Open an item **Proof {actual-id}** to inspect its real record. Group item counts and headline completed-action counts are explicitly distinguished. |
| S14 | 2:40–2:50 | 10 seconds | `/present/s14?present=1` | Click **Verify original proof pack**: green Verified after actual signature verification. Click **Tamper COPY: change one field**: red COPY verification failed. Exact field `payload.dataset` changes from the displayed dataset ID to `TAMPERED-COPY`. Original digest and signature remain unchanged and valid. |

## Every Recorded Step

`recording-contact-sheet.html` contains all 54 actual step screenshots in order, each with its exact runtime URL and click/input description. `recording-assets/recording-evidence.json` is the machine-readable step ledger. Each screenshot is headless Chromium at 1440×900 with full-page capture; password controls are masked, blank logins are captured before entry. Full-page images may exceed 900 pixels in height. No videos are claimed.

The recorder also checked ten routes at 1440, 768 and 390 pixels, 30 overflow cases total. No external browser requests or JavaScript page errors were observed. Audi and view were independently signed in and confirmed read-only briefing access.

To regenerate from committed application code in a new isolated clone: activate a Python environment with project dependencies and Playwright Chromium installed, then run `python scripts/record_presentation.py --output-dir /absolute/new/recording-assets`. It launches only scripted mode, never copies or reads the release `.env`, and stops its own launcher. The clone uses a short `/tmp` path for the macOS Unix socket limit.

## Provenance And Recording Limits

The paper contract is a reconstructed synthetic source with literal fixture signatures, not a digitally signed client contract. The proof pack itself has a genuine generated Ed25519 signature. All processing and approval effects are genuine local application operations against synthetic in-memory worlds. Nothing is sent outside. Existing R18 contradiction BLOCK, five-strike controls and independent R12 sponsor expectations remain unchanged.

Section C's exact S07 BLOCKED-email wording and S09 gateway-HOLD implication cannot both be asserted honestly under the current policy. The interface explicitly exposes those boundaries instead of weakening policy or fabricating results. S11's saved disagreement probe and corrected contract flow are distinct, labelled records. For a 15-second final edit, prepare the separate role contexts beforehand; the full prerequisite and login sequence is longer than the shot window.

## Reset

The scene reset archives the previous scene dataset in an owner-local DB setting and retains original audit records. It does not delete user or production data. For an entirely fresh authority dataset, stop the owned foreground launcher, run `./run-local-demo.sh reset`, then `./run-local-demo.sh --scripted`. This archives the entire demo state directory atomically. Start again with blank login and 14-tool review.

## Final Verification

Final canonical test receipt: 2,147 tests, 30 shards, jobs=1, all passed, zero skips. The first browser and adaptive shard attempts timed out at the existing 300-second bound. Their partial logs were retained; the same receipt was resumed with sequential per-node subshards and completed successfully. No tests, verdicts, caps or timeout bounds were weakened.
