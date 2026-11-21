# Local Demo

## Start

```sh
./run-local-demo.sh
```

Uses an installed trusted Python 3.12 runtime, never installs dependencies. Discovery order: explicit `TWINGUARD_LOCAL_PYTHON`, repository `.venv/bin/python`, then `$HOME/Qwen/aegis/.venv/bin/python`. Exact requirements.txt versions are checked. No virtual environment is packaged. A missing prerequisite is an error, not permission to download packages.

The readiness line prints the actual URL and owned HTTP child PID. Default is http://localhost:8000; an occupied port is skipped without stopping its owner. No automatic preview is opened. Full private application, not the public limited interface.

Owner login: `admin`, using the owner-specified local credential. This launcher-only alias authenticates the existing Dana administrator (`dana` internally), not a separate user. Only its PBKDF2 hash is installed; existing owner credentials are backed up in an owner-only SQLite backup before migration. Other accounts and passwords are unchanged: ops/approver, riley/approver, audi/auditor, view/viewer. Fresh other-role passwords are independently generated and stored in `.local-demo/passwords.json` (0600). Any legacy Dana entry in that file is obsolete; use `admin` with the owner-known credential. No password is included here. Production rejects this fixed fixture as well as the older fixtures; non-loopback local child startup is refused. This is intentionally synthetic local demo authority, not production accounts. Default startup securely reads the optional owner-only `.env` to resolve a configured provider, but never writes it. For guaranteed isolated scripted recording use `./run-local-demo.sh --scripted`: this bypasses `.env` entirely, even when a real key is present.

## Memory-Only Provider Settings

Start with `./run-local-demo.sh`, sign in as `admin`, and open the printed origin plus `/local-demo/settings`. Select DeepSeek, Qwen, or an OpenAI-compatible public HTTPS base URL and model. Paste the key before recording. The password input is blank in the POST response; only provider, model, source, and a masked last-four hint are shown. Never capture screenshots or video while entering a key.

The override lives only in this HTTP process behind an RLock and expires after eight hours on a monotonic clock. Forget removes the pasted override; restarting starts without it. Python strings are garbage-collected, not a forensic RAM-zeroization guarantee. No pasted key is written to dotenv, database, logs, audit, proof, cache, temporary files, cookies, or browser storage. An existing environment credential is unchanged and may remain live after Forget; Settings explicitly labels that fallback source.

Test connection makes one request, with eight output tokens and the existing admission, spending, daily allowance, bounded response, and unknown-accounting HOLD controls. Failures are generic and do not echo provider errors. Normal local startup permits external sockets only inside the existing public-HTTPS DNS-pinned provider transport. Explicit `--scripted` stays hard-offline and disables Settings writes. These routes are installed only by local startup, never the production app entry point. The shared client snapshot hook is inactive in production.

Focused verification: `tests/test_local_key_settings.py` and `tests/test_local_provider.py`, 18 passing tests. This includes runtime-random memory canary paste/use/forget, masked POST response, one tiny fake transport call with real admission/accounting, expiry via fake clock, fresh-store restart semantics, CSRF/admin denials, and a whole release-tree scan including ignored files with zero full-canary matches. No real provider key or network request was used. The follow-up gate `scripts/verify_local_key_browser.py` passed 31 actual Chromium/server checks in an isolated committed clone. It pasted a runtime-random fake credential through the password field, verified the blank POST result, last-four-only hint, live badges on dashboard/audit/presentation, one tiny fake call, all four nonadmin roles and anonymous denial, CSRF, rate limit, timeout HOLD, browser local/session storage and cookies, actual Forget, actual HTTP-process stop/restart, durable unknown-accounting refusal, and zero full-canary matches across both original release and clone (including ignored DB and logs). Production source hashes were unchanged and production route inventory contained no Settings route. All owned HTTP servers and browsers stopped. No real provider calls or screenshots were made. Focused follow-up tests passed 31 cases, including secret echo, refusal, missing usage, and timeout exception suppression. No full suite was rerun.

## Click Path

1. Sign in as `admin` using the owner-known local credential.
2. Open `/admin/tools/review`, review all 14 displayed tools, schemas and fingerprints. Enter the owner-known local password, confirm the displayed snapshot, then select **Approve reviewed snapshot**. Require the saved approval audit receipt.
3. Open `/admin/demo`. Select **Reset demo**, then **Run five stories**. These allocate isolated scenario state, not a production reset.
4. Open `/admin/demo/source` for emitted source evidence, `/admin/demo/guard` for Aegis/Delta saved judgments, `/admin/demo/briefing` for the morning briefing, and `/admin/demo/results` for actual verdicts and contract gaps.
5. Follow this run's proof links under `/admin/demo/proof/`. Ordinary `/audit` is a separate parent audit stream. Do not substitute normalized scenario references for its database IDs.
6. Open `/local-demo` for the combined source/scenario, Aegis/Delta, briefing and copied-proof tamper panel. Sign in separately as ops and riley to approve the same saved synthetic pack. First approval stays held; a repeated identity is rejected; the second distinct identity marks the pack approved. Pack approval never releases an action.
7. Local `/approvals` additionally requires ops and riley for action approval: first approval remains held, duplicate and creator approvals are rejected, second approval invokes the original fingerprint/expiry/release checks. On `/local-demo`, dana selects **Seed synthetic quorum action**. Open its `/approvals/{id}` detail separately as ops and riley and enter a short review reason. The actual browser gate verified first approval held, duplicate rejected and second approval executed the legitimate large-refund fixture in the in-memory sandbox. No actual payment or outbound message occurs.

All model judgments are scripted stand-ins, not live AI. Existing scenarios include risky actions, unsupported numeric claims and contradictions. HOLD is not BLOCK. The source view is emitted JSON evidence, not a newly completed rogue-pack comparison interface. The observed guard pair is Aegis safe / Delta unsure, not Delta unsafe. No full AvePoint acceptance claim is made.

## Reset And Stop

Stop only the owned foreground launcher with Ctrl-C in its terminal. SIGTERM to the displayed owned HTTP child also causes the parent to finish. Do not use pkill, killall or port-wide termination. `run-local-demo.sh stop` requests termination through the owned private Unix control socket, not a saved PID or a port-wide process search. This command was verified against the repeated server.

After stopping:

```sh
./run-local-demo.sh reset
./run-local-demo.sh
```

Reset atomically renames the entire demo directory to `.local-demo-archive-<timestamp>`. It never deletes user files or clears production logs. Running-state reset is refused by an exclusive owner lock. Both active state and archives are gitignored and absent from tracked-file release inventories. Do not include ignored state in ad hoc release archives.

## Verification

The existing browser rehearsal was minimally adapted to accept the already-running loopback server and its private credential file:

```sh
$HOME/Qwen/aegis/.venv/bin/python scripts/demo_rehearsal.py \
  --approve-sandbox --existing-url http://localhost:8000 \
  --password-file "$PWD/.local-demo/passwords.json" \
  --output-dir /absolute/empty/output-directory
```

Two actual server rehearsals passed, separated by stop, archive reset and a fresh one-command startup. Each captured 25 screenshots across 1440 and 390 pixel viewports, checked twelve existing private routes, five scenario results, verified audit history and zero synthetic sends. Browser requests outside the origin were blocked and none were observed. No full suite was run.

The launcher allowlists inherited environment names. Explicit scripted mode enforces loopback sockets/DNS in its Python HTTP process; normal mode gates external access to the pinned provider transport as described above. Python descendants inherit a gated sitecustomize policy through PYTHONPATH in scripted mode. This is a trusted-Python runtime boundary, not an OS sandbox against arbitrary hostile native executables.

The final implementation was rehearsed twice against actual servers with an archive reset between them. Four-role `/local-demo` browser smoke checks passed on both runs: first reviewer held, duplicate reviewer rejected, second reviewer approved, original proof seal true and modified COPY seal false. Main saved proof and audit history were not tampered with.

Scoped gates passed on the repeated clean runtime: 35 GET routes from the current source inventory, 175 named-role cases at 1440 pixels, valid run/approval/incident/audit/proof IDs, no 404/422/500 responses. Expected authorization denials and redirects are retained in get-matrix.json. Every successful HTML page had the universal offline/scripted banner. Viewer login and panel were verified. The existing scenario proof/source/guard/briefing pages prove the requested moments without claiming live AI or broader sponsor correctness.

The owned-dummy collision check reserved 8000, observed readiness on http://localhost:8001 (HTTP child 64339), stopped only the demo via its control socket and proved the dummy still owned 8000. The dummy was then closed by its own test scope.

Focused commands after the rehearsal: `scripts/local_action_smoke.py OUTPUT`, `scripts/local_get_smoke.py OUTPUT`, `scripts/local_panel_smoke.py OUTPUT`, and `scripts/local_port_smoke.py`, all using the verified installed Python. Historical local smoke checks did not run the full suite. The presentation release subsequently completed the canonical 2,147-test, 30-shard suite with jobs=1 and zero skips; see `recording-script.md`.
