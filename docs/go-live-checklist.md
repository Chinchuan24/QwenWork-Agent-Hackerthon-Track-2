# Public demo go-live gate

Current Fly target: twinguard-demo.fly.dev, sin. Sanitized receipt: twinguard-host-backup-evidence-20261121.txt (2026-11-21 UTC). Host agent consumed the ONE start budget; no further host operations or restart loop are authorized. Current docs/helper commit does not deploy or alter original history.

## Verdict: Qualified host backup PASS; user actions pending

- [x] One Machine 78111244b62498 and one encrypted 1GB aegis_data volume vol_rkg27pyzpkno1l24 in sin observed before/after. Configuration and status support single-instance operation, not autoscaling/replicas; minimum running count is not a maximum.
- [x] Actual start 09:00:45Z; last observed 09:03:36Z started with 2/2 checks passing. Ordinary outside /healthz and /readyz returned 200. This short window is not continuous availability or billing-stop proof.
- [x] Actual ingress configuration matches exact host, Fly provider and approved 172.16.0.0/12; prior observed peer 172.16.10.210. Prior focused ingress/mixed/HTTPS suite: 37 passed, not newly rerun host evidence. Fly-Client-IP is one edge-replaced address; ordinary proxied pages require forwarded HTTPS. Trusted exact GET probes alone permit transport-local HTTP.
- [x] Runtime app UID/GID 10001; /data/aegis mode 0700. Rootfs requirement DISPOSITIONED by explicit user acceptance: actual / is writable overlay and /data writable ext4; non-root permissions constrain ordinary writes but do not enforce writable-only-/data. Reason: retain current managed Fly runtime while honestly accepting this residual limitation.
- [ ] Read-only-root enforcement: NOT established; disposition above is not enforcement PASS.
- [x] Real online SQLite backup under BEGIN IMMEDIATE writer lock, separate read-only backup connection, original stable key copied in the same snapshot, off-host isolated restore PASS. sessions=8, events=9, live_sessions=2, live_attempts=0; integrity ok, 9/9 HMAC links, Fernet decrypt and canonical payload checks pass. Auxiliary SQLite has no tables. Plaintext backup is owner-only, not additionally encrypted; retain/encrypt privately. No secret archive is delivered.
- [x] Public-production external anchor N/A: absent and not implemented via AEGIS_ANCHOR_EXTERNAL; signer=false, simulated_hmac=true. Public consistency only, no independent provenance/coordinated-rollback guarantee; private signer/anchor acceptance is not claimed.
- [ ] Exact pre-stop/post-start persistence equality remains UNVERIFIED: machine was already stopped and no numeric pre-stop baseline existed. Repeated post-start 9 events and restored 9 events do not supply that baseline. Future explicitly authorized task after billing must capture a baseline before any restart.
- [ ] Local Docker remains UNRUN under Mac heat rule; real remote Fly image/runtime is separate evidence.
- [ ] User personally adds/approves billing; no card or billing change performed here. If platform stops, report and stop, never restart-loop.
- [ ] User DeepSeek key, account/model calibration and optional owned custom domain/DNS/TLS remain pending; no live API request or credential change claimed.

## Historical local gates (not current host instructions)

The remainder preserves older evidence and superseded pending lists. Historical single-root manifests, local gate counts and no-host statements are stale for the current multi-commit Fly release; they are not fresh acceptance or directions to create resources. Current gates above control.

- [x] Native per-crate attribution complete: 133 registry lock entries, 131 unique official archives SHA256-verified; 240 legal texts plus full copyright/SPDX comment blocks retained in included `RUST_THIRD_PARTY_NOTICES`. Nine root/path entries covered by full legal texts/headers from both verified PyPI sdists.
- [x] wit-bindgen-rt 0.39.0 missing archive licences resolved from official workspace licences at exact archive-recorded VCS commit, source URLs/hashes retained. Zero missing/unknown or incompatible selected licences; permissive alternatives elected and mandatory Unicode/BSD/exception scopes retained.
- [x] Existing seeded route-role acceptance and 2081-test/30-shard suite reused for docs-only changes. Fresh release fingerprint-bound scanner must match the new immutable single-root release; external receipt carries identity. Historical local gates below are superseded by final audit closure; actual host/container acceptance remains unperformed as explicitly requested.

## Native provenance follow-up (historical)

Official PyPI sdists SHA256-verified; both Rust BOMs enumerate every locked crate, exact-version crates.io checksum/license metadata, and separately resolved root/path project licenses. 40 cryptography packages and 102 pydantic_core packages; zero unknown or incompatible expressions found. OpenSSL 4.0.3 wheel statement verified against official cryptography changelog; official Apache-2.0 text/source/hash added to THIRD_PARTY_NOTICES. Full per-crate attribution/NOTICE completeness remains unverified, so binary redistribution clearance and READY TO DEPLOY verdict are not granted. Existing 2081 tests across 30 shards and browser/restart receipts are reused for docs-only work; host gates remain pending. No deployment, publishing, signup, push or Docker action.

## Verified local evidence

- [x] Official Render/Fly/Railway facts searched/fetched 2026-11-20; source links and dated costs in deploy.md. Render recommended for simpler click-led paid deployment ($7.25 base); Fly cheaper CLI option ($3.84 base in iad).
- [x] Docker Hub base digest matched computed SHA256; immutable multi-platform reference unchanged.
- [x] Six-module image closure includes actual pure evaluator, claims, policy and sensitivity; legacy executor/API client/config/db not imported by isolated evaluation test.
- [x] Production lock includes 18 pins with hashes, including PyYAML 6.0.3 and uvicorn 0.54.0; Linux amd64 and arm64 clean binary-only hash dry resolution passed.
- [x] Production-lock pip-audit rerun clean; no known vulnerabilities reported, not universal vulnerability clearance.
- [x] Current tracked plus nonignored untracked files/history redacted scan rerun: 295 files, 14 current matches all explained by bounded fixture/dummy use; history 129 commits/905 blob paths, 33 hits including history-only provenance candidates. Not exhaustive public clearance; hidden/key files excluded.
- [x] Compose non-root/read-only root, only /data writable declared; container tests preserve isolation/capability/context protections.
- [x] Core honors PORT before fallback; loopback read-only health/ready probes supported; public HTTPS boundary tests pass.
- [x] Fresh state uses owner-only keys/db subdirectories and sibling tmp; server generates key once. Retained DB missing original key refused. Existing first-version layout preserved.
- [x] Focused command in deploy.md: 24 passed, 1 pytest warning in 3.43s; 7 packaging + 3 container + 2 evaluator + 11 production + 1 HTTPS browser. No new full suite.
- [x] Local ephemeral HTTPS browser proof covers 3 roles, 4 pages, 3 widths, secure cookies, reset, denied actions and no external requests. Receipt: /private/var/folders/20/hrrmnm4n4m31m2bn72h7pfzm0000gn/T/pytest-of-chin/pytest-936/test_https_browser_all_roles0.
- [x] Local restart preserves key; quota remains full across restart and readiness remains 503 by design. No provider redeploy or backup/restore acceptance claim.
- [x] Post-quota core e1750a5: 16 production/evaluator/HTTPS tests passed in 3.35s, 1 pytest warning; separate 10 packaging/container tests passed in 0.39s. Exact commands in deploy.md. New proof: /private/var/folders/20/hrrmnm4n4m31m2bn72h7pfzm0000gn/T/pytest-of-chin/pytest-941/test_https_browser_all_roles0.
- [x] AEGIS_DEMO_MAX_EVENTS default 10000, range 1..100000 documented/template covered; atomic quota refusal retains immutable history and authenticated visitor export. Profiles use optional application default.
- [x] Packaging/core integration previously committed b284eb3; quota core committed e1750a5. This follow-up stages only documentation/template updates.

## Remaining target gates

- [ ] Parent independently verifies integrated core/packaging revision and decides full-suite schedule; no fabricated full-suite pass.
- [ ] Actual provider immediate-proxy CIDRs and single-address replacement of X-Forwarded-For confirmed. Nonloopback healthchecks may require core-owned narrow adapter; do not broaden public bypass.
- [ ] Linux fresh-volume UID 10001 ownership established; no permanent root workaround.
- [ ] Managed-host read-only-root enforcement verified or requirement explicitly dispositioned; Dockerfile alone cannot enforce it.
- [ ] Docker image build/runtime intentionally NOT run per Mac heat restriction; this is unperformed target evidence, not a known coding failure. Any later container proof requires a separately approved capable runner.
- [ ] Provider start/restart/redeploy retains state and keys; actual HTTPS host healthchecks accepted.
- [ ] Backup/restore rehearsal into isolated state completed; result PENDING, parent adds receipt later.
- [ ] Independent distribution review confirms history-only test provenance and excluded hidden/key-file handling. Current bounded candidates classified; do not treat heuristic scan as exhaustive credential clearance.
- [ ] Exactly one service/Machine/worker and one persistent volume confirmed; no SQLite replicas/autoscaling.
- [x] Existing local intended-file commit b284eb3 reviewed; no amend/push. Follow-up docs/template commit hash supplied in final response.

## Explicit user actions

- [ ] Choose Render (recommended click-led path) or cheaper CLI-led Fly; sign up and authorize only intended repository.
- [ ] Review current checkout pricing and approve billing personally.
- [ ] Provision persistent /data, non-root ownership, exact public host and reviewed ingress/probe configuration.
- [ ] Public simulated demo requires no external credentials; any private Qwen integration is separately authorized and never injected into this public image.
- [ ] Optional owned custom domain and DNS after TLS verification.
- [ ] Authorize deployment after target gates; follow deploy.md provider-specific steps.
- [ ] Perform manual health/role/reset checks after deployment/restart; choose backup/recovery owner and billing alerts. At quota, /readyz 503 may withdraw public routing: preserve whole immutable DB/keys via approved operator maintenance access before volume replacement. Visitor export is scoped metadata, not full backup. No automatic erase. Continuous monitoring optional.

Railway JSON is deprecated: current official docs forbid new-service opt-in and legacy reads stop 2026-12-01. Use Settings UI and attach /data volume there; no unsupported JSON volume declaration.
