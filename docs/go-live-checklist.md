# Public demo go-live gate

Local integration verified 2026-11-20 UTC. Managed-host acceptance not performed. Local commit authorized; no push, deployment, signup, payment or Docker run. Core owns production.py and evaluator logic; parent next performs independent verification.

## Verdict: READY TO DEPLOY (pending host configuration)

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
