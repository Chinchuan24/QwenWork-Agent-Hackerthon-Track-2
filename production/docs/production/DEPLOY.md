# Production Package Runbook

Source: `7efc4657a5e92712319573fe8b456ed3ce3bd186`. This package serves the isolated PUBLIC SIMULATION, not the full gateway or a production administrator. Optional LIVE model judgments operate on embedded fictional excerpts. No worker, payment, email, upload, or external action dispatch exists here. Do not market this as unconditionally production-ready.

## Configuration and Secrets

Entrypoint: `python -m aegis.production`. Python 3.12, exactly one process/instance, workers=1. Install only `requirements-production.lock` with `--require-hashes`. Docker base is digest-pinned. Test tools are not shipped.

`.env.production.example` is reference documentation with placeholders ONLY. Never source it, copy it to `.env`, or use dotenv. No `.env` discovery is implemented. Provider keys come only from platform secret environment variables. DeepSeek uses `DEEPSEEK_API_KEY`; Qwen uses `AEGIS_QWEN_API_KEY` and `AEGIS_MODEL_PROVIDER=qwen`. Public endpoints are fixed allowlists. Do not set both provider keys unnecessarily. Never print, log, check into Git, or place keys in command literals.

Fly template app and exact hostname must be replaced together. No commands below were executed. The exact safe placeholder form for staging secrets is:

```sh
fly secrets set --stage --app REPLACE_APP DEEPSEEK_API_KEY=REPLACE_IN_PLATFORM_SECRET_WORKFLOW AEGIS_LIVE_ACCESS_CODES=REPLACE_WITH_SHA256_DIGEST
```

Do NOT substitute a real key into shell history or a recorded command. Use the platform secure input UI or an approved secrets-manager integration instead. The command above describes names and staging only, not a safe plaintext key-entry mechanism. Staged secrets are not active until the separately approved release. Never use a source `.env` file to populate them.

Access codes must be generated using cryptographic randomness (32 random bytes encoded URL-safe, 43 characters), delivered privately to the approved user, and hashed as `sha256:` plus lowercase SHA256 of the code bytes. Store only that digest as `AEGIS_LIVE_ACCESS_CODES`. Multiple digests are comma-separated. Generate within the approved secret manager, without console output; keep the plaintext only in its protected recipient-delivery channel. Never include plaintext codes in this package or reports. Rotating digests prevents new unlocks but does not revoke already-unlocked persisted visitors; coordinate expiry/session revocation as an operator maintenance action. Default limits: 30 per visitor, 60 per IP/day, 1500/day, 2M tokens/day, 10M/month; these are application counters, NOT a currency/billing guarantee. Each judgment reserves two 20,000-token calls. Unknown usage persists as pending and holds future LIVE work; reconcile with provider evidence before any repair. Never blindly clear reservations.

## Host, Proxy, and Storage

Fly config retains source `172.16.0.0/12` as a template boundary, NOT verified authority for a new app. Verify the immediate peer range independently, narrow it where supported, and test spoofed headers from outside the range. Allow exact hostname only, no wildcard. Fly uses replaced `Fly-Client-IP`; Render uses a single replaced `X-Forwarded-For`; appended lists are rejected. Verify TLS termination and replacement of `X-Forwarded-Proto`. Uvicorn proxy reinterpretation is disabled. Render exact host and trusted immediate proxy CIDRs are manually supplied; absent values are not acceptance.

UID/GID `10001:10001`; writable persistent mount `/data`, with owner-only `/data/aegis`, `/data/aegis/keys`, `/data/aegis/db`, and `/data/tmp`. Initialize mount ownership for that UID before admission. One machine, one volume, no horizontal scaling. `min_machines_running=1` is not a maximum-machine guarantee. Root filesystem should be read-only with `/data` writable; Dockerfile does NOT itself enforce read-only root. Fly/Render capability and enforcement must be confirmed before release. If unavailable, record an explicit security exception with owner and mitigation, or do not deploy. Local read-only-container verification was prohibited and remains pending.

## Health and Monitoring

`/healthz` reports liveness only. `/readyz` checks database access, cipher roundtrip, simulated HMAC, and event quota; `signer=false` is intentional. Startup verifies existing evidence chain and refuses a missing key for existing history. Local/proxy GET health probes may use HTTP, other traffic needs HTTPS/exact host. Health requests are rate-limited too; use 30-second checks, not high-frequency polling.

Alert on readiness 503, request 5xx/429, volume capacity, event count near 10,000, reservation backlog, process restarts, failed backups, key/storage permission failures, and provider usage reconciliation. Logs contain method/status, not keys/bodies. No monitoring service was configured. Midnight UTC resets generations, not immutable audit history. Quota exhaustion requires reviewed export/new-volume disposition, not deletion of history.

## Backup and Restore

No platform backup or restore occurred. Before release, rehearse on disposable storage. Quiesce the only process, snapshot the complete `/data/aegis` directory (database AND original key together) with an approved encrypted backup mechanism. Protect backups as secrets, retain permissions and ownership, record snapshot and image digest, and test restore to a separate volume. Do not expose key bytes or raw evidence in receipts. Restart against restored storage and require `/readyz=200`, verified chain, preserved visitor events, and retained pending accounting. Missing/changed keys or a tampered chain must fail admission. `/audit/export` is visitor-scoped metadata, NOT a complete database backup. Avoid copying live SQLite files without quiescing or a transactional backup API.

## Rollback

Record the approved deployed image digest and compatible volume snapshot before changes. Stop traffic and the sole writer; restore a compatible image plus matching storage only after operator approval. Never rotate the internal key to make history appear valid. Verify readiness, scoped events, and accounting before reopening traffic. No image was built, pushed, deployed, or rolled back by this task.

## Assurance Boundary

Evidence uses an encrypted, local HMAC-linked chain plus SQLite mutation triggers. This is not an external anchor, independent signer, or protection against a privileged operator replacing both database and key. Embedded policy decisions are deterministic; semantic wording is an exact-text stand-in. Optional LIVE uses two classifier requests, not proven independent production judges. Real-provider acceptance, upstream usage failure handling, and operational security require separate evidence. No billing-plan assumptions or claims of guaranteed external anchoring are made.

## Untouched Release Gates

- [ ] Fly/Render app, account, plan/cost, volume ownership and singleton enforcement accepted.
- [ ] Exact new hostname/TLS and immediate proxy replacement verified on platform.
- [ ] Read-only root/nonroot volume enforcement verified or exception approved.
- [ ] Linux amd64/arm64 digest-pinned image build and dependency/security audit completed.
- [ ] Real DeepSeek/Qwen provider acceptance, usage reconciliation, caps and failure cases verified with approved platform secrets.
- [ ] Backup/restore, hard-stop recovery and compatible rollback rehearsed on platform.
- [ ] Monitoring/alerts, retention, incident owner and runbook acceptance completed.
- [ ] Optional AI/source acceptance gaps reviewed; public simulation claim boundaries approved.
- [ ] Deployment, push and any actual operations separately authorized.
