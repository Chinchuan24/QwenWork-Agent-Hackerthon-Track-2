# Twinguard

Twinguard is a demo that checks an AI helper's actions on fictional company files.

## Why use it?

- See which actions pass the rules before they run.
- Review held actions instead of letting the helper continue unchecked.
- Read recorded explanations without treating model answers as proof of safety.

## How it works

1. Pick a task using fresh sample files.
2. Read each action's result: **ALLOWED**, **WAITING FOR YOU**, or **STOPPED**.
3. Review held actions; **ALLOWED** is not execution success, and **STOPPED** blocks the action.

Fictional tools and sample data only. No real emails, uploads, payments, or outside actions.

## Judge Summary

- Model mode uses real providers when available; fallback runs are labelled recorded mocks.
- Fixed rules can skip model checks; missing judge answers are never invented.
- Local mock tests support the demo; real-provider and deployed acceptance remain unverified.

This branch is not certified production-ready. See the [verified inventory](docs/production/LIVE-PRODUCT-PLAN.md).

## Limits

Open access is the default. All spending limits still apply.

| Limit | Default | What happens |
|---|---:|---|
| Provider calls per visitor | 30 | Labelled scripted fallback |
| Provider calls per IP per UTC day | 60 | Labelled scripted fallback |
| Provider calls per UTC day | 1,500 | Labelled scripted fallback |
| Tokens per UTC day | 2,000,000 | Labelled scripted fallback |
| Tokens per UTC month | 10,000,000 | Labelled scripted fallback |
| Action attempts per visitor per rolling minute | 6 | Seventh refused before provider calls |
| Concurrent live evaluations | 1 | Scripted fallback while busy |
| Output tokens per provider call | 512 | Capped output; uncertain replies held |
| Live enabled | 1 | Setting 0 disables new calls, not calls already running |
| Access mode | open | Optional operator-issued access codes |

These counters are not billing guarantees. Unknown usage stays charged until reviewed.

## Preview

No README banner or dashboard screenshots are included in this branch.

The available image is a [dashboard backdrop](aegis/assets/backdrops/B2-rainy-megacity-poster.jpg), not a screenshot.

<details>
<summary>Run and configure the demo</summary>

- Use Python 3.12 and exactly one process and instance.
- Install the locked runtime dependencies:

```sh
pip install --require-hashes -r requirements-production.lock
```

- The entrypoint is `python -m aegis.production`.
- Read the [runbook](docs/production/DEPLOY.md) for hosting settings; some descriptions cover the older simulation.
- Use the [current inventory](docs/production/LIVE-PRODUCT-PLAN.md) for mounted-dashboard capabilities and remaining checks.
- Use platform runtime secrets for provider keys; never put keys in browser files or commands.
- The [environment example](.env.production.example) contains placeholders only; do not source it or use dotenv.
- Role entry selects simulated viewers, approvers, or auditors; it is sample-only, not administrator login.
- No sample username or password is supplied. Optional live codes must come from an operator.

See the [Dockerfile](Dockerfile), [Fly template](fly.toml), and [Render template](render.yaml).
Templates are not evidence of deployment.

</details>

<details>
<summary>Technical boundaries and accounting</summary>

- The mounted dashboard uses the original gateway in a worker against fictional World data.
- Reviewed tools read, draft, delete, upload, and email within that fictional world only.
- Draft writes stay in the worker sandbox; a held draft is absent from files.
- Schema, scope, passport, containment, shield, enforcement, and approval checks remain in the dispatch path.
- Mounted evidence uses encrypted SQLite and a separate signer process.
- Restart verification and tampered-store rejection are tested, not durable dashboard task replay.
- The older public simulation uses local HMAC evidence, not independent signing or external anchoring.
- Replacing its database and key together defeats that public simulation's protection against privileged operators.
- Legacy evaluation reserves two judge calls and 40,000 tokens before dispatch.
- Mounted paths reserve 20,000 tokens per provider call; validated usage replaces reservations.
- Planning, checks, and approval rechecks count toward provider spending limits.
- Failed and finished plans consume admitted action attempts; idle advance requests consume none.
- Approval rechecks consume a new attempt; denial and simple sandbox approval do not.
- Internal contexts expire after 60 seconds and allow 16 reservations; startup allows one.
- Restart closes contexts without clearing burst history or unknown charges.
- Original spending caps can only decrease; burst accepts 1-60, concurrency 1-32, output 1-512.
- Use `AEGIS_LIVE_BURST_ACTIONS`; the retired `AEGIS_LIVE_BURST_CALLS` setting is ignored.
- Most limits load at startup; live enablement is checked before each new provider request.
- Audit storage exhaustion stops paid evaluations; HTTP security throttles are separate from spending caps.

Read the [complete limits and owner checklist](docs/production/LIMITS.md) for setting names and accounting details.
Read the [mounted backend inventory](docs/production/LIVE-PRODUCT-PLAN.md) for tested boundaries and remaining work.

</details>

<details>
<summary>Verification and release gaps</summary>

- The [earlier receipt](docs/production/VERIFICATION.md) records 108 passing tests and one warning.
- It describes an older eight-module package, not this branch's full mounted dashboard.
- The mounted backend inventory records 41 passing local tests using Python 3.12 and mocks.
- Recorded warnings include Starlette/httpx deprecation and subprocess or unclosed-file resource warnings.
- These are historical receipts, not tests run for this README.
- No real-provider acceptance, deployment, secret setting, image publication, or platform operations were demonstrated.
- Mounted-backend browser acceptance, public lifecycle/replay hardening, and resource cleanup remain open.
- Image builds, platform TLS/proxies, volume ownership, and single-instance enforcement still need release checks.
- Read-only root enforcement, monitoring, retention, backup/restore, and rollback require platform acceptance.
- `/healthz` checks liveness; `/readyz` includes local checks, not full mounted-backend acceptance.
- Visitor audit exports are metadata, not complete database backups.
- Backups must preserve database and original key together; never clear history to repair readiness.
- Pattern scans cannot prove every possible secret format is absent.

See the [release gates and operational procedures](docs/production/DEPLOY.md),
[provenance](docs/production/PROVENANCE.json), [manifest](docs/production/MANIFEST.json),
and [scan record](docs/production/SCAN.json).

</details>

<details>
<summary>License and notices</summary>

See [LICENSE](LICENSE), [third-party notices](THIRD_PARTY_NOTICES),
and [Rust third-party notices](RUST_THIRD_PARTY_NOTICES).

</details>
