# OPTION 3: mixed Fly deployment (supersedes historical guide below)

Fly release target: twinguard-demo.fly.dev, personal organization, primary region sin.
No GitHub push or local Docker. Deploy uses remote build only. One 1GB aegis_data
volume at /data and one runtime Machine, UID/GID 10001. One-time administrative
bootstrap verified /data ownership 10001:10001 and mode 0700.
Fly first-party header contract: https://docs.fly.io/networking/request-headers.
Observed immediate peer 172.16.11.2 is trusted as /32 only; Fly-Client-IP replaced
spoofed input in the HTTPS probe. X-Forwarded-Proto can retain client input:
non-HTTPS values fail closed, never broaden trust. Revalidate peer after host moves.
Missing DeepSeek key returns polite SCRIPTED fallback without budget reservation;
failed/uncertain configured live calls still HOLD. Actual acceptance recorded separately.
Public visitors always start SCRIPTED even with keys present. The existing private
qwen_client imports executors and private state: it is intentionally NOT imported.
mixed_demo is a narrow transport adapter using the same OpenAI-compatible HTTP
protocol. Seven-module image closure is explicitly tested; no new dependencies.

Operator-issued codes unlock real model judgments, not administration. No budget
controls or operator role are exposed publicly. Each code is 32 random bytes
(256-bit entropy), URL-safe, stored only as sha256: plus 64 lowercase hex digits
in AEGIS_LIVE_ACCESS_CODES (CSV). Every digest is compared with compare_digest.
Plaintext is shown only on the operator terminal, never persisted by the generator.
Only pass the hash to Fly secrets. Session cookies expire in one hour; resets do
not reset usage. Rotating code hashes does not revoke already-unlocked sessions;
wait for expiry or perform an explicitly reviewed server-side revocation.

Caps: session 30 calls, salted IP 60/day, global 1500/day, 2,000,000 tokens/day,
10,000,000 tokens/month. Each evaluation reserves TWO calls and 40,000 tokens
atomically in SQLite before network. UTC day/month windows; session is lifetime.
Known usage settles reservations; timeouts/unknown usage retain them and block
further live admission across restart and rollover until private reconciliation.
Only one live evaluation at a time; concurrent attempts HOLD, not unsafe fallback.
IP identifiers use HMAC with persistent internal key and UTC date, not raw IPs.
Caps can be lowered by named AEGIS_LIVE_* variables, not raised above defaults.
Exhaustion returns polite SCRIPTED simulation; uncertain/invalid/failed live
judgment returns HOLD. Deterministic blocks are never promoted by model output.
No upstream output/reasons/errors are returned or logged. No email, payment,
upload, tools or worker dispatch exists. Only fixed HTTPS provider endpoints;
redirects and environment proxies disabled. These are application controls,
not an OS egress firewall or a mathematical token billing guarantee.

Official docs fetched via built-in search and public URLs, November 21 2026:
https://api-docs.deepseek.com/ confirms https://api.deepseek.com and OpenAI format,
but now lists deepseek-flash/deepseek-v4-pro, NOT deepseek-chat. Requested
deepseek-chat default is retained; acceptance of that alias is UNVERIFIED and
may HOLD. Set AEGIS_LIVE_MODEL only after operator account/model verification.
https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope
now recommends workspace-specific domains; the fixed legacy Singapore endpoint
is retained for the existing client contract. Account compatibility is pending.

Fly runbook is delivered with the prelaunch report. One Machine, one aegis_data
volume at /data, 8080, /healthz and /readyz, autostop off. Actual exact hostname
and immediate proxy CIDRs must replace placeholders, never universal ranges.
Trusted proxy health probes may use HTTP only at exact read-only health routes.
Untrusted probes remain blocked. Provider ingress/volume UID 10001 ownership,
base-image runtime, real-provider calibration and restart/redeploy acceptance
remain prelaunch gates. Fresh-volume chown in Docker build is NOT mount ownership.
Do not clear pending reservations without independently verified usage settlement.
The old Render/Railway recommendation and six-module/no-model descriptions below
are historical evidence, not the current deployment contract. Railway config
remains deprecated. Existing immutable audit event capacity behavior is unchanged.

# Public simulated demo deployment

Status: local public evaluator integration verified on 2026-11-20 UTC; managed-host acceptance NOT performed. No Docker installed/run, host deployment, signup, payment or push performed. Local commit is authorized after focused checks; no full-suite claim.

## Verified public facts

Checked 2026-11-20 UTC using built-in web search followed by official documentation fetches. Prices below are current source quotations and arithmetic examples, not future promises; review checkout before approving payment.

| Host | Persistent single-instance option | Cost and free constraints |
|---|---|---|
| Fly | One shared-cpu-1x 512MB Machine in iad + 1GB volume | $3.69/30 days compute + $0.15/GB/month volume = $3.84 before traffic/tax/other resources. No monthly platform fee. No general free tier; trial is $1/7 days. Official docs mention personal-organization bills below $5 waived; eligibility and total bill must be checked, never assume free. |
| Railway | Hobby service + one attached volume | $5/month minimum including $5 usage; CPU $20/vCPU/month, RAM $10/GB/month, storage $0.15/GB/month used, egress $0.05/GB. Actual bill can exceed $5. Free has $1 monthly usage, sleep and 0.5GB volume; service stops when exhausted. Trial $5/30 days is not perpetual always-on hosting. |
| Render | Paid 0.5c-512mb + 1GB disk | $7/month compute + $0.25/GB/month disk = $7.25 before overages/tax. Hobby workspace is $0 plus compute, not free persistent compute. Free web services cannot attach disks. |

Recommend Render for this user's click-led deployment: paid compute plus 1GB persistent disk has a clear $7.25/month base and straightforward Blueprint UI. Fly is cheaper at $3.84 base in iad but requires CLI-led Machine/volume configuration. These are qualified choices, conditional on measured memory, volume ownership, trusted ingress and actual host acceptance. Neither is HA: a single host/volume failure causes downtime. Railway remains an alternative with explicit UI settings because its legacy JSON configuration is deprecated. No static profile alone certifies managed-host readiness.

Sources:
- https://render.com/pricing
- https://render.com/docs/disks
- https://render.com/docs/free
- https://render.com/docs/blueprint-spec
- https://docs.fly.io/about/pricing
- https://docs.fly.io/reference/configuration
- https://docs.railway.com/pricing/plans
- https://docs.railway.com/pricing/free-trial
- https://docs.railway.com/volumes/reference
- https://docs.railway.com/deployments/healthchecks
- https://docs.railway.com/reference/config-as-code
- https://docs.railway.com/infrastructure-as-code

IMPORTANT: Railway's official current docs say railway.json is deprecated, new services cannot opt in, and legacy files stop being read on 2026-12-01. The supplied railway.json is ONLY a syntax-compatible legacy reference. New projects MUST set equivalent values in Settings UI; do not claim the file provisions a new host. Railway volume attachment is explicitly UI-managed here; no unsupported volume JSON field is declared. IaC migration requires separately scoped .railway files, not silently added by this lane.

## Entrypoint contract and blockers

Entrypoint is `python -m aegis.production`. Image module closure: production -> public_evaluator -> claims, policy.evaluate_lumen, sensitivity. Only these six Python modules including __init__ are copied. policy imports PyYAML at module level; its legacy db/audit imports are function-local and not reached by evaluate_lumen. claims and sensitivity use standard-library imports only. The bounded invented Lumen fixture excerpts live in public_evaluator; verdicts are calculated from input, not hardcoded. Separate temporary-package subprocess test verifies input-dependent decisions and absence of imported config/db/audit/gateway/qwen_client/worker. No lumen_world or lumen_sponsor module is needed. The Docker image omits legacy executors, run.py, API client, external policy files and private runtime. Non-root UID/GID 10001; Compose rootfs is read-only, capabilities dropped, ONLY /data writable (no /tmp tmpfs). Managed platform rootfs read-only enforcement is NOT established by a Dockerfile. Compose declares read_only; equivalent self-managed invocation must use Docker --read-only with /data as the sole writable mount. These commands were NOT run, intentionally per Mac heat restriction. Application-owned key/DB/tmp paths are under /data; that is not OS enforcement against arbitrary rootfs writes. Fly/Render/Railway managed read-only enforcement remains unknown, requiring operator acceptance of this limitation or a supported enforcement configuration. Do not equate non-root with read-only or label the intentional no-Docker check an implementation failure.

Core lead owns production.py. Current source honors PORT before AEGIS_PRODUCTION_PORT fallback; creates owner-only /data/aegis/keys, /data/aegis/db and /data/tmp; generates key once and refuses retained database without original key. Existing first-version layout is preserved, not migrated or silently rekeyed. Loopback GET /healthz and /readyz may use HTTP; public routes still require HTTPS and exact hosts. Trusted edge must REPLACE X-Forwarded-For with exactly one valid client IP; comma-separated/appended chains are rejected. This is stricter than many default provider proxy behaviors: verify actual provider behavior, do not guess CIDRs or assume compatibility. Non-loopback host healthchecks can still fail because they do not receive the loopback exemption. Host probe/forwarding acceptance is NOT verified; core owner must coordinate any narrowly scoped provider adapter if necessary. Single-worker/shared-root lock cannot stop independently provisioned Machines with separate SQLite volumes.

Fresh managed volumes may be root-owned. Pre-provision /data ownership for UID/GID 10001 using a separately approved one-time platform administrative operation; then restore runtime non-root. Do not set RAILWAY_RUN_UID=0 as a permanent workaround. Railway explicitly warns non-root images have volume permission issues. Do not deploy until ownership is established and a rehearsal verifies it. Key directories and data directories must be 0700, keys 0600. Directory separation within one volume is NOT an independent security boundary or rollback-proof external anchor.

## Audit quota (core e1750a5)

AEGIS_DEMO_MAX_EVENTS is optional on every host: default 10000, integer range 1..100000. Profiles omit it intentionally to use the default; set it in host Variables/Environment only when explicitly choosing another limit. Invalid values refuse startup. This is a global immutable-event count, not per-user, disk-byte or spend quota.

Admission uses BEGIN IMMEDIATE and checks required slots in the same transaction as session/action/reset changes. At capacity mutations return 429 without partially creating sessions or advancing generations; nightly reset also refuses atomically and does not erase events. /healthz stays live; /readyz returns 503 with capacity=false. Existing authenticated visitor /audit/export remains read-only and returns only that visitor's generation/event metadata. It is NOT an operator backup of the full encrypted immutable ledger. Session expiry can prevent later visitor export; preserve state via operator backup before expiry/capacity.

All profiles use /readyz: provider health handling can stop routing traffic at quota, so browser export is not guaranteed reachable through the public edge even though the app read route remains available. Operator must arrange approved maintenance access/backup of the whole DB and keys. Restart does not clear quota. Preserve original immutable history and key together; archive privately, then explicitly provision a new independent volume if replacement is approved. No automatic erase, vacuum-to-hide-history, key regeneration or in-place history reset. Raising quota within supported bounds is an explicit capacity decision, not deletion.

## Configuration inventory

`.env.example` documents names only, never real secret values. Do NOT inject the entire template into the public service. Public variables: AEGIS_DEMO_MAX_EVENTS optional default 10000 (1..100000, global immutable-event admission limit); AEGIS_ENV=production, AEGIS_DEMO_PUBLIC=1, AEGIS_WORKERS=1; AEGIS_PRODUCTION_DATA_DIR=/data/aegis canonical owner-only root; AEGIS_PRODUCTION_HOST=0.0.0.0; PORT from host (8080 locally); AEGIS_PRODUCTION_PORT is the fallback only when PORT is absent; AEGIS_DEBUG and DEBUG must be disabled (true/yes/1 refused); arbitrary AEGIS_*PASSWORD names with demo-prefixed values are refused, not public login configuration; AEGIS_TRUSTED_HOSTS comma-separated exact hostnames (no wildcard); AEGIS_TRUSTED_PROXY_CIDRS comma-separated reviewed actual immediate proxy CIDRs (empty fails public HTTP behind edge); optional AEGIS_TLS_KEY_FILE/AEGIS_TLS_CERT_FILE for direct TLS; TMPDIR=/data/tmp and HOME=/data for writable paths. Do not guess universal proxy ranges or trust 0.0.0.0/0. Verify ingress rewrites forwarded headers and does not permit direct bypass. Provider-issued health host may need narrowly scoped probe handling; Railway documents healthcheck.railway.app.

Private-only config.py variables: AEGIS_DATA_DIR, AEGIS_SIGNER_STATE, AEGIS_SIGNER_PORT, AEGIS_ANCHOR_EXTERNAL control legacy persisted state; AEGIS_EVIDENCE_KEY, AEGIS_EVIDENCE_KEY_FILE, AEGIS_EVIDENCE_KEYRING_FILE supply private encryption identity; AEGIS_QWEN_API_KEY enables external model calls, AEGIS_QWEN_BASE_URL selects endpoint; AEGIS_MODEL_JUDGE/WORKER/FAST select models; AEGIS_SPEND_CAP_USD, AEGIS_JUDGE_TIMEOUT_S, AEGIS_ADAPTIVE_SEED, AEGIS_ADAPTIVE_SPEND_CAP_USD control private demo budgets/timeouts/seed. Other legacy variables: AEGIS_HOST/PORT listener, AEGIS_HTTPS secure cookies, AEGIS_REPLAY_FILE replay input, AEGIS_RECORD recording toggle, AEGIS_AGENT_TOKEN child credential. NEVER set legacy credential/replay/record variables in public demo. Public simulated demo needs no Qwen key and no external credentials. Qwen integration is a separate explicitly authorized private deployment, not this public image.

## Render click path (operator only)

1. Sign in at https://dashboard.render.com and authorize ONLY the intended repository. Review billing and select paid compute, not Free.
2. New > Blueprint, select repository/branch and render.yaml; review the resource plan. Confirm 0.5c-512mb, one instance, /data 1GB disk, automatic deploys off. Creation starts a deploy: do not click until core gates are green.
3. Supply exact public hostname and independently verified proxy CIDRs in the requested fields. If hostname is not yet allocated, let fail-closed startup remain unavailable, then update Environment once the hostname is shown; never use wildcard to bootstrap.
4. Verify Disk mount /data, provision UID 10001 ownership, and select Manual Deploy after environment correction. Do not use pre-deploy command for disk initialization: disk is only available at runtime.
5. Verify /readyz and public HTTPS flow. Disk services cannot scale horizontally and have brief stop/start redeploy downtime. Test persistence through one approved restart and redeploy.
6. Optional Settings > Custom Domains: add owned domain, follow displayed DNS records, wait for TLS, then add exact hostname to trusted hosts. No domain purchase is performed here.

## Fly operator path

Fly is CLI-led, not a fictional one-click volume deployment. Sign in at https://fly.io/dashboard, review organization billing, install official flyctl only after approval.

1. Choose unique app name and region; update fly.toml app/trusted host. `fly launch --no-deploy` is an operator action that creates remote resources, not executed here.
2. Create exactly one 1GB aegis_data volume in iad using `fly volumes create aegis_data --region iad --size 1`. Review charges before confirmation. Establish non-root volume ownership before runtime.
3. Supply reviewed proxy CIDRs and confirm no private credentials. Disable HA duplication on deploy with `fly deploy --ha=false`; keep one Machine using approved `fly scale count 1`. Do not enable autoscaling, canary or bluegreen with SQLite.
4. Dashboard > app > Machines/Volumes: verify exactly one Machine, correct attached volume and region. Dashboard > Monitoring/logs: check readiness and redacted failures. min_machines_running is a floor, NOT a maximum.
5. Verify public HTTPS, role isolation and restart/redeploy persistence. Optional Certificates/domain configuration requires operator-owned DNS and exact trusted hostname.

## Railway click path (new service UI)

1. Sign in at https://railway.com, review Hobby billing (not trial permanence), New Project > deploy intended GitHub repo. Initial import can deploy immediately; do this only after core gates or pause service while provisioning.
2. Service > Settings: Dockerfile builder, Dockerfile path Dockerfile; start `python -m aegis.production`; healthcheck /readyz, timeout 300; restart ON_FAILURE, maximum retries 3. New services ignore deprecated railway.json; set these in UI explicitly.
3. Add volume from project canvas/service volume controls, attach to THIS service and set mount /data. Verify volume attached in service; cannot declare it in railway.json. Keep one replica, one region, no serverless sleep for always-on Hobby demo. Volumes cannot be used with replicas; redeploy has brief downtime.
4. Variables: public config only; platform supplies PORT. Set exact generated HTTPS host, include narrowly scoped Railway probe host as required by integrated core, and verified actual immediate proxy CIDRs. Establish UID 10001 ownership without permanent root override. Stop if unsupported.
5. Settings > Networking > Generate Domain, use platform HTTPS URL; redeploy after exact trusted host configuration. Railway healthcheck is deploy-time ONLY, not continuous monitoring. Manual checks after deploy/restart are required; continuous uptime monitoring is optional and is not an added go-live requirement.
6. Optional custom domain in Networking, follow shown DNS and TLS verification. Review memory/CPU/volume/egress usage and set billing alerts; a usage limit can stop availability.

## Audit evidence and limits

Production hash lock now contains 18 pinned packages, including uvicorn 0.54.0, PyYAML 6.0.3 and opentelemetry-api 1.45.2. PyYAML hashes include CPython 3.12 Linux amd64/arm64 wheels and source archive. Linux amd64 and arm64 clean binary-only dry resolution with --ignore-installed --require-hashes passed on 2026-11-20; no runtime dependency installed. Production-lock pip-audit rerun returned 'No known vulnerabilities found'; earlier installed-environment audit also clean. Standard audit sent package metadata only, not repository code or credentials. Current advisory coverage is not proof of no vulnerabilities or base OS clearance. Docker build/runtime deliberately not performed per user request.

Base image digest came directly from Docker Hub registry manifest API for library/python:3.12-slim-bookworm; Docker-Content-Digest matched locally computed SHA256 of response bytes: 935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df. Multi-platform index includes linux/amd64 and linux/arm64. No Docker installed or executed.

Fresh redacted heuristic scan on 2026-11-20 includes tracked files AND nonignored untracked new code/docs, plus all reachable history; hidden/key files excluded, no actual .env values accessed and no network credential validation. Current: 295 eligible files, 3 excluded, 14 matched lines across 10 paths (13 credential-literal, 1 provider-token shape). History rerun against e1750a5: 129 commits, 905 unique blob/path pairs, 11 candidate paths, 33 matched blob/path/category entries. No private-key-header hits. Bounded AST/context classification without printing values: current aegis/redteam.py:16 is explicitly dummy-marked (historical 7 versions also dummy-marked); historical Compose hits are ${...} interpolation (2 versions), not embedded credentials. Bounded AST/data-use review now classifies the remaining 13 current matches in 9 test files as constructed test fixtures: password/session identity inputs in test_password_change_revokes_other_sessions and local create_user/login helpers; secret sentinels inserted into proof/briefing assertions; provider-shaped text passed to detect_secrets; registered-secret attack inputs and persisted synthetic session/card token. These are confirmed fixture uses, not merely inferred from tests/ path. Current disposition: all 14 matches explained (1 explicit dummy, 13 constructed fixtures), zero unexplained matches within this heuristic scope. Historical totals are pattern counts, not blanket per-version fixture clearance; 24 test blob/category entries remain history-only provenance candidates, while 7 redteam dummy versions and 2 Compose interpolation versions are explained. Paths/lines: tests/test_auth_password_regression.py:91; test_c4_proof_pack.py:93,104,233; test_detectors.py:21; test_g1_metrics_screen.py:26; test_g1_view_route.py:40,111; test_new_attacks_delta.py:71,152; test_new_attacks_identity.py:54; test_proof_pack_receipt_bindings.py:10; test_t8_briefing.py:38. Values withheld. New public_evaluator and production code included; no candidate hits there. This is heuristic clearance of specific false positives, NOT exhaustive zero-secrets certification. No history rewritten; hidden-file/distribution review remains separately scoped.

Fresh command: `.venv/bin/python -m pytest tests/test_public_packaging.py tests/test_container_config.py tests/test_public_evaluator.py tests/test_production.py tests/test_production_https.py -q -s --confcutdir=tests` returned 24 passed, 1 pytest warning in 3.43s on 2026-11-20. Breakdown: packaging 7, reconciled container 3, evaluator 2, production boundary 11, real HTTPS browser 1. HTTPS receipt directory: `/private/var/folders/20/hrrmnm4n4m31m2bn72h7pfzm0000gn/T/pytest-of-chin/pytest-936/test_https_browser_all_roles0`; proof.json plus 36 screenshots cover 3 roles x 4 pages x 3 widths. Local ephemeral self-signed TLS verification bypass is test-scoped; Node also emitted a NODE_TLS_REJECT_UNAUTHORIZED warning inherited by the test process. Do not disable certificate validation on deployment. Starlette emitted an httpx TestClient deprecation warning. No failed tests, no new full suite. This local proof is not provider ingress, volume or container acceptance. Official JSON-schema validation attempted but unavailable because jsonschema is not installed; YAML/JSON/TOML parsing and focused assertions passed, not full provider schema certification.

## Post-quota verification

On 2026-11-20 after core e1750a5, `.venv/bin/python -m pytest tests/test_production.py tests/test_public_evaluator.py tests/test_production_https.py -q -s --confcutdir=tests` returned 16 passed, 1 pytest warning in 3.35s (13 production, 2 evaluator, 1 HTTPS). New quota tests verify atomic refusal, retained export/history, readiness 503, live health after restart, and concurrent last-slot admission yielding one 303 and one 429. Fresh HTTPS proof directory: `/private/var/folders/20/hrrmnm4n4m31m2bn72h7pfzm0000gn/T/pytest-of-chin/pytest-941/test_https_browser_all_roles0`. `.venv/bin/python -m pytest tests/test_public_packaging.py tests/test_container_config.py -q --confcutdir=tests` returned 10 passed in 0.39s after adding quota variable to template. Production-lock pip-audit rerun: no known vulnerabilities. No new full suite, Docker or managed-host check.

README comparison: README describes private local_setup/gateway demo and links docs/deployment.md, not the isolated public entrypoint. Its demo accounts and executor behavior must NOT be reused as public-service instructions. This deploy.md is the public-profile guide. Host facts remain the earlier November 20 official verification, not a newly claimed pricing fetch; Railway deprecation remains explicit.

## Recovery

Stop traffic before recovery. Back up SQLite using its backup API plus corresponding key directory and integrity metadata; do not copy a live DB file alone or regenerate keys against retained data. Rehearse restoring into a separate isolated service with no production volume sharing. Preserve full trusted state and avoid data-only rollback. Maintain reviewed previous image/source revision and inspect schema compatibility before rollback. Delete no volumes or keys without explicit operator consent. Lead adds exact rehearsal command, revision, receipt and result later; no invented PASS.
