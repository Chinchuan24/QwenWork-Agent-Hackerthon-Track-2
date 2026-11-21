# QwenWork Pages feasibility

Status: **SCHEMA REVIEWED, NOT RUNTIME TESTED**. Source: current declared tool inputs/descriptions and parent-reviewed skill facts supplied in the task. This is not a connected-service inventory.

## Decision

A small self-contained Node database demo is plausible. The existing Python application cannot run as-is through this interface; keep it local or on its separately evaluated Fly path. Do not replace the full implementation just to obtain Pages evidence.

**Free use is unclear, so conditional permission to provision only if free is not satisfied.** No provisioning, migration, database read/write test, or publishing occurred. Publishing is explicitly forbidden. No internal configuration queries, Page/Barn MCP discovery, secret inspection, or public/private-product web research occurred.

## Declared contracts

Formal output JSON schemas are not exposed. Descriptive returns are not formal output contracts or tested results.

| Tool | Declared inputs | Description boundary |
| --- | --- | --- |
| `functions.qw-builtin_qwenwork_pages_publish` | Required absolute `file_path: string`. Optional `category: static\|dynamic`, relative `entrypoint: string`, `port: number`, `with_database: boolean`, `name: string`, legacy `command: string[]`. | Static HTML or dynamic Node project. Dynamic entrypoint required; default port 8081, never 9000. Legacy command only translates `['node', '<entrypoint>']`. Requires explicit publish permission; desktop confirmation collects access control, not `access_mode` or `access_members` parameters. Database-backed publishing follows provisioning. Non-retryable failure prohibits another publishing attempt that turn. |
| `functions.qw-builtin_qwenwork_pages_provision_database` | Optional `name: string`. | Creates/reuses the session dynamic Page database, waits ready, and pins later migrations/publishing to that Page. Description returns domain/state and says no Supabase credentials are exposed. Exact returned JSON shape is unexposed. |
| `functions.qw-builtin_qwenwork_pages_apply_migration` | Required `domain: string`, `sql: string`. | Must follow provisioning. Idempotent SQL executes in the Page schema; tenant-unqualified table names, no direct PostgreSQL or service-role credentials. |

Related declared Pages tools are these three only. No direct database inspection/read/write tool is declared here. No inference is made about undiscovered tools, and internal alternatives were not searched.

## Runtime fit

Parent-reviewed skill guidance describes Node 22, a self-contained project with `package.json` and installed modules, and listening through `PORT` / `HOST`. Python and arbitrary process commands are unsupported as-is by the declared publisher.

Database guidance describes Supabase-compatible PostgreSQL, not SQLite. Runtime injection is described as `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_INSTANCE_ID`; these are runtime configuration, not agent credentials. No values were inspected. Injection does not prove tenant isolation or authorization.

Separate provisioning and publishing suggests provision-before-publish is possible, not proof that an unpublished database is private, free, retained indefinitely, or accessible in a particular way. Provisioning may create a Page resource; its visibility and lifecycle remain unverified.

## Minimal proof demo

Only after cost and private-access terms are confirmed, and new explicit authorization covers remote actions, prepare four synthetic-data moments:

1. Load a briefing from persisted database records.
2. Show a proposed action with tenant, decision, and approval state.
3. Record an authorized approval or denial and read back the database row.
4. Verify an evidence-file hash and show the resulting decision receipt.

Make tenant IDs, decisions, approvals, evidence references, hashes, and timestamps explicit. Test denied actions, cross-tenant access, and hash mismatches. Do not upload real secrets, customer data, or sensitive evidence metadata. A database row proves persistence only, not universal worker interception, immutable audit history, or trustworthy signing. Tamper-evident signatures, signer identity, key custody, and independent verification are separate requirements. Scripted refresh is not proof of realtime behavior.

The owner's stated Track 2 requirement for a live-database application built with QwenWork makes this direction plausible, not a guarantee of judges' compliance interpretation. The exact AvePoint quote was not supplied verbatim here, so it is not invented or externally researched. A Node demo would not prove Python hosting, full product-engine integration, or submission eligibility.

## Scoped work

Scoped tasks rather than an unsupported hour estimate:

| Work unit | Required evidence |
| --- | --- |
| Confirm commercial/access terms | Owner-approved cost, unpublished visibility, access control, and retention facts. |
| Prepare isolated Node adapter | Self-contained project, PORT/HOST behavior, synthetic fixtures, no Python hosting claim. |
| Define tenant data contract | Minimal decisions, approvals, evidence references/hashes; explicit authorization and isolation rules. |
| Verify locally | Four scripted moments, approval/denial paths, cross-tenant negative tests, hash mismatch, restart persistence using an appropriate test database. |
| Remote verification if newly authorized | Controlled provisioning/migration/readback evidence. Publishing still requires new explicit permission and desktop access confirmation. |

## Unknowns and risks

- Pricing, free allowance, quotas, storage limits, and formal output schemas are unexposed; no free-use or available-plan claim is justified.
- No SLA, backup/restore guarantee, monitoring contract, or database lifetime was established.
- Desktop access confirmation is declared; specific private/password modes and unpublished database privacy are unverified.
- Authentication-provider configuration, secrets handling, persisted audit trust, retention, metadata exposure, and realtime support remain unverified.

## Review boundary

The capability file was read before editing. This feasibility path was checked and absent before creation. Only these two documents are owned by this review; no app code, key settings, or tests were edited. Pages execution evidence: **none**. No runtime or document test pass is claimed. Commit coordination belongs to the parent/integrator; no commit was made.
