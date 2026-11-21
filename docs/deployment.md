# Twinguard — local setup and cloud prerequisites

Built by Qwen. This document describes setup and state custody, not production acceptance. Docker packaging has not been built or verified here. Network installation, upload, remote login and publishing are waiting for Chin.

## Local fresh start (F01)

From the repository root, use README's Python 3.12 venv/install commands, then:

```bash
.venv/bin/python scripts/local_setup.py start
```

Port 8080 must be free. Open http://127.0.0.1:8080. The helper creates owner-only state and clears inherited AEGIS settings so a fresh local demo cannot accidentally use another runtime, replay file or live API key. It runs stand-in mode. Repeating init validates and preserves state; damaged, partial, symlinked, mismatched or nonprivate state is refused. Never repair a refusal by deleting keys or resetting audit history.

Live Qwen requires separately managed settings and network permission; the local helper deliberately disables it. Direct run.py still needs valid evidence key configuration before startup.

## State inventory and backup (F03)

The helper's `.local-runtime/` contains:

- `environment.json`: versioned relative path configuration and key fingerprints.
- `evidence.key`: current encryption key; retain every historical decryption key/keyring required by retained records after rotation.
- `data/`: SQLite DB, WAL/SHM sidecars if present, encrypted evidence, checkpoints, recordings and application state.
- `signer/`: separate signer key and forward-only records.jsonl.
- `external/anchor.json`: latest outside-data checkpoint anchor.

Signer and anchor state are outside **data/**, not outside the machine or inaccessible to its owner. The setup helper provisions signer state; the app communicates with the separate signer at runtime. Same-user OS read isolation is not claimed.

Stop writers gracefully before making a consistent backup of the complete runtime and separately configured historical keys. Keep the set private, encrypted according to operator policy, outside Git and outside share bundles. Do not copy only the DB or data directory. No destructive restore command is provided.

Restore only into a new private recovery location; preserve the original and any newer signer/anchor evidence. Verify the recovered set before using it. A historical DB restored against newer forward-only signer state is expected to fail rollback checks. A restored backup is not automatically current history, and failure is not proof merely that one file is missing. Stop and investigate; do not reset anchors or suppress verification.

## Clean demo versus recovery (F04)

A new empty Git clone plus `local_setup.py init` creates an independent demo with fresh keys and an empty history. It is not recovery, not continuation, and not a way to erase a failed audit. Existing runs/users/policies/decisions remain stateful in their original runtime. Keep that runtime and its backups intact. Never move only aegis_data aside and restart at unchanged external state paths.

## Container prerequisites (F02) — static repairs, runtime verification pending

Current `docker-compose.yml` is the isolated public simulated service, not the private gateway described above. It declares one persisted `/data` volume, read-only rootfs and non-root UID 10001. The Dockerfile copies only six public-evaluator modules, not local setup scripts or legacy executors. Its internal evidence key is generated once within the volume; no Qwen key is used. See `deploy.md` for ownership, ingress, quota and recovery boundaries. These are static contracts, not Docker runtime acceptance.

The image build, memory/CPU budget, health timing, password-script execution and restore behavior require actual container verification. No resource sizing or fixed startup time is asserted. Do not upload local runtime state as source code. `.dockerignore` now excludes local runtime directories, environment files, secrets, keys and keyring JSON; `.gitignore` alone does not protect Docker contexts. Static exclusion checks do not prove every possible secret filename is excluded.

## One disposable sponsor safety story

```bash
.venv/bin/python scripts/sponsor_story.py
```

This runs simulated Lumen S1 through the real gateway in isolated temporary state, using stand-in judges and a separate signer over pipes. Prints measured decisions, R15 block and audit/side-effect checks. Preliminary reads may be blocked too; exact full sponsor acceptance, live AI and browser acceptance are not claimed. Run the quick commands in README; full-suite and dependency advisory acceptance remain main-task gates.
