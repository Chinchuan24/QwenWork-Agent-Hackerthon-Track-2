# QwenWork capability evidence: T11 Part A

Snapshot: 18 November 2026, this task's declared tool surface and observed execution only. A declared tool means an interface exists here, not that its service works, is connected, or is configured. `tested` refers only to the narrow scope stated below; `used` refers only to this inventory task. Unknown availability is not evidence of absence.

Historical planning inputs: the owner's Track 2 alignment, cybersecurity additions and Round 2 additions (kept outside this repository). These are not runtime dependencies or submission files. Repository evidence is indexed in `docs/progress.md`; historical outcomes were not re-executed for this inventory.

No internal QwenWork configuration was queried for this content. No login, publishing, schedule creation, account connection, media generation, or remote action was attempted. No key inspection or secret inspection was performed. No network calls or working-copy creation were performed. Only this document and its document tests were edited; no commits or core edits were made. Part B is not proven by this inventory.

F13 repair: this is a historical declaration snapshot, not today's connected-tool or runtime inventory. The session reference now names the stable progress heading rather than a drifted line number. Development skill loading and reported collaboration do not establish product-engine use. The acceptance target is a worker trace at the logged gateway boundary for simulated actions; no same-user filesystem interception or universal fail-closed claim follows. Original launch logs remain unavailable here.

## Inventory

The following JSON is the machine-readable evidence table. Tool names are exact current declaration names, not fabricated execution traces. Except for the skill load, no capability was tested or used in this refresh. Sessions and subagents also have historical reported observations in `docs/progress.md, heading 'Parallel Track 2 and governance work' (historical session report; stale numeric citation withdrawn)`: the integrator reports launching independent worker/checker sessions and sending repair follow-ups. This is evidence of reported use, not declaration-only absence, but this refresh did not observe the original launch results or recount them. 23 is a reported count, not a recounted measurement; the named list on that line is not independent count proof. No internal host queries were used to obtain content.

```json
{
  "sessions": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qw_query", "functions.qw-builtin_qw_action"],
    "scope": "Session/task inspection and historical-session operations are described by the tool declarations; no session lifecycle or Twinguard adapter tested.",
    "observed": "historical report",
    "evidence": "docs/progress.md, heading 'Parallel Track 2 and governance work' (historical session report; stale numeric citation withdrawn) reports independent worker/checker sessions and follow-ups; read with functions.read in this refresh. Neither session tool called here. No proof that worker actions were routed through Twinguard."
  },
  "skills": {
    "exists": "declared", "tested": true, "not_tested": false, "used": true,
    "tools": ["functions.skill", "functions.qw-builtin_qwenwork_skill_manage"],
    "scope": "Skill loading only: audit-verify-explain-grade-5 instructions used to separate claims from evidence. Skill creation, installation, watcher packaging and execution not tested.",
    "evidence": "functions.skill(name=audit-verify-explain-grade-5): returned skill_content"
  },
  "connectors": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qwenwork_mcp_tool_list", "functions.qw-builtin_qwenwork_mcp_tool_get", "functions.qw-builtin_qwenwork_mcp_tool_call", "functions.qw-builtin_qwenwork_channel_list_conversations"],
    "scope": "Discovery/calling interfaces declared; no upstream tools, connected accounts, IM targets or authentication state established.",
    "evidence": "Current declarations only; no discovery or connector call executed."
  },
  "cron": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qwenwork_cron_manage_job"],
    "scope": "Schedule management interface declared; no jobs listed, created, enabled or run. Morning briefing delivery not tested.",
    "evidence": "Current declaration only; no cron call executed."
  },
  "pages": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qwenwork_pages_publish", "functions.qw-builtin_qwenwork_pages_provision_database", "functions.qw-builtin_qwenwork_pages_apply_migration"],
    "scope": "Static/dynamic publishing and database interfaces declared; no database provision, migration or deployment executed.",
    "evidence": "Current declarations only; no Pages call executed."
  },
  "subagents": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qwenwork_task_send_message", "functions.qw-builtin_qwenwork_task_get_detail", "functions.qw-builtin_qwenwork_task_submit_response", "functions.qw-builtin_qwenwork_task_cancel"],
    "scope": "Existing sub-task control interfaces declared; independent creation, delegation and parallel execution not tested.",
    "observed": "historical report",
    "evidence": "docs/progress.md, heading 'Parallel Track 2 and governance work' (historical session report; stale numeric citation withdrawn) reports parallel independent workers/checkers and repair follow-ups, including the T11 inventory worker. Original launch/control results were not observed in this refresh; no sub-task control call executed here. No subagent creation tool is declared in this surface."
  },
  "media": {
    "exists": "declared", "tested": false, "not_tested": true, "used": false,
    "tools": ["functions.qw-builtin_qwenwork_image_generate", "functions.qw-builtin_qwenwork_video_generate", "functions.qw-builtin_qwenwork_music_generate", "functions.qw-builtin_qwenwork_media_task", "functions.qw-builtin_qwenwork_media_read"],
    "scope": "Image/video/music generation and media reading interfaces declared; no generated file, duration, narration accuracy or download verified.",
    "evidence": "Current declarations only; no media call executed. A 60-second briefing video is not proven."
  },
  "voice": {
    "exists": "not declared", "tested": false, "not_tested": true, "used": false,
    "tools": [],
    "scope": "No dedicated text-to-speech tool declared. elevenlabs-tts appears in the available skill list but was not loaded or executed. Video audio and music are not proof of scripted narration.",
    "evidence": "Current tool/skill declarations only; runtime voice availability unknown."
  },
  "Hashmeta": {
    "exists": "not declared", "tested": false, "not_tested": true, "used": false,
    "tools": [],
    "scope": "No named Hashmeta tool declared; undiscovered connector availability unknown. No account inspection, sign-in, draft or publishing attempted.",
    "evidence": "No Hashmeta declaration or observed execution; waiting for Chin: Hashmeta AI sign-in."
  }
}
```

## Evidence gaps

- Sessions: no independently controlled worker session or proof that every worker action passes through Twinguard's logged channel.
- Skills: loading instructions succeeded; no reusable watcher skill was packaged or run.
- Connectors: no discovery results or working upstream calls. Do not infer an account is connected from an interface name.
- Cron: no morning schedule or delivered briefing. Schedule creation is outside this task's permission.
- Pages: no live application, database or deployment evidence. Publishing is outside this task's permission.
- Pages feasibility follow-up: `docs/qwenwork-pages-feasibility.md` records declaration-only input contracts and parent-reviewed runtime guidance. Status: SCHEMA REVIEWED, NOT RUNTIME TESTED. Free use remains unclear, so conditional provisioning permission was not satisfied. No provisioning, migration, database read/write testing, or publishing occurred. Historical tested/used flags remain unchanged.
- Subagents: historical parallel use is reported at `docs/progress.md, heading 'Parallel Track 2 and governance work' (historical session report; stale numeric citation withdrawn)`; original creation traces and an independently measured count are unavailable here. Existing-task controls do not prove the ability to launch a new agent.
- Media/voice: no generation results or verified 55-65 second briefing video. Dedicated narration remains unknown.
- Hashmeta: connection unknown, website not built with Hashmeta here; waiting for Chin: Hashmeta AI sign-in. QW Pages is not Hashmeta evidence.
- Live Qwen judgments and briefing wording were not tested; earlier progress-log key limitations are historical reports, not a current credential check.

## Verification boundary

`tests/test_t11_capabilities.py` checks category coverage, explicit not-tested flags, declaration names, the observed skill-load trace, and visible limits. It is not a runtime integration test. Its expected names are manually grounded in this conversation's declarations; they do not automatically discover future tool changes. The trace is recorded here from the observed tool result, not independently authenticated from an exported host log.

The prior inventory recorded a first run with four missing-document errors; that historical run was not repeated here. This refresh added the observation-boundary test first and ran all five document checks: the new test failed with `KeyError: 'observed'` before the inventory was updated. After the update, all five checks passed. These are local document checks, not scripted business-suite or live integration measurements. Run the document checks directly with `.venv/bin/python tests/test_t11_capabilities.py` to avoid the application-wide pytest fixtures creating unrelated test users and signer state. No scoreboard, normal-task suite or dependency audit result is claimed here: this task changes only the inventory and its tests. An integrator must run the broader checks separately.
