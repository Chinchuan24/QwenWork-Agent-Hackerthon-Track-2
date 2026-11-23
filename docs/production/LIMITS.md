# Public live demo limits

Open mode is the default: visitors do not need an access code. Set AEGIS_LIVE_ACCESS_MODE=access-code to require codes again. Every spending limit applies in both modes. No secret is bundled into the browser or image. Configure the provider credential only as a server-side runtime secret.

| Limit | Environment variable | Default | Visitor result |
|---|---|---:|---|
| Calls per visitor | AEGIS_LIVE_SESSION_CALLS | 30 | Scripted result and one plain limit message |
| Calls per IP per UTC day | AEGIS_LIVE_IP_DAILY_CALLS | 60 | Same scripted fallback |
| Calls per UTC day | AEGIS_LIVE_DAILY_CALLS | 1500 | Same scripted fallback |
| Tokens per UTC day | AEGIS_LIVE_DAILY_TOKENS | 2000000 | Same scripted fallback |
| Tokens per UTC month | AEGIS_LIVE_MONTHLY_TOKENS | 10000000 | Same scripted fallback |
| Gateway action attempts per visitor in rolling 60 seconds | AEGIS_LIVE_BURST_ACTIONS | 6 | Seventh attempt refused before any provider request; labelled fallback |
| Concurrent live evaluations | AEGIS_LIVE_CONCURRENCY | 1 | Same scripted fallback while occupied |
| Maximum output tokens per provider call | AEGIS_LIVE_MAX_OUTPUT_TOKENS | 512 | Provider generation is capped; uncertain response is held safely |
| Live enabled | AEGIS_LIVE_ENABLED | 1 | 0 disables new live calls; scripted unavailable message |
| Access mode | AEGIS_LIVE_ACCESS_MODE | open | All simulated sessions are eligible, still limited; access-code restores code gating |

Browser scenario results show an escaped plain line, such as “Live demo limit reached. Showing the scripted demo instead.” JSON consumers retain structured results. Access-code unlock still requires an operator-issued code; open mode hides the unlock form. Limits do not bypass deterministic policy or enable external actions.

## Accounting and operation

Burst admission is a separate atomic SQLite transaction, shared across tasks for the same trusted visitor. One helper step is admitted before its model plan and includes all gateway checks, both judges and supplemental fake-only read assessments. Provider calls do not increment burst. Failed plans and `{done:true}` plans still consume the admitted attempt: the result is unknown until paid planning returns, so this is an action-attempt limit, not a count of executed tools. No-op advance requests on pending/done/busy tasks consume nothing. The seventh attempt in a rolling minute is refused before any provider call.

Mounted session startup uses a spending-only context limited to one `limits` judgment, not an action. An authenticated approve/recheck attempt consumes one NEW action attempt, including all recheck calls; denial consumes none. Repeated approval requests cannot reuse a context. Simple sandbox approval makes no provider calls and does not consume an additional attempt. These are intentionally distinct paths, not a claim that rechecks are free.

Server-issued contexts bind visitor and address, expire after 60 seconds, close at operation completion, and allow at most 16 provider reservations (startup: one). Missing, forged, closed, expired or mismatched contexts refuse provider dispatch. Contexts are not accepted from HTTP clients. `reserve_call` performs spending/concurrency checks only; the legacy internal `reserve` is a spending reservation primitive, not a public dispatch endpoint. All public paid paths admit an action or bounded startup context first. Restart closes outstanding contexts without erasing burst history or unknown spending charges.

Legacy MixedDemo evaluation consumes ONE action and reserves its two judges individually as two call rows plus 40,000 tokens before dispatch. Default burst therefore permits six evaluations, not three. Live helper/gateway paths reserve 20,000 tokens per actual provider call; helper, limits, guard and approval recheck calls all count toward the unchanged 30 visitor calls, 60 IP/day calls, 1500 global/day calls, 2M tokens/day and 10M tokens/month. Actual validated usage replaces each reservation. Unknown usage and unissued reserved calls remain conservatively charged. Concurrency remains atomic with the same default of one; cleanup failure retains slots and fails safely. A full original pipeline can exhaust spending before burst; separate visitors for recording still share IP/day and global caps, and do not justify raising any spending limit.

Original cap defaults cannot be raised through configuration; lower values are permitted. Burst supports 1–60, concurrency 1–32 and output 1–512. Use only `AEGIS_LIVE_BURST_ACTIONS`; retired `AEGIS_LIVE_BURST_CALLS` is ignored, with no compatibility alias. Limits load on process startup. The enabled switch is read before each new provider request, but cannot cancel a request already in flight. Changing a Fly environment value requires the platform to apply it to the running process; this code does not claim remote instantaneous control. Daily and monthly accounting use UTC.

Audit-event storage exhaustion prevents new paid evaluations and returns scripted results without adding an event. Transport/security/CSRF throttles remain separate protective HTTP refusals, not live spending caps.

## Owner checklist

- Put DEEPSEEK_API_KEY into Fly runtime secrets yourself, never into source or website files.
- Use a dedicated DeepSeek key only for this demo.
- Set a spending limit in the DeepSeek dashboard if your account provides that control.
- Enable dashboard usage alerts if available; otherwise check usage manually.
- Open mode is the default; set AEGIS_LIVE_ACCESS_MODE=access-code if you want code gating.
- Apply the limits you want and know how to turn live AI off.
- Rotate or revoke the demo key after the hackathon.

## Verified boundary and remaining work

Fake-key-only local HTTP tests cover provider success, exception text and malformed replies; responses, headers, captured logs, stdout/stderr and isolated data files are checked. Local tests do not certify Fly secrets, deployed images, external logging/crash systems or dashboard controls. Read-only pattern scans found no matching credential patterns in inspected repository/history and website text files; environment files, binary files and unreachable Git objects were not inspected. A previously tracked environment example remains tracked even though all environment files are now ignored; ignore rules do not remove historical tracked files. Docker uses a deny-all build-context allowlist excluding environment files. No deployment, publication, secret setting or real provider call was performed.
