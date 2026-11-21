# Existing-screen browser check

## Ownership and rules

18 November 2026. Assigned ownership: `templates/base.html`, the actual shared source stylesheet `static/app.css`, `tests/test_r12_browser.py` (timing only), and this document. `base.html` loads `/static/app.css`; there is no reason to create or edit `static/styles.css`. Changed only `static/app.css`, the timing helper in the browser test, and this document. Base template remains unchanged. No other templates, core files, tests or contributors' changes were edited. Main owns commits; none made here.

Read the full Round 2 additions, Track 2 alignment, cyber-governance additions and cyber-governance plan. Applied accessibility-audit and better-accessibility. Did not open review-probes.

## Exact changes

- Primary button text now uses `--bg` instead of white against the existing blue accent. Secondary buttons explicitly retain light `--text` against their dark background. Danger buttons inherit the dark button text.
- Danger token changed from `#e74c3c` to `#ff7568`; redaction token from `#9b59b6` to `#c58ade`. This fixes error/status text contrast while preserving the existing palette and meaning.
- Shared layout uses `overflow-wrap: anywhere`, zero minimum widths for flex children and form controls, wrapping identity/step headers, and a zero minimum width on `.col`.
- At widths up to 600px, tables use fixed layout so cells wrap instead of enlarging the document. Main/header/card padding and cell padding are reduced. No content is hidden, no overflow is clipped, no table semantics are removed.
- Keyboard activation asserts the target remains focused and waits for link/form navigation with `expect_navigation(wait_until="load")` around Enter. Non-navigation summary activation remains keyboard-only. No verdict, role, contrast, reflow or Verify assertion was loosened.

## Measured evidence

Commands run from the repository root (`.`), using the installed headless Chromium and labelled stand-in gateway:

```sh
.venv/bin/python -m pytest tests/test_r12_browser.py -q --tb=short
.venv/bin/python -m pytest -q --tb=line --disable-warnings
.venv/bin/python -m pytest tests/test_r12_browser.py tests/test_suites.py tests/test_security_app.py tests/test_m1_auth.py tests/test_m4_policy.py tests/test_m5_roles_attribution.py tests/test_m6_compliance.py tests/test_approvals.py -q --tb=line
```

Before edits: **18 passed, 13 failed, 4 warnings in 29.98s**. Five 320px overflow failures: live, approvals, audit, policies, compliance. Eight contrast failures: login, live, audit, policies, redteam, admin, password change, error. Samples: primary buttons 3.22:1, danger button 3.82:1, redaction span 3.94:1, error div 4.36:1, each requiring 4.5:1. This confirms the existing red evidence without changing thresholds.

After shared CSS/navigation fix: **31 passed, 4 warnings in 29.96s** for the complete browser file. All nine 320px screens and all ten contrast screen samples pass, including redteam. Keyboard login for all four roles, hold/second-person approval, exactly one refund, audit Verify/detail, kill switch, five old demo stories, expiry and back-after-logout pass.

Final targeted browser plus regression run: **73 passed, 59 warnings in 35.49s**. Includes the existing real-pipeline attack/normal scoreboards; their full-stop, zero-leak, full-normal-completion and zero-false-hold assertions pass.

Full-suite integration remains **682 passed, 2 failed, 79 warnings, 9 subtests passed**. Repeated full-suite runs reproduced the same failures. Latest diagnostic run took 201.28s:

- `test_t3_office_actions.py::test_office_actions_have_validated_schemas`: `delete_file` missing from `gateway.SIDE_EFFECT`. Main-owned T3; not changed.
- `test_r12_browser.py::test_keyboard_task_hold_second_person_approval_and_audit`: Verify returns an actual **TAMPER DETECTED** banner, with fingerprint mismatches and missing checkpoints after earlier full-suite tests. Navigation reached the expected `?verify=1` URL. A temporary diagnostic asserted absence of the danger banner and exposed this result; it was removed afterwards. A temporary 30-second wait and two animation-frame waits did not resolve it and were removed. Thus the remaining failure cannot honestly be called only a slow-browser race or fixed with waits. Audit/test-state repair is outside this ownership. Verify OK remains required unchanged.

The terminal wrapper sometimes reports an unknown/null exit code; the explicit pytest summaries above are the evidence. Existing FastAPI/Starlette deprecation warnings remain outside scope.

## Safety and remaining coverage

Shared conftest creates a temporary database, random evidence key and separate signer, and removes the Qwen API key. The browser fixture starts only an owned loopback server with lifespan off, aborts and fails on nonlocal requests, disables access logs, and closes its socket/server/browser at teardown. Runtime credentials are not stored or printed. No external login, network side effect, upload, publication, screenshots, traces, video or delivered files. No dependency audit requiring network was run.

These are existing-screen checks, not complete R12 coverage of new owner/Demo/attack-board/rule-match/incident/proof-pack/alarm integrations. No screen-reader audit was performed. Solid-color computed text contrast does not cover opacity, gradients, pseudo-content or all states. Full R12 integration is still blocked by the full-suite audit state failure, not by the repaired contrast or 320px layout findings.
