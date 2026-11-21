"""Owned Chromium rehearsal, not sponsor/live acceptance; no browser artifacts."""
import json
from time import perf_counter
from urllib.parse import quote

import pytest
from playwright.sync_api import expect

from aegis.demo_repeatability import normalize
from test_r12_browser import activate, local_server, login, page  # noqa: F401

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")


def saved_json(page):
    return json.loads(page.locator("main pre").inner_text())


def reflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
        f"Horizontal overflow at {page.url} (320px)"
    )


def semantics(result):
    # Child canonicalizes proof/approval IDs while preserving their relationships.
    # Exclude clocks only; retain decisions, numeric facts and source evidence.
    return normalize({k: v for k, v in result.items()
                      if k != "backend_scenario_seconds"})


def test_ten_reset_clicks_then_five_complete_browser_workflows(page):
    login(page, "admin")
    page.set_default_timeout(60000)
    page.set_default_navigation_timeout(60000)
    page.set_viewport_size({"width": 320, "height": 640})
    page.goto("/admin/demo")
    reflow(page)
    resets = []
    for take in range(10):
        start = perf_counter()
        with page.expect_navigation(wait_until="load"):
            page.get_by_role("button", name="Reset demo", exact=True).click()
        reset = saved_json(page)["result"]
        elapsed = perf_counter() - start
        print(f"reset {take + 1}: {elapsed:.6f}s", flush=True)
        assert elapsed < 180
        assert reset["audit_ok"] is True
        resets.append(reset)
        assert reset == resets[0]
        reflow(page)

    results = []
    for take in range(5):
        start = perf_counter()
        activate(page, page.get_by_role("button", name="Run five stories", exact=True))
        saved = saved_json(page)
        assert saved["mode"] == "scripted stand-in"
        result = saved["result"]
        assert result["audit_ok"] is True
        assert result["sent"] == 0
        assert len(result["scenarios"]) == 5
        records = {r["record_ref"]: r for r in result["record_projection"]}
        assert len(records) == result["records"] > 0
        assert result["bindings"] and result["guards"]
        for binding in result["bindings"]:
            record = records[binding["record_ref"]]
            assert record["event"] == "decision"
            assert {k: record["detail"][k] for k in ("verdict", "reasons")} == binding["reply"]
        for guard in result["guards"]:
            record = records[guard["record_ref"]]
            assert record["event"] == "second_opinion"
            assert record["detail"] == {k: v for k, v in guard.items() if k != "record_ref"}
        assert result["disagreements"] == [g for g in result["guards"] if
            g["a"]["verdict"] == "safe" and g["b"]["verdict"] in ("unsafe", "unsure")]
        results.append(semantics(result))
        assert results[-1] == results[0], "Saved decisions/evidence changed across takes"
        for view, field in (("Source", "scenarios"), ("Guard", "guards"),
                            ("Briefing", "briefing"), ("Results", "scenarios")):
            activate(page, page.get_by_role("link", name=view, exact=True))
            expect(page.locator("main h1")).to_have_text("Isolated " + view)
            assert saved_json(page) == result[field]
            if view == 'Source':
                expected_refs = {ref for story in result['scenarios']
                                 for ref in story['decision_refs']}
                for ref in expected_refs:
                    assert page.locator(f"main a[href='/admin/demo/proof/{quote(ref, safe='')}']").count() == 1
            reflow(page)
            activate(page, page.get_by_role("link", name="Back to isolated demo", exact=True))
        links = page.locator("main a[href^='/admin/demo/proof/']")
        assert links.count() == len(records)
        for ref, record in records.items():
            link = page.get_by_role("link", name="Proof " + ref, exact=True)
            assert link.get_attribute("href") == "/admin/demo/proof/" + quote(ref, safe="")
            activate(page, link)
            expect(page.locator("main h1")).to_have_text("Isolated Proof")
            assert saved_json(page) == {"record": record, "bindings": [b for b in
                result["bindings"] if b["record_ref"] == ref]}
            reflow(page)
            activate(page, page.get_by_role("link", name="Back to isolated demo", exact=True))
        elapsed = perf_counter() - start
        print(f"complete workflow {take + 1}: {elapsed:.6f}s", flush=True)
        assert elapsed < 180, "Actual browser workflow exceeded 180 seconds"


def test_saved_briefing_exposes_keyboard_proof_navigation(page):
    login(page, "admin")
    page.set_default_navigation_timeout(60000)
    page.goto("/admin/demo")
    activate(page, page.get_by_role("button", name="Run five stories", exact=True))
    result = saved_json(page)["result"]
    refs = result["briefing"]["headline"]["proof_ids"]
    assert refs, "Actual child recorded no headline proof"
    page.set_viewport_size({"width": 320, "height": 640})
    activate(page, page.get_by_role("link", name="Briefing", exact=True))
    reflow(page)
    for ref in refs:
        link = page.locator(f"main a[href='/admin/demo/proof/{quote(ref, safe='')}']")
        assert link.count() == 1, f"Saved briefing proof {ref} has no navigable link"
        activate(page, link)
        assert saved_json(page)["record"]["record_ref"] == ref
        reflow(page)
        activate(page, page.get_by_role("link", name="Back to isolated demo", exact=True))
        activate(page, page.get_by_role("link", name="Briefing", exact=True))
