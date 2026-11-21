"""Real local Chromium checks. Browser absence fails; no traces or screenshots."""
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit

import pytest
import uvicorn
from playwright.sync_api import expect, sync_playwright

from aegis import auth, db, gateway, suites
from aegis.app import app


@pytest.fixture(scope="module")
def local_server(_setup):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", access_log=False,
                                         log_level="critical"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.02)
        assert server.started, "Owned loopback server failed to start"
        print(f"R12 local browser URL: http://127.0.0.1:{port}")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "Owned loopback server failed to stop"


@pytest.fixture
def page(local_server, reviewed14_sandbox_tools):
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(base_url=local_server)
        external = []

        def guard(route):
            u = urlsplit(route.request.url)
            if f"{u.scheme}://{u.netloc}" != local_server:
                external.append(f"{u.scheme}://{u.netloc}{u.path}")
                route.abort()
            else:
                route.continue_()

        context.route("**/*", guard)
        p = context.new_page()
        errors = []
        p.on("pageerror", lambda error: errors.append(type(error).__name__))
        try:
            yield p
        finally:
            context.close()
            browser.close()
            assert not external, "Browser attempted nonlocal traffic"
            assert not errors, "Browser JavaScript error"


def tab_to(page, target):
    # Choose the shorter natural keyboard path without setting focus in JS.
    direction = target.evaluate("""el => {
        const controls = [...document.querySelectorAll(
            'a[href],button,input,select,textarea,[tabindex]')].filter(node =>
            !node.disabled && node.tabIndex >= 0 && node.getClientRects().length);
        const target = controls.indexOf(el);
        const current = controls.indexOf(document.activeElement);
        if (target < 0) return 'Tab';
        if (current < 0) return target > controls.length / 2 ? 'Shift+Tab' : 'Tab';
        const forward = (target - current + controls.length) % controls.length;
        const backward = (current - target + controls.length) % controls.length;
        return backward < forward ? 'Shift+Tab' : 'Tab';
    }""")
    for _ in range(150):
        page.keyboard.press(direction)
        if target.evaluate("el => el === document.activeElement"):
            visible = target.evaluate("""el => {
                const s=getComputedStyle(el);
                return (s.outlineStyle!=='none' && parseFloat(s.outlineWidth)>0)
                    || s.boxShadow!=='none';
            }""")
            assert visible, "No visible keyboard focus indicator"
            return
    pytest.fail("Control not reachable in natural tab order")


def activate(page, target):
    tab_to(page, target)
    expect(target).to_be_focused()
    # Submission/link navigation must finish before tabbing on the next page.
    navigates = target.evaluate("el => el.matches('a[href], button[type=submit], button:not([type])')")
    if navigates:
        with page.expect_navigation(wait_until="load"):
            page.keyboard.press("Enter")
    else:
        page.keyboard.press("Enter")


def choose(page, target, value):
    tab_to(page, target)
    values = target.locator("option").evaluate_all("els => els.map(el => el.value)")
    assert value in values
    label = target.locator("option").nth(values.index(value)).inner_text()
    page.keyboard.type(label, delay=30)
    page.keyboard.press("Tab")
    expect(target).to_have_value(value)


def login(page, role):
    import re

    username = "r12_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(24)
    auth.create_user(username, password, role)
    page.goto("/login")
    tab_to(page, page.get_by_label("Username", exact=True))
    page.keyboard.insert_text(username)
    page.keyboard.press("Tab")
    expect(page.get_by_label("Password", exact=True)).to_be_focused()
    page.keyboard.insert_text(password)
    page.keyboard.press("Tab")
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_focused()
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"/$"))
    expect(page.locator("main h1")).to_have_text("What your AI did today")
    page.goto("/live")
    expect(page.locator("main h1")).to_have_text("Live")
    expect(page.locator(".who")).to_contain_text(f"({role})")
    return username, password


@pytest.mark.parametrize("role", ["admin", "approver", "auditor", "viewer"])
def test_role_login_and_admin_boundary(page, role):
    login(page, role)
    response = page.goto("/admin")
    assert response.status == (200 if role == "admin" else 403)
    expect(page.locator("main h1")).to_be_visible()


def test_keyboard_task_hold_second_person_approval_and_audit(page):
    owner, _ = login(page, "admin")
    choose(page, page.locator("select[name='scenario']"), "normal:N22")
    choose(page, page.locator("select[name='mode']"), "enforce")
    activate(page, page.get_by_role("button", name="Run", exact=True))
    expect(page.locator(".verdict.hold")).to_have_count(1)
    activate(page, page.locator(".step.v-hold summary"))
    link = page.locator(".step.v-hold a[href^='/approvals/']")
    path = link.get_attribute("href")
    activate(page, link)
    expect(page.get_by_role("button", name="Approve once")).to_have_count(0)
    expect(page.locator("main")).to_contain_text("You set this task")
    activate(page, page.get_by_role("button", name="log out"))
    login(page, "approver")
    page.goto(path)
    page.get_by_label('Short review reason (required for highest-risk approvals)').fill('Checked invoice and requested refund.')
    activate(page, page.get_by_role("button", name="Approve once", exact=True))
    expect(page.locator(".banner.ok")).to_contain_text("executed")
    run = db.conn().execute("SELECT id FROM runs WHERE created_by=? ORDER BY created_at DESC", (owner,)).fetchone()
    assert len(gateway.get_world(run["id"]).refunds) == 1
    page.goto(path)
    expect(page.get_by_role("button", name="Approve once")).to_have_count(0)
    activate(page, page.get_by_role("link", name="Audit", exact=True))
    activate(page, page.get_by_role("button", name="Verify", exact=True))
    expect(page.locator(".banner.ok")).to_contain_text("Verify OK")
    activate(page, page.get_by_role("link", name="detail", exact=True).first)
    expect(page.locator("main h1")).to_be_visible()


def test_keyboard_kill_switch_reauthentication(page):
    _, password = login(page, "admin")
    page.goto("/admin")
    form = page.locator("form[action='/admin/kill']")
    field = form.get_by_label("Re-authenticate (password)")
    tab_to(page, field)
    page.keyboard.insert_text(secrets.token_urlsafe(24))
    activate(page, form.get_by_role("button", name="Turn ON", exact=True))
    expect(page.locator("main")).to_contain_text("Re-authentication failed")
    assert db.get_setting("kill_switch") == "off"
    tab_to(page, field)
    page.keyboard.press("Home")
    page.keyboard.press("Shift+End")
    page.keyboard.insert_text(password)
    activate(page, form.get_by_role("button", name="Turn ON", exact=True))
    expect(page.locator(".banner.danger")).to_contain_text("KILL SWITCH ACTIVE")
    assert db.get_setting("kill_switch") == "on"
    tab_to(page, field)
    page.keyboard.insert_text(password)
    activate(page, form.get_by_role("button", name="Turn off", exact=True))
    expect(page.locator(".banner.danger")).to_have_count(0)
    assert db.get_setting("kill_switch") == "off"


@pytest.mark.parametrize("scenario", [s["id"] for s in suites.DEMO_SCENARIOS])
def test_existing_demo_scenario(page, scenario):
    login(page, "admin")
    choose(page, page.locator("select[name='scenario']"), "demo:" + scenario)
    choose(page, page.locator("select[name='mode']"), "enforce")
    activate(page, page.get_by_role("button", name="Run", exact=True))
    expect(page.locator("main h1")).to_contain_text(scenario)
    expect(page.locator(".banner.ok")).to_contain_text("0 leaks")
    expect(page.locator(".step").first).to_be_visible()


def test_session_expiry_and_back_after_logout(page):
    username, _ = login(page, "viewer")
    db.conn().execute("UPDATE web_sessions SET expires_at=0 WHERE user_id=(SELECT id FROM users WHERE username=?)", (username,))
    db.conn().commit()
    activate(page, page.get_by_role("link", name="Audit", exact=True))
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    login(page, "viewer")
    activate(page, page.get_by_role("button", name="log out"))
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    page.go_back()
    # Check history restoration itself, not only a reload that masks stale content.
    expect(page.locator(".who")).to_have_count(0)
    page.goto("/audit")
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()


SCREENS = ["/live", "/approvals", "/audit", "/policies", "/redteam",
           "/compliance", "/admin", "/change-password", "/error"]


@pytest.mark.parametrize("path", SCREENS)
def test_existing_screen_small_window_reflow(page, path):
    login(page, "admin")
    page.set_viewport_size({"width": 320, "height": 640})
    response = page.goto(path)
    assert response.status == 200
    expect(page.locator("main h1")).to_have_count(1)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Horizontal overflow at {path} (320px)"


@pytest.mark.parametrize("path", ["/login"] + SCREENS)
def test_rendered_text_contrast(page, path):
    login(page, "admin")
    page.goto(path)
    failures = page.evaluate(r"""() => {
      const rgb = s => (s.match(/[\d.]+/g)||[]).map(Number);
      const lum = c => c.slice(0,3).map(v => {v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4})
        .reduce((a,v,i)=>a+v*[.2126,.7152,.0722][i],0);
      const bad=[];
      for(const el of document.querySelectorAll('body *')) {
        if(el.closest('[aria-hidden="true"]') || !el.getClientRects().length) continue;
        if(![...el.childNodes].some(n=>n.nodeType===3 && n.textContent.trim())) continue;
        const s=getComputedStyle(el); if(s.visibility==='hidden') continue;
        let bg, p=el;
        while(p) {bg=rgb(getComputedStyle(p).backgroundColor);if(bg.length===3 || bg[3]===1)break;p=p.parentElement;}
        if(!p) {bad.push({tag:el.tagName,problem:'unknown background'});continue;}
        const fg=rgb(s.color), a=lum(fg), b=lum(bg), ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
        const size=parseFloat(s.fontSize), large=size>=24 || (size>=18.66 && parseInt(s.fontWeight)>=700);
        if(ratio<(large?3:4.5))bad.push({tag:el.tagName,ratio:Math.round(ratio*100)/100,required:large?3:4.5});
      }
      return bad;
    }""")
    assert not failures, f"WCAG text contrast failures at {path}: {failures}"
