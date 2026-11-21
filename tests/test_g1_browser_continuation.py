"""Local browser acceptance; marker visibility is not proof facts were read."""
import time

from playwright.sync_api import expect

from aegis import approvals, db, evidence
from test_approvals import held_refund
from test_r12_browser import local_server, page, login


def test_g1_visible_marker_records_once_and_decision_timing(page):
    reviewer, _ = login(page, 'approver')
    _, _, held = held_refund()
    aid = held['approval_id']
    path = '/approvals/' + aid
    page.goto(path)
    marker = page.locator('[data-review-view-url]').first
    marker.scroll_into_view_if_needed()
    expect(marker).to_be_visible()
    page.wait_for_function("url => performance.getEntriesByType('resource').some(e => e.name.endsWith(url))",
                           arg=path + '/view')
    deadline = time.monotonic() + 5
    while approvals.get(aid)['viewed_at'] is None and time.monotonic() < deadline:
        page.wait_for_timeout(20)
    viewed = approvals.get(aid)
    assert viewed['viewed_at'] is not None and viewed['viewed_by'] == reviewer
    page.reload()
    marker.scroll_into_view_if_needed()
    page.get_by_label('Short review reason (required for highest-risk approvals)').fill('Check customer invoice before proceeding')
    page.get_by_role('button', name='Request change', exact=True).click()
    expect(page.locator('.banner.ok')).to_contain_text('changed')
    stored = approvals.get(aid)
    assert stored['viewed_at'] == viewed['viewed_at']
    events = [evidence.dec_json(r['detail_json']) for r in db.conn().execute(
        "SELECT detail_json FROM audit WHERE event='approval_decided'")]
    event = next(e for e in events if e['approval'] == aid)
    assert event['viewed_at'] == viewed['viewed_at']
    assert stored['decided_at'] >= event['viewed_at']
    assert stored['reason'] == 'Check customer invoice before proceeding'
    page.goto(path)
    expect(page.get_by_role('button', name='Approve once')).to_have_count(0)


def test_g1_home_allow_once_routes_to_review_before_deciding(page):
    login(page, 'approver')
    _, _, held = held_refund()
    aid = held['approval_id']
    page.goto('/')
    card = page.locator('article').filter(has=page.locator('a[href="/approvals/' + aid + '"]'))
    expect(card).to_have_count(1)
    allow = card.get_by_role('button', name='Allow once', exact=True)
    if allow.count():
        allow.click()
    else:
        card.get_by_role('link', name='Review this work', exact=True).click()
    expect(page).to_have_url(page.url.split('/approvals/')[0] + '/approvals/' + aid)
    expect(page.get_by_label('Short review reason (required for highest-risk approvals)')).to_be_visible()
    assert approvals.get(aid)['status'] == 'pending'
