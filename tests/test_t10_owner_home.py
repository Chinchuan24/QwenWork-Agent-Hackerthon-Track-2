"""Template fixture checks only, not owner-route authentication verification."""
from copy import deepcopy
from uuid import uuid4

import pytest
from starlette.requests import Request
from aegis.app import render


@pytest.fixture
def context():
    return dict(briefing={
        'mode': 'template', 'live_status': 'waiting for key',
        'headline': {'text': 'One thing needs you.', 'proof_ids': [17]},
        'sections': {
            'needs_decision': [{'text': 'Keep the unpaid invoice.', 'proof_ids': [23]}],
            'stopped_for_you': [{'text': 'The client list stayed here.', 'proof_ids': [31]}],
            'you_should_know': [], 'went_fine': [], 'still_waiting': []}},
        approvals=[dict(id='fixture-approval', explanation='Delete an unpaid invoice.',
                        recommendation='Keep the invoice.', decision='APPROVE',
                        status='pending', expired=False, created_by='worker', proof_ids=[17, 23])])


def page(context, role='approver', username='owner', must_change=False):
    user = dict(username=username, role=role, must_change=must_change, csrf=uuid4().hex)
    request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'headers': []})
    html = render(request, 'owner_home.html', user, **context).body.decode()
    return html.split('<main', 1)[1].split('>', 1)[1].split('</main>', 1)[0], html, user


def test_fixture_content_proof_and_csrf(context):
    original = deepcopy(context)
    main, html, user = page(context)
    for text in ['What your AI did today', 'One thing needs you.', 'Keep the invoice.',
                 'Needs your decision', 'Stopped for you', 'Details and proof', 'Security room']:
        assert text in main
    for rid in [17, 23, 31]:
        assert f'href="/audit/record/{rid}"' in main
    assert 'href="/approvals/fixture-approval"' in main
    assert '<form' not in main
    assert '/static/app.css' in html
    assert '<script' not in main and '<style' not in main
    assert original == context


@pytest.mark.parametrize('decision', ['NEVER', 'never', 'BLOCK', 'unknown', 'ALLOW'])
def test_never_and_unknown_cannot_be_released(context, decision):
    context['approvals'][0]['decision'] = decision
    main, _, _ = page(context)
    assert '<form' not in main
    if decision.upper() in ('NEVER', 'BLOCK'):
        assert 'Stopped' in main


@pytest.mark.parametrize('kwargs', [dict(role='auditor'), dict(role='viewer'),
    dict(username='worker'), dict(must_change=True)])
def test_display_guards_not_backend_auth_verification(context, kwargs):
    main, _, _ = page(context, **kwargs)
    assert '<form' not in main


@pytest.mark.parametrize('change', [dict(expired=True), dict(status='denied'),
    dict(proof_ids=[]), dict(created_by=None)])
def test_incomplete_or_closed_item_has_no_controls(context, change):
    context['approvals'][0].update(change)
    main, _, _ = page(context)
    assert '<form' not in main


def test_empty_is_not_success(context):
    context.update(briefing=None, approvals=[])
    main, _, _ = page(context)
    assert "Today's note is not ready." in main
    assert 'Nothing is waiting for your decision.' in main
    assert '<form' not in main and '/audit/record/' not in main


def test_escape_and_only_numeric_supplied_proof_ids(context):
    attack = '<script>alert("fixture")</script>'
    context['briefing']['headline'].update(text=attack, proof_ids=[True, -1, 'javascript:bad', 17],
        proof=[{'audit_url': 'https://outside.example'}])
    context['approvals'][0].update(explanation=attack, recommendation=attack,
                                  private_data='private fixture sentinel')
    main, _, _ = page(context)
    assert '<script>' not in main and '&lt;script&gt;' in main
    for text in ['javascript:', 'https://outside.example', 'private fixture sentinel',
                 '/audit/record/True', '/audit/record/-1']:
        assert text not in main


def test_plain_fixture_words(context):
    import re
    main, _, _ = page(context)
    text = re.sub('<[^>]+>', ' ', main).lower()
    for word in ['idempotency', 'exfiltration', 'verdict', 'regulated', 'compliant',
                 'certified', 'approved by', 'guarantees']:
        assert word not in text


def test_actual_briefing_builder_contract(context):
    from aegis.briefing import build_briefing
    context['briefing'] = build_briefing([
        dict(id=41, ts=10, event='decision',
             detail_json='{"mode":"enforce","verdict":"block"}')],
        start=0, end=20, checker=lambda *_: {'safe': True})
    main, _, _ = page(context)
    assert context['briefing']['headline']['text'] in main
    assert context['briefing']['sections']['stopped_for_you'][0]['text'] in main
    assert 'href="/audit/record/41"' in main
    assert 'Written from a template.' in main


@pytest.mark.parametrize('mode', [None, '', 'unknown'])
def test_unknown_briefing_origin_is_not_ai_success(context, mode):
    context['briefing']['mode'] = mode
    main, _, _ = page(context)
    assert 'Writing source is not known.' in main
    assert 'Written with AI help.' not in main


def test_raw_queue_contract_is_readable_and_non_actionable(context):
    # Queue fields before the owner-view adapter exists.
    context['approvals'] = [dict(id='raw-row', action_id='action', status='pending',
        expired=False, created_by='worker', tool='delete_file',
        args_json='private args sentinel', reasons_json='private reasons sentinel',
        task_text='private task sentinel', run_id='run')]
    main, _, _ = page(context)
    assert 'Details are not ready. Open the decision page to review this work.' in main
    assert 'No recommendation is available yet.' in main
    assert 'href="/approvals/raw-row"' in main
    assert '<form' not in main
    assert 'private' not in main


def test_decision_controls_have_context(context):
    main, _, _ = page(context)
    assert 'aria-describedby="decision-note-1"' in main
    assert 'id="decision-note-1"' in main
    assert 'href="/approvals/fixture-approval"' in main


def test_missing_sections_is_not_a_render_error(context):
    context['briefing'].pop('sections')
    main, _, _ = page(context)
    assert 'One thing needs you.' in main
