from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from aegis import auth, incident_store
from aegis.breach_views import make_router


@pytest.fixture
def client(monkeypatch):
    from datetime import datetime
    from aegis import breach_views
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 21, tzinfo=tz)
    monkeypatch.setattr(breach_views, 'datetime', Clock)
    from aegis import breach_incident
    monkeypatch.setattr(breach_incident, 'datetime', Clock)
    import secrets
    username = 'g2-' + secrets.token_hex(8)
    auth.create_user(username, 'g2-private-password', 'admin')
    session = auth.login(username, 'g2-private-password')
    templates = Jinja2Templates(directory=Path(__file__).resolve().parents[1] / 'templates')
    def render(request, name, user, **ctx):
        return templates.TemplateResponse(request, name, dict(request=request, user=user,
            csrf=user['csrf'], live_mode=False, kill_switch=False, **ctx))
    app = FastAPI()
    app.include_router(make_router(render))
    with TestClient(app) as c:
        c.cookies.set('aegis_session', session['token'])
        c.csrf = session['csrf']
        yield c


def create(client, **extra):
    return client.post('/breach-clock', data=dict({'csrf': client.csrf, 'text': 'Review incident'}, **extra),
                       follow_redirects=False)


def test_human_clocks_persist_and_escape(client):
    result = create(client, count='500', data='<script>private</script>', harm='no',
                    awareness_at='2026-11-19T23:59', human_awareness='yes')
    assert result.status_code == 303
    url = result.headers['location']
    page = client.get(url)
    assert '2026-12-19' in page.text
    assert 'Waiting for a human trigger' in page.text
    assert '&lt;script&gt;private&lt;/script&gt;' in page.text
    assert '<script>private</script>' not in page.text
    result = client.post(url + '/steps', data=dict(csrf=client.csrf, text='Owner determined notifiable',
        determination_at='2026-11-20T00:01', human_determination='yes'), follow_redirects=False)
    assert result.status_code == 303
    page = client.get(url)
    assert '2026-11-23' in page.text
    assert 'Owner determined notifiable' in page.text
    user = auth.user_by_token(client.cookies.get('aegis_session'))
    saved = incident_store.get_incident(user, url.split('/')[-1])
    assert saved['facts']['count'] == 500 and saved['facts']['harm'] is False
    assert len(saved['steps']) == 1


def test_no_fact_inference_and_required_copy(client):
    url = create(client, count='500', harm='yes').headers['location']
    page = client.get(url).text
    assert page.count('Waiting for a human trigger') == 2
    for text in ('reminder, not legal advice', 'as soon as practicable',
                 'same time as or after the PDPC', 'Built by Qwen', 'Asia/Singapore'):
        assert text in page


@pytest.mark.parametrize('extra', [dict(awareness_at='2026-11-19T00:00'),
    dict(human_awareness='yes'), dict(count='-1'), dict(harm='maybe'),
    dict(determination_at='2026-11-18T00:00', human_determination='yes',
         awareness_at='2026-11-19T00:00', human_awareness='yes')])
def test_invalid_input_does_not_write(client, extra):
    user = auth.user_by_token(client.cookies.get('aegis_session'))
    before = len(incident_store.list_incidents(user))
    assert create(client, **extra).status_code == 422
    assert len(incident_store.list_incidents(user)) == before


@pytest.mark.parametrize('case', ['conflict_awareness', 'conflict_determination', 'future',
                                 'reversed', 'range', 'negative', 'step_range'])
def test_invalid_stored_dates_return_safe_422(client, monkeypatch, case):
    from datetime import datetime
    from aegis.breach_clock import SG
    epoch = lambda day: datetime(2026, 11, day, tzinfo=SG).timestamp()
    row = dict(id='stored', title='PRIVATE TITLE', actor_id=1, audit_id=1,
               timestamp=epoch(19), facts={}, awareness_at=epoch(19), human_awareness=True,
               determination_at=epoch(20), human_determination=True, steps=[])
    if case.startswith('conflict'):
        step = dict(row, step='PRIVATE STEP')
        step.pop('steps')
        step['awareness_at' if case == 'conflict_awareness' else 'determination_at'] = epoch(18)
        row['steps'] = [step]
    elif case == 'future':
        row['determination_at'] = epoch(22)
    elif case == 'reversed':
        row['determination_at'] = epoch(18)
    elif case == 'range':
        row['awareness_at'] = 10**30
    elif case == 'negative':
        row['awareness_at'] = -1
    else:
        row['timestamp'] = 10**30
    monkeypatch.setattr(incident_store, 'get_incident', lambda *args: row)
    response = client.get('/breach-clock/stored')
    assert response.status_code == 422
    assert response.json() == {'detail': 'Invalid incident facts or dates'}
    assert 'PRIVATE' not in response.text


@pytest.mark.parametrize('awareness, determination, outcome, deadline', [
    ('2026-11-19T00:00', '2026-11-20T00:00', 'on time', '2026-12-19'),
    ('2026-10-01T00:00', '2026-11-20T00:00', 'late', '2026-10-31')])
def test_completed_assessment_preserves_deadline(client, awareness, determination, outcome, deadline):
    url = create(client, awareness_at=awareness, human_awareness='yes',
                 determination_at=determination, human_determination='yes').headers['location']
    page = client.get(url).text
    assessment = page.split('Assessment: 30 calendar days')[1].split('</section>')[0]
    assert 'Assessment completed' in assessment
    assert outcome in assessment and deadline in assessment
    assert 'Status: overdue' not in assessment
    assert 'Calendar days remaining' not in assessment


def test_competing_trigger_append_uses_one_continuous_lock(client, monkeypatch):
    import asyncio
    import copy
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime
    from starlette.requests import Request
    from starlette.datastructures import FormData
    from aegis import audit
    from aegis.breach_clock import SG

    user = auth.user_by_token(client.cookies.get('aegis_session'))
    epoch = lambda day: datetime(2026, 11, day, tzinfo=SG).timestamp()
    stored = dict(id='race', title='Race', actor_id=user['id'], audit_id=1,
        timestamp=epoch(18), facts={}, awareness_at=epoch(18), human_awareness=True,
        determination_at=None, human_determination=False, steps=[])
    entered = threading.Event()
    contender = threading.Event()
    reads = []
    ownership = []

    def read(*args):
        reads.append(threading.get_ident())
        ownership.append(audit._LOCK._is_owned())
        return copy.deepcopy(stored)

    def append(user, incident_id, **values):
        ownership.append(audit._LOCK._is_owned())
        if not entered.is_set():
            entered.set()
            assert contender.wait(2)
        stored['steps'].append(dict(values, actor_id=user['id'], audit_id=2))
        return {'id': len(stored['steps']), 'audit_id': 2}

    monkeypatch.setattr(incident_store, 'get_incident', read)
    monkeypatch.setattr(incident_store, 'add_step', append)
    endpoint = next(route.endpoint for route in make_router(lambda *args: None).routes
                    if route.path == '/breach-clock/{incident_id}/steps')
    token = client.cookies.get('aegis_session')
    def submit(day):
        request = Request({'type': 'http', 'method': 'POST', 'path': '/breach-clock/race/steps',
                           'headers': [(b'cookie', ('aegis_session=' + token).encode())]})
        async def form():
            assert not audit._LOCK._is_owned()
            return FormData(dict(csrf=client.csrf, text='Human step',
                determination_at=f'2026-11-{day}T00:00', human_determination='yes'))
        request.form = form
        try:
            return asyncio.run(endpoint(request, 'race')).status_code
        except Exception as error:
            from fastapi import HTTPException
            if isinstance(error, HTTPException):
                return error.status_code
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(submit, 19)
        assert entered.wait(2)
        def second():
            contender.set()
            return submit(20)
        other = pool.submit(second)
        results = [first.result(timeout=5), other.result(timeout=5)]
    assert results == [303, 422]
    assert len(stored['steps']) == 1
    assert len(set(reads)) == 2
    assert all(ownership), 'History read and committed append must share audit._LOCK'


def test_completion_screen(client):
    url = create(client, awareness_at='2026-10-31T23:59', human_awareness='yes').headers['location']
    values = dict(csrf=client.csrf, outcome='not_notifiable', reason='Owner reviewed facts',
                  completed_at='2026-11-01T00:00', human_completion='yes')
    assert client.post(url + '/steps', data=dict(values, reason=' ')).status_code == 422
    assert client.post(url + '/steps', data=values, follow_redirects=False).status_code == 303
    page = client.get(url).text
    assert 'Assessment completed' in page and '2026-11-30' in page
    assert 'Notification not required' in page and 'Owner reviewed facts' in page


def test_completion_has_separate_form_after_notification_started(client):
    url = create(client, awareness_at='2026-10-30T00:00', human_awareness='yes',
                 determination_at='2026-10-31T23:59', human_determination='yes').headers['location']
    page = client.get(url).text
    forms = [part.split('</form>')[0] for part in page.split('<form ')[1:]]
    form = next((part for part in forms if 'name="reason"' in part), '')
    assert form
    assert 'name="text"' not in form
    assert 'name="reason" required' in form
    result = client.post(url + '/steps', data=dict(csrf=client.csrf, outcome='not_notifiable',
        reason='Later human decision', completed_at='2026-11-01T00:00', human_completion='yes'),
        follow_redirects=False)
    assert result.status_code == 303
    page = client.get(url).text
    assert 'Notification not required' in page and '2026-11-03' in page


@pytest.mark.parametrize('supplied, expected', [(True, ''), (False, 'Saved categories')])
def test_data_clear_or_absent_preserves_update_semantics(client, supplied, expected):
    from aegis.breach_prefill import pdpc_fact_prefill
    url = create(client, data='Saved categories', count='12', harm='yes').headers['location']
    values = dict(csrf=client.csrf, text='Human fact update', count='', harm='')
    if supplied:
        values['data'] = ''
    assert client.post(url + '/steps', data=values, follow_redirects=False).status_code == 303
    user = auth.user_by_token(client.cookies.get('aegis_session'))
    stored = incident_store.get_incident(user, url.split('/')[-1])
    assert ('data' in stored['steps'][-1]['facts']) is supplied
    assert pdpc_fact_prefill(stored) == dict(count=12, harm=True, data=expected)
    page = client.get(url).text
    textarea = page.split('<textarea id="data"')[1].split('</textarea>')[0].split('>', 1)[1]
    assert textarea == expected
    assert 'blank: no update to previous saved value' in page
    assert 'Unknown: no update to previous saved value' in page


def test_empty_agent_header_refused(client):
    url = create(client).headers['location']
    for path in ('/breach-clock', url):
        assert client.get(path, headers={'X-Agent-Token': ''}).status_code == 403
    for path in ('/breach-clock', url + '/steps'):
        assert client.post(path, headers={'X-Agent-Token': ''},
            data={'csrf': client.csrf, 'text': 'refused'}).status_code == 403


def test_security_boundary(client):
    assert create(client, csrf='bad').status_code == 403
    assert client.get('/breach-clock/missing').status_code == 404
    client.cookies.clear()
    assert create(client).status_code == 401
    assert client.get('/breach-clock', headers={'X-Agent-Token': 'helper'}).status_code == 403
