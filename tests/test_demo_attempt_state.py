import asyncio
import json
import threading
from uuid import UUID

import pytest
from starlette.requests import Request
from aegis import app as web, demo_repeatability


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    async def access(request):
        return {'role': 'admin', 'csrf': 'test', 'username': 'operator'}
    monkeypatch.setattr(web, 'demo_access', access)
    monkeypatch.setattr(web, 'demo_result_path', lambda request:
                        tmp_path / (request.cookies['aegis_session'] + '.json'))
    monkeypatch.setattr(web.gateway, 'kill_switch_on', lambda: False)
    monkeypatch.setattr(web.db, 'get_setting', lambda *args: json.dumps({
        'version': 1, 'approved_records': [{'name': 'test'}]}))
    from aegis import tool_passport
    class Passport:
        def __init__(self, records):
            pass
        def check(self, record):
            return type('Check', (), {'status': 'allow'})()
    monkeypatch.setattr(tool_passport, 'ToolPassport', Passport)
    return tmp_path


def request(action='run', session='first'):
    return Request({'type': 'http', 'method': 'POST', 'scheme': 'http',
                    'path': '/admin/demo/' + action, 'query_string': b'',
                    'headers': [(b'cookie', ('aegis_session=' + session).encode())]})


@pytest.mark.parametrize('failure', [RuntimeError('child failed'), ValueError('bad result')])
def test_failed_attempt_removes_previous_success(isolated, monkeypatch, failure):
    path = isolated / 'first.json'
    path.write_text(json.dumps({'result': {'old_success': True}}))
    def launch(*args):
        raise failure
    monkeypatch.setattr(demo_repeatability, '_launch', launch)
    with pytest.raises(web.HTTPException) as exc:
        asyncio.run(web.demo_execute(request()))
    assert exc.value.status_code == 503
    assert not path.exists()
    with pytest.raises(web.HTTPException) as exc:
        asyncio.run(web.demo_proof_view(request(), 'old'))
    assert exc.value.status_code == 404


def test_envelope_identity_and_latest_proof_label(isolated, monkeypatch):
    monkeypatch.setattr(demo_repeatability, '_launch', lambda *args: ({
        'run_id': 'child-id', 'record_projection': [{'record_ref': 'r1'}]}, 0.1))
    asyncio.run(web.demo_execute(request()))
    saved = json.loads((isolated / 'first.json').read_text())
    UUID(saved['run_id'])
    assert saved['saved_at']
    assert 'run_id' not in saved['result']
    page = asyncio.run(web.demo_page(request())).body.decode()
    proof = asyncio.run(web.demo_proof_view(request(), 'r1')).body.decode()
    for text in (page, proof):
        assert saved['run_id'] in text
        assert saved['saved_at'] in text
        assert 'latest session result' in text
        assert 'not an immutable signed export' in text


def test_reset_run_serialized_but_other_session_independent(isolated, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    calls = []
    def launch(run, manifest):
        calls.append(run)
        if len(calls) == 1:
            entered.set()
            assert release.wait(3)
        return {'scenarios': []}, 0.1
    monkeypatch.setattr(demo_repeatability, '_launch', launch)
    async def exercise():
        first = asyncio.create_task(web.demo_execute(request('reset')))
        assert await asyncio.to_thread(entered.wait, 3)
        second = asyncio.create_task(web.demo_execute(request('run')))
        try:
            await asyncio.sleep(0.1)
            assert calls == [False]
            await asyncio.wait_for(web.demo_execute(request('run', 'other')), 2)
            assert calls == [False, True]
        finally:
            release.set()
            await asyncio.gather(first, second)
        assert calls == [False, True, True]
    asyncio.run(exercise())
