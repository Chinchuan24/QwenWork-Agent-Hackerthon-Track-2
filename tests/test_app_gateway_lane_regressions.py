import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from aegis import app as web, db, evidence, gateway
from conftest import make_session


def request():
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []})


@pytest.mark.parametrize('endpoint', ['live_run', 'live_agent_run', 'redteam_run', 'admin_bench'])
def test_password_gate_before_work(monkeypatch, endpoint):
    user = {'username': 'lane-admin', 'role': 'admin', 'must_change': 1}
    monkeypatch.setattr(web, 'need_login', lambda r: (user, None))
    monkeypatch.setattr(web, 'current_user', lambda r: user)
    monkeypatch.setattr(web, 'csrf_ok', lambda *a: True)
    monkeypatch.setattr(web, 'must_change_blocked', lambda *a: 'password-required')
    def expensive(*a, **k):
        pytest.fail('expensive work reached before password gate')
    monkeypatch.setattr(web, '_find_scenario', expensive)
    monkeypatch.setattr(web.config, 'live_mode', expensive)
    monkeypatch.setattr(web.redteam, 'comparison', expensive)
    from aegis import bench
    monkeypatch.setattr(bench, 'measure', expensive)
    kwargs = {'scenario': 'demo:x'} if endpoint.startswith('live_') else {}
    assert getattr(web, endpoint)(request(), csrf='ok', **kwargs) == 'password-required'


@pytest.mark.parametrize('api', [False, True])
def test_viewer_run_projection(monkeypatch, api):
    rid, session = make_session(task='private task sentinel')
    db.conn().execute("INSERT INTO actions(id,session_id,tool,args_json,args_hash,verdict,reasons_json,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      ('lane-' + rid, session['session_id'], 'read_file', evidence.enc_json({}),
                       'hash', 'block', evidence.enc_json([{'rule': 'private-rule', 'reason': 'private reason'}]), 'blocked', 0))
    db.conn().commit()
    gateway.WORLDS[rid] = SimpleNamespace(sent=[], leaks=lambda: [
        {'kind': 'protected-fact', 'sink': 'sent[0]', 'fact': 'private fact', 'to': 'private recipient'}])
    user = {'role': 'viewer'}
    monkeypatch.setattr(web, 'need_login', lambda r: (user, None))
    monkeypatch.setattr(web, 'current_user', lambda r: user)
    monkeypatch.setattr(web, 'render', lambda *a, **k: k)
    out = web.api_run(rid, request()) if api else web.run_view(request(), rid)
    result = out if api else out['results'][out['mode']]
    assert result['steps'][0]['reasons'] == [{'rule': 'WITHHELD', 'reason': 'clear text withheld for your role'}]
    assert result['leaks'] == [{'kind': 'protected-fact', 'sink': 'sent[0]'}]
    assert 'private' not in json.dumps(out)


@pytest.mark.parametrize('declared,body,expected', [
    ('public', 'Website copy\nPatient diagnosis: private', 'regulated'),
    ('public', 'Website copy\nNDA confidential', 'client-confidential'),
    ('regulated', 'Website copy approved for publication', 'regulated')])
def test_upload_effective_sensitivity(declared, body, expected):
    world = SimpleNamespace(doc=lambda p: {'body': body, 'sensitivity': declared},
                            ledger_entry=lambda p: None, contact_known=lambda p: False,
                            state={'outside_tools': {}})
    facts, checked = gateway._lumen_facts({'task_text': 'upload'}, 'upload_file',
                                {'doc_id': 'upload.md', 'target': 'example.test'}, world)
    assert facts['level'] == expected


@pytest.mark.parametrize('failure', ['false', 'exception'])
@pytest.mark.parametrize('frozen', [False, True])
def test_helper_checkpoint_failure_freezes(monkeypatch, failure, frozen):
    _, session = make_session(by='lane-owner')
    sid = session['session_id']
    before = db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0]
    original = gateway.audit.record_decision
    def record(*a, **k):
        receipt = original(*a, **k)
        if failure == 'exception':
            raise RuntimeError('checkpoint failed after durable event')
        return {**receipt, 'checkpoint_ok': False}
    monkeypatch.setattr(gateway.audit, 'record_decision', record)
    with pytest.raises(RuntimeError):
        gateway._persist_helper_freeze(sid, gateway._load_card(sid), frozen, 'lane-owner')
    assert gateway._load_card(sid)['frozen'] is True
    assert db.conn().execute('SELECT COUNT(*) FROM audit').fetchone()[0] > before


def test_helper_release_requires_creator():
    _, session = make_session(by='lane-owner')
    sid = session['session_id']
    gateway._persist_helper_freeze(sid, gateway._load_card(sid), True, 'lane-owner')
    with pytest.raises(PermissionError):
        gateway._persist_helper_freeze(sid, gateway._load_card(sid), False, 'other-admin')
    assert gateway._load_card(sid)['frozen'] is True
