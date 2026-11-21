"""Real local workflows, provider transport fake only; no outside network."""
import json
import pytest
from fastapi.testclient import TestClient
from aegis import adaptive, app as views, audit, config, db, evidence, gateway, provider, qwen_client as client, redteam, suites

CANARY = 'fixture-canary-local-workflows-never-display'

@pytest.mark.usefixtures('reviewed14_sandbox_tools')
@pytest.mark.parametrize('failure', ['success', 'badkey', 'timeout', 'json', 'cap', 'echo'])
def test_actual_live_worker_redteam_adaptive_and_exports(monkeypatch, failure):
    monkeypatch.setattr(config, 'LOCAL_AI', True)
    monkeypatch.setattr(config, 'QWEN_API_KEY', CANARY)
    monkeypatch.setattr(config, 'MODEL_PROVIDER', 'deepseek')
    monkeypatch.setattr(config, 'QWEN_BASE_URL', 'https://api.deepseek.com')
    monkeypatch.setattr(config, 'LIVE_RETRIES', 0)
    monkeypatch.setattr(config, 'LOCAL_DAY_CALLS', 1 if failure == 'cap' else 60)
    monkeypatch.setattr(client, 'RATE_PER_MIN', 1000)
    client._cache.clear()
    client._calls_window.clear()
    db.set_setting('model_usage_unknown', 'false', 'fixture', 0)
    db.set_setting('local-model-pending', 'false', 'fixture', 0)
    db.conn().execute("DELETE FROM settings WHERE key LIKE 'local-model-day:%' OR key='model:rate:attempts'")
    db.conn().commit()
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return self.body
    def fake(request, timeout):
        calls.append(request.full_url)
        assert request.full_url == 'https://api.deepseek.com/chat/completions'
        if failure in ('badkey', 'timeout'):
            raise TimeoutError(CANARY)
        payload = json.loads(request.data)
        system = payload['messages'][0]['content']
        if 'variant generator' in system:
            content = json.dumps([{'instruction':'synthetic attack', 'payload_key':adaptive.PAYLOADS[0]['key'], 'tricks':['rewording'], 'targets':['judges']} for _ in range(20)])
            message = {'content': content}
        elif payload.get('tools'):
            if any(m.get('role') == 'tool' for m in payload['messages']):
                message = {'content':'Finished synthetic read.'}
            else:
                message = {'content':None, 'tool_calls':[{'id':'fixture-read', 'type':'function', 'function':{'name':'list_inbox', 'arguments':'{}'}}]}
        else:
            verdict = 'ok' if 'Derive least' in system else 'clean' if 'security classifier' in system else 'yes' if 'reasonable step' in system else 'safe'
            message = {'content':json.dumps({'verdict':verdict, 'reason':'synthetic only', 'limits':{'clients':['acme','boreal','cirrus'], 'tools':['list_inbox','read_email','read_file','search_files','send_email','issue_refund','get_client','find_contact','fetch_web'], 'external_send':True, 'refund':True}})}
        if failure == 'echo': message = {'content':CANARY}
        response = Response()
        response.body = b'bad json' if failure == 'json' else json.dumps({'choices':[{'message':message}], 'usage':{'prompt_tokens':1,'completion_tokens':1}}).encode()
        return response
    monkeypatch.setattr(provider, 'open_pinned', fake)
    # Restrict scenario count, not execution: run_live_suite still invokes real
    # worker.run, gateway HTTP, policies, signer, world and scoreboard machinery.
    scenario = {'id':'LOCAL-WORKFLOW', 'name':'Synthetic inbox read', 'threat':'synthetic', 'task':'Read Acme inbox', 'steps':[{'tool':'list_inbox','args':{}}]}
    monkeypatch.setattr(suites, 'ATTACKS', [scenario])
    monkeypatch.setattr(suites, 'NORMAL', [scenario])
    monkeypatch.setattr(suites, 'EVASION', [scenario])
    start = db.conn().execute('SELECT COALESCE(MAX(id),0) FROM audit').fetchone()[0]
    try:
        result = redteam.run_live_suite('smoke')
        assert result['waiting_for_key'] is False
        assert result['judge_mode'] == 'live'
        rows = result['main']['results']['attacks'] + result['main']['results']['normal']
        serialized = json.dumps(rows)
        if failure == 'success':
            assert 'list_inbox' in serialized and 'Finished synthetic read.' in serialized
            assert all(db.conn().execute('SELECT finished FROM runs WHERE id=?', (row['run_id'],)).fetchone()[0] for row in rows)
            variants = adaptive.generate_live()
            assert variants['waiting_for_key'] is False and len(variants['items']) == 20
            # Generated live instructions enter the existing scenario executor.
            variant = adaptive.generate(seed=42)[0]
            variant['variant_text'] = variants['items'][0]['instruction']
            run = redteam.run_scenario('enforce', variant)
            assert run['run_id'] and run['harm_stopped']
        else:
            assert 'error' in serialized or 'hold' in serialized
            with pytest.raises(client.JudgeUnavailable): adaptive.generate_live()
        assert calls
        if failure != 'success': assert len(calls) == 1
        records = [dict(row) for row in db.conn().execute('SELECT * FROM audit WHERE id>?', (start,))]
        assert records and CANARY not in json.dumps(records)
        assert audit.verify()['ok']
        with TestClient(views.app) as web:
            response = web.post('/login', data={'username':'audi','password':'demo-audi-2026'})
            assert response.status_code == 200
            for path in ('/audit', '/audit/export.json', '/audit/export.csv', '/live', '/redteam'):
                response = web.get(path)
                assert response.status_code == 200, path
                assert CANARY not in response.text
    finally:
        db.set_setting('model_usage_unknown', 'false', 'fixture-cleanup', 0)
        db.set_setting('local-model-pending', 'false', 'fixture-cleanup', 0)
        db.conn().execute("DELETE FROM settings WHERE key LIKE 'local-model-day:%' OR key='model:rate:attempts'")
        db.conn().commit()
        client._cache.clear()
        client._calls_window.clear()
