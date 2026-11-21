import importlib
import json
import pytest


def test_ten_resets_five_runs(reviewed14_sandbox_tools):
    demo = importlib.import_module('aegis.demo_repeatability')
    report = demo.measure(reviewed_manifest={
        'version': 1, 'approved_records': reviewed14_sandbox_tools})
    assert report['resets'] == 10 and report['runs'] == 5
    assert report['reset_identical'] and report['results_identical']
    assert len(report['backend_seconds']) == 5
    assert report['browser_shot_seconds'] is None
    first = report['results'][0]
    assert first['audit_ok'] and first['records'] > 0
    assert len(first['scenarios']) == 5 and first['sent'] == 0
    assert 'R15' in first['scenarios'][0]['rules']
    source = first['scenarios'][0]['evidence']
    assert source, 'Blocked client upload must retain actual source-line evidence'
    citations = [item for group in source for item in group.get('sources', [])]
    assert any(item['source'] == 'admin/client_list.csv' and item['line'] == 1
               and item['text'] == 'name,email,phone' for item in citations)
    assert 'R18' in first['scenarios'][3]['rules']
    for story in first['scenarios'][:4]:
        assert not story['sponsor_contract']['missing_sources'], story
    assert 'R09' in first['scenarios'][3]['rules']
    assert not first['scenarios'][3]['sponsor_contract']['missing_rules']
    assert first['guards']
    for story in first['scenarios']:
        contract = story['sponsor_contract']
        assert set(contract) == {'expected_decision', 'decision_match', 'missing_rules',
                                 'missing_sources', 'strictness_difference'}
        assert isinstance(contract['missing_sources'], list)
    s5 = first['scenarios'][-1]['sponsor_contract']
    assert s5['expected_decision'] == 'block'
    assert s5['decision_match']
    assert not s5['missing_rules']
    assert not s5['missing_sources']
    assert all(g['a']['mode'] == 'standin' for g in first['guards'])
    assert first['disagreements'] == [g for g in first['guards'] if
        g['a']['verdict'] == 'safe' and g['b']['verdict'] in ('unsafe', 'unsure')]
    assert '/' + 'Users' + '/' not in json.dumps(report)


def test_source_citations_follow_current_documents():
    from aegis import gateway, lumen_world
    world = lumen_world.fresh()
    path = 'admin/client_list.README.md'
    world.state['documents'][path]['body'] = 'Changed trusted classification note\nSecond current line'
    _, checked = gateway._lumen_facts({'task_text': 'Upload client list'}, 'upload_file', {
        'doc_id': 'admin/client_list.csv', 'target': 'audience.example'}, world)
    cited = [source for source in checked['sources'] if source['source'] == path]
    assert cited == [{'source': path, 'line': 1, 'text': 'Changed trusted classification note'},
                     {'source': path, 'line': 2, 'text': 'Second current line'}]
    del world.state['documents'][path]
    _, checked = gateway._lumen_facts({'task_text': 'Upload client list'}, 'upload_file', {
        'doc_id': 'admin/client_list.csv', 'target': 'audience.example'}, world)
    assert not any(source['source'] == path for source in checked['sources'])


@pytest.mark.parametrize('path', ['finance/cashflow_notes_nov2026.md',
                                 'finance/bank_details.md', 'admin/owner_records.md'])
def test_scope_read_evidence_is_current_not_fabricated(path):
    from aegis import gateway, lumen_world, policy
    world = lumen_world.fresh()
    session = {'task_text': 'Draft a reply to QuickPrint about the reprint.'}
    args = {'doc_id': path}
    facts, checked = gateway._lumen_facts(session, 'read_file', args, world)
    assert policy.evaluate_lumen('read_file', args, **facts)['rules'] == ['R01', 'R02']
    assert checked['sources'] == [{'source': path, 'line': 1,
                                  'text': world.state['documents'][path]['body']}]
    world.state['documents'][path]['body'] = 'Changed current source'
    _, checked = gateway._lumen_facts(session, 'read_file', args, world)
    assert checked['sources'] == [{'source': path, 'line': 1, 'text': 'Changed current source'}]
    del world.state['documents'][path]
    _, checked = gateway._lumen_facts(session, 'read_file', args, world)
    assert checked is None


@pytest.mark.parametrize('flag', ['--child-run', '--child-reset'])
def test_direct_child_flags_fail_before_config(tmp_path, flag):
    import os
    import subprocess
    import sys
    env = dict(os.environ, AEGIS_DATA_DIR=str(tmp_path / 'must-not-exist'))
    proc = subprocess.run([sys.executable, '-m', 'aegis.demo_repeatability', flag],
                          env=env, capture_output=True, timeout=20)
    assert proc.returncode != 0
    assert not (tmp_path / 'must-not-exist').exists()


def test_proof_bindings_are_inspectable(reviewed14_sandbox_tools):
    demo = importlib.import_module('aegis.demo_repeatability')
    result = demo._launch(True, reviewed_manifest={
        'version': 1, 'approved_records': reviewed14_sandbox_tools})[0]
    s5 = result['scenarios'][-1]['sponsor_contract']
    assert s5['expected_decision'] == 'block'
    assert s5['decision_match']
    assert not s5['missing_rules']
    assert not s5['missing_sources']
    records = {r['record_ref']: r for r in result['record_projection']}
    assert records and result['bindings']
    for story in result['scenarios']:
        refs = story.get('decision_refs', [])
        expected = [b['record_ref'] for b in result['bindings']
                    if b['story'] == story['scenario']]
        assert refs == expected and refs, 'Source story lacks its decision receipts'
        assert [records[ref]['detail']['verdict'] for ref in refs] == story['decisions']
        emitted = [reason['evidence'] for ref in refs
                   for reason in records[ref]['detail']['reasons']
                   if reason.get('evidence') is not None]
        assert emitted == story['evidence']
    for binding in result['bindings']:
        stored = records[binding['record_ref']]
        assert stored['event'] == 'decision'
        assert stored['detail']['verdict'] == binding['reply']['verdict']
        assert stored['detail']['reasons'] == binding['reply']['reasons']
    def check(value):
        if isinstance(value, dict):
            for ref in value.get('proof_ids', []):
                assert ref in records
            for proof in value.get('proof', []):
                assert proof['id'] in records
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(result['briefing'])
    assert result['briefing']['headline']['proof_ids']
    approvals = {r['detail']['approval'] for r in records.values()
                 if r['event'] == 'approval_requested'}
    assert set(result['briefing']['seen_approval_ids']) <= approvals
    for guard in result['guards']:
        stored = records[guard['record_ref']]
        assert stored['event'] == 'second_opinion'
        assert stored['detail'] == {k: v for k, v in guard.items() if k != 'record_ref'}
    assert len(result['disagreements']) == 2
    assert all(g['b']['verdict'] == 'unsure' for g in result['disagreements'])


@pytest.mark.parametrize('payload', [None, '/real/catalog.json', {},
                                   {'version': True, 'approved_records': []},
                                   {'version': 1, 'approved_records': [{'name': 'bad'}]}])
def test_child_rejects_missing_or_invalid_manifest(payload):
    demo = importlib.import_module('aegis.demo_repeatability')
    with pytest.raises(RuntimeError):
        demo._launch(False, reviewed_manifest=payload)


def test_user_path_refused(tmp_path):
    demo = importlib.import_module('aegis.demo_repeatability')
    marker = tmp_path / 'keep'
    marker.write_text('untouched')
    with pytest.raises(TypeError):
        demo.reset(tmp_path)
    assert marker.read_text() == 'untouched'


def test_normalization_keeps_semantics():
    normalize = importlib.import_module('aegis.demo_repeatability').normalize
    row = {'ts': 1, 'run_id': 'one', 'verdict': 'block', 'total': 5040,
           'evidence': 'SGD 5,040'}
    assert normalize(row) == normalize(dict(row, ts=2, run_id='two'))
    for changed in (dict(row, verdict='allow'), dict(row, total=5250),
                    dict(row, evidence='SGD 5,250')):
        assert normalize(row) != normalize(changed)
