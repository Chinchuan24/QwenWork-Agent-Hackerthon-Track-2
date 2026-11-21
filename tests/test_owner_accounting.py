"""Owner-scoped spend checks through the actual gateway boundary."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from aegis import db, gateway
from conftest import make_session
from test_new_attacks_identity import persist, call


@pytest.fixture
def owner_run(reviewed_sandbox_tools):
    import uuid
    owner = 'owner-' + uuid.uuid4().hex
    rid, first = make_session('Order fixture supplies.', mode='off', by=owner)
    yield rid, first, gateway.get_world(rid)
    gateway.WORLDS.pop(rid, None)
    gateway._RUN_IDENTITIES.pop(rid, None)


def funded(helper, owner='owner'):
    if owner == 'owner':
        owner = db.conn().execute('SELECT created_by FROM agent_sessions WHERE id=?',
                                  (helper['session_id'],)).fetchone()[0]
    persist(helper, budget_owner=owner,
            money_limits=dict(currency='SGD', per_action='20', per_day='30'))


@pytest.mark.parametrize('other_owner,expected', [('owner', 'block'), ('other', 'allow')])
def test_owner_separation(owner_run, other_owner, expected):
    rid, first, w = owner_run
    if other_owner == 'owner':
        other_owner = db.conn().execute('SELECT created_by FROM agent_sessions WHERE id=?',
                                        (first['session_id'],)).fetchone()[0]
    second = gateway.start_session(rid, 'Order fixture supplies.', other_owner)
    funded(first)
    funded(second, other_owner)
    assert call(first, 'order_supplier', supplier='fixture', amount=20)['verdict'] == 'allow'
    assert call(second, 'order_supplier', supplier='different', amount=20)['verdict'] == expected
    assert len(w.state['orders']) == (1 if expected == 'block' else 2)


def test_owner_race(owner_run):
    rid, first, w = owner_run
    owner = db.conn().execute('SELECT created_by FROM agent_sessions WHERE id=?',
                              (first['session_id'],)).fetchone()[0]
    helpers = [first] + [gateway.start_session(rid, 'Order fixture supplies.', owner) for _ in range(7)]
    for helper in helpers:
        funded(helper)
    barrier = Barrier(8)

    def worker(helper):
        try:
            barrier.wait(timeout=15)
            return call(helper, 'order_supplier', supplier='fixture', amount=20)['verdict']
        finally:
            db.conn().close()
            del db._local.conn

    with ThreadPoolExecutor(max_workers=8) as pool:
        verdicts = list(pool.map(worker, helpers))
    assert verdicts.count('allow') == 1
    assert verdicts.count('block') == 7
    assert sum(order['amount'] for order in w.state['orders']) == 20


@pytest.mark.parametrize('owner', ['unknown', '', None])
def test_unknown_budget_owner_fails_closed(owner_run, owner):
    _, helper, w = owner_run
    funded(helper, owner)
    assert call(helper, 'order_supplier', supplier='fixture', amount=20)['verdict'] == 'block'
    assert not w.state.get('orders')


def test_per_action_limit(owner_run):
    _, helper, w = owner_run
    funded(helper)
    assert call(helper, 'order_supplier', supplier='fixture', amount=21)['verdict'] == 'block'
    assert not w.state.get('orders')


def test_owner_budget_spans_runs(owner_run):
    _, first, _ = owner_run
    funded(first)
    assert call(first, 'order_supplier', supplier='fixture', amount=20)['verdict'] == 'allow'
    owner = db.conn().execute('SELECT created_by FROM agent_sessions WHERE id=?',
                              (first['session_id'],)).fetchone()[0]
    _, second = make_session('Order fixture supplies.', mode='off', by=owner)
    funded(second)
    assert call(second, 'order_supplier', supplier='fixture', amount=20)['verdict'] == 'block'
