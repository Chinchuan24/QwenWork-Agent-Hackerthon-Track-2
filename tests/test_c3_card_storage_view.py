"""Stored C3 cards are displayed only after human authorization."""
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")
from fastapi.testclient import TestClient

from aegis import app as web, card_view, db, evidence
from conftest import make_session


@pytest.fixture
def stored():
    _, session = make_session(task='Read the actual stored task <script>private()</script>')
    helper_id = session['session_id']
    connection = db.conn()
    original = connection.execute(
        'SELECT version, content FROM helper_cards WHERE helper_id=?',
        (helper_id,)).fetchone()
    try:
        yield helper_id
    finally:
        # Fault-injected cards must not poison subsequent module startup.
        connection.execute(
            'UPDATE helper_cards SET version=?, content=? WHERE helper_id=?',
            (original['version'], original['content'], helper_id))
        connection.commit()


@pytest.mark.parametrize('role', ['admin', 'approver', 'auditor'])
def test_actual_storage_route(monkeypatch, stored, role):
    monkeypatch.setattr(web, 'current_user', lambda request: {'role': role, 'username': 'reader', 'csrf': ''})
    response = TestClient(web.app).get('/helper-cards')
    assert response.status_code == 200
    assert stored in response.text
    assert 'Version 1' in response.text
    assert 'read_file' in response.text
    assert 'confidential' in response.text
    assert 'All paths (stored empty prefix)' in response.text
    assert 'Not recorded' in response.text
    assert '&lt;script&gt;private()&lt;/script&gt;' in response.text
    assert '<script>private()' not in response.text
    assert 'Not frozen.' not in response.text


@pytest.mark.parametrize('role', [None, 'viewer'])
def test_authorization_precedes_decode(monkeypatch, role):
    monkeypatch.setattr(web, 'current_user', lambda request: None if role is None else {'role': role, 'username': 'reader', 'csrf': ''})
    monkeypatch.setattr(evidence, 'dec_json', lambda value: pytest.fail('unauthorized decode'))
    response = TestClient(web.app).get('/helper-cards', follow_redirects=False)
    assert response.status_code == (303 if role is None else 403)
    with pytest.raises(PermissionError):
        card_view.load_stored_cards(role=role)


def test_fresh_version_and_explicit_metadata(stored):
    content = {'tools': ['read_file'], 'read_folders': ['notes'],
               'read_sensitivity': ['confidential'], 'frozen': True,
               'alone': [], 'secret': 'do not expose'}
    db.conn().execute('UPDATE helper_cards SET version=7, content=? WHERE helper_id=?',
                      (evidence.enc_json(content), stored))
    db.conn().commit()
    view = card_view.load_stored_cards(role='auditor')
    row = next(c for c in view['cards'] if c['helper_id'] == stored)
    assert row['version'] == 7
    assert row['tools'] == ['read_file']
    assert row['frozen'] is True
    assert row['alone'] == []
    assert row['ask'] is None
    assert 'secret' not in row
    assert view['enforcement_connected'] is False


@pytest.mark.parametrize('content', ['enc:v2:broken', '{}', '{"tools":"read_file"}',
                                      '{"tools":[],"read_folders":[],"read_sensitivity":[],"frozen":"false"}'])
def test_invalid_card_warning(monkeypatch, stored, content):
    db.conn().execute('UPDATE helper_cards SET content=? WHERE helper_id=?', (content, stored))
    db.conn().commit()
    monkeypatch.setattr(web, 'current_user', lambda request: {'role': 'auditor', 'username': 'reader', 'csrf': ''})
    response = TestClient(web.app).get('/helper-cards')
    assert response.status_code == 200
    assert 'Invalid or unreadable stored card' in response.text
    assert content not in response.text
