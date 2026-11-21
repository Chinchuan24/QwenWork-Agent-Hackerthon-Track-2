import pytest

from aegis import auth, breach_incident, incident_store
from test_g2_breach_views import client, create


@pytest.mark.parametrize('completed_at', [
    '0001-01-01T00:00:00+14:00',
    '9999-12-31T23:59:59-12:00',
])
def test_completion_date_overflow_returns_safe_422_without_write(client, completed_at):
    url = create(client).headers['location']
    user = auth.user_by_token(client.cookies.get('aegis_session'))
    incident_id = url.split('/')[-1]
    before = incident_store.get_incident(user, incident_id)

    response = client.post(url + '/steps', data=dict(
        csrf=client.csrf, outcome='not_notifiable', reason='PRIVATE REASON',
        completed_at=completed_at, human_completion='yes'), follow_redirects=False)

    assert response.status_code == 422
    assert response.json() == {'detail': 'Invalid incident facts or dates'}
    assert 'PRIVATE' not in response.text
    assert incident_store.get_incident(user, incident_id) == before


def test_completion_adapter_overflow_returns_safe_422(client, monkeypatch):
    url = create(client).headers['location']

    def overflow(*args, **kwargs):
        raise OverflowError('PRIVATE STORAGE DETAILS')

    monkeypatch.setattr(breach_incident, 'complete_assessment', overflow)
    response = client.post(url + '/steps', data=dict(
        csrf=client.csrf, outcome='not_notifiable', reason='Human decision',
        completed_at='2026-11-01T00:00', human_completion='yes'), follow_redirects=False)

    assert response.status_code == 422
    assert response.json() == {'detail': 'Invalid incident facts or dates'}
    assert 'PRIVATE' not in response.text
