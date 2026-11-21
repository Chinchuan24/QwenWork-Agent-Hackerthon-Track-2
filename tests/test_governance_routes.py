"""Governance views authenticate before projecting stored data."""
import pytest
from fastapi.testclient import TestClient
from aegis.app import app

@pytest.mark.parametrize('path', ['/attack-board', '/helper-cards', '/rule-match', '/incident-report', '/alarm'])
def test_governance_pages_require_login(path):
    with TestClient(app) as client:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers['location'] == '/login'
