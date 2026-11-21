from pathlib import Path

from scripts.local_demo import style_local_html


LOCAL_HINT = ('Owner login: admin. Other local roles: ops and riley (approvers), '
              'audi (auditor), view (viewer). Other-role passwords are in '
              '.local-demo/passwords.json on this computer.')


def test_local_login_hint():
    template = (Path(__file__).resolve().parents[1] / 'templates/login.html').read_bytes()
    for presenting in (False, True):
        result = style_local_html(template, presenting).decode()
        assert '<p class="muted">' + LOCAL_HINT + '</p>' in result
        assert result.count(LOCAL_HINT) == 1
        assert 'demo-dana-2026' not in result
        assert 'LOCAL MODE ONLY' not in result
        assert 'autocomplete="current-password"' in result


def test_owner_alias_preserves_identity(monkeypatch, tmp_path):
    from aegis import auth, db
    from scripts import local_demo
    monkeypatch.setattr(local_demo, 'STATE', tmp_path)
    original = auth.login
    monkeypatch.setattr(auth, 'login', original)
    before = dict(db.conn().execute("SELECT * FROM users WHERE username='dana'").fetchone())
    others = [tuple(row) for row in db.conn().execute("SELECT * FROM users WHERE username!='dana'")]
    local_demo.install_owner_login(auth)
    result = auth.login('admin', bytes([80, 64, 115, 115, 119, 48, 114, 100]).decode())
    assert result and result['user']['id'] == before['id']
    assert result['user']['username'] == 'dana' and result['user']['role'] == 'admin'
    assert auth.user_by_token(result['token'])['username'] == 'dana'
    assert not db.conn().execute("SELECT 1 FROM users WHERE username='admin'").fetchone()
    assert others == [tuple(row) for row in db.conn().execute("SELECT * FROM users WHERE username!='dana'")]
    assert len(list(tmp_path.glob('owner-backup-*.db'))) == 1
    local_demo.install_owner_login(auth)
    assert len(list(tmp_path.glob('owner-backup-*.db'))) == 1
    with db.conn() as connection:
        connection.execute('UPDATE users SET pw_hash=?, salt=?, must_change=? WHERE id=?',
                           (before['pw_hash'], before['salt'], before['must_change'], before['id']))


def test_owner_fixture_refuses_nonlocal(monkeypatch):
    import pytest
    from scripts.local_demo import child
    for key, value in [('AEGIS_HOST', '0.0.0.0'), ('AEGIS_ENV', 'production'), ('AEGIS_DEMO_PUBLIC', '1')]:
        with monkeypatch.context() as patch:
            patch.setenv(key, value)
            with pytest.raises(ValueError, match='local loopback'):
                child()


def test_production_refuses_old_and_owner_fixtures(monkeypatch):
    import pytest
    from aegis.production import create_app
    monkeypatch.setenv('AEGIS_ENV', 'production')
    monkeypatch.setenv('AEGIS_DEMO_PUBLIC', '1')
    for value in ['demo-dana-2026', 'demo-ops-2026', 'demo-audi-2026', bytes([80, 64, 115, 115, 119, 48, 114, 100]).decode()]:
        monkeypatch.setenv('AEGIS_OWNER_PASSWORD', value)
        with pytest.raises(ValueError, match='refuses fixture passwords'):
            create_app()


def test_normal_and_present_controls():
    for presenting, size in [(False, b'18px'), (True, b'20px')]:
        result = style_local_html(b'<html><head></head><body>Demo</body></html>', presenting)
        assert b'--local-control-font: ' + size in result
        assert b'min-height: 48px' in result
        assert b'padding: 10px 14px' in result
        assert b'outline: 3px' in result
        assert result.count(b'local-demo-controls') == 1


def test_fragment_has_responsive_shell():
    result = style_local_html(b'<main>Settings</main>', True)
    assert b'name="viewport"' in result
    assert b'/static/app.css' in result
    assert b'<body class="present">' in result


def test_production_does_not_install_local_styling():
    from fastapi.testclient import TestClient
    from aegis.app import app
    with TestClient(app) as client:
        response = client.get('/login')
        assert response.status_code == 200
        assert 'local-demo-controls' not in response.text
        assert 'data-local-banner' not in response.text
        template = (Path(__file__).resolve().parents[1] / 'templates/login.html').read_text()
        original_hint = next(line for line in template.splitlines() if 'Demo accounts:' in line)
        assert original_hint in response.text
        assert LOCAL_HINT not in response.text
    assert not any(getattr(route, 'path', '').startswith('/local-demo/settings') for route in app.routes)
