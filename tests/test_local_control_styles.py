from scripts.local_demo import style_local_html


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
    assert not any(getattr(route, 'path', '').startswith('/local-demo/settings') for route in app.routes)
