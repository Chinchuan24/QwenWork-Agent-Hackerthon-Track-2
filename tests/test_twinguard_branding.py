"""Visible product naming; internal package/settings retain their identifiers."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_visible_product_branding():
    base = (ROOT / 'templates/base.html').read_text()
    assert '{% block title %}Twinguard{% endblock %}' in base
    assert '>Twinguard</a>' in base
    assert 'two AI guards' in base
    assert 'Built by Qwen' in base
    for name in ('alarm', 'owner_home', 'incident_report', 'helper_cards', 'rule_match', 'attack_board'):
        title = (ROOT / f'templates/{name}.html').read_text().splitlines()[1]
        assert 'Twinguard' in title
    assert 'title="Twinguard"' in (ROOT / 'aegis/app.py').read_text()
    assert 'Twinguard refused to start' in (ROOT / 'run.py').read_text()
