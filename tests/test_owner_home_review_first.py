"""Home decisions require review before submission, without app imports."""
from html.parser import HTMLParser
from pathlib import Path

from jinja2 import Environment


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.current = [dict(attrs), '']

    def handle_data(self, data):
        if self.current is not None:
            self.current[1] += data

    def handle_endtag(self, tag):
        if tag == 'a' and self.current is not None:
            self.links.append(self.current)
            self.current = None


def test_home_decisions_are_review_first_links():
    path = Path(__file__).resolve().parents[1] / 'templates' / 'owner_home.html'
    source = path.read_text().replace('{% extends "base.html" %}', '')
    html = Environment(autoescape=True).from_string(source).render(
        briefing=None, csrf='fixture-token',
        user=dict(role='approver', username='owner', must_change=False),
        approvals=[dict(id='review/item', explanation='Review the proof.',
                        recommendation='Keep it.', decision='APPROVE',
                        status='pending', expired=False, created_by='worker',
                        proof_ids=[17])],
    )
    parser = Links()
    parser.feed(html)
    for label in ('Allow once', 'Do not allow'):
        matches = [attrs for attrs, text in parser.links if text.strip() == label]
        assert len(matches) == 1, f'{label} must be a review link'
        assert matches[0]['href'] == '/approvals/review%2Fitem'
        assert matches[0]['aria-describedby'] == 'decision-note-1'
    assert '/decide' not in html
    assert '<form' not in html and '<button' not in html
    assert 'Review this work' in html
    assert 'href="/audit/record/17"' in html
