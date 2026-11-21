"""Narrow label and declared-color regressions, without app startup."""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]


class Labels(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels = {}
        self.controls = {}
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'label':
            self.current = attrs.get('for')
            self.labels[self.current] = ''
        if tag == 'textarea':
            self.controls[attrs.get('id')] = attrs

    def handle_data(self, data):
        if self.current:
            self.labels[self.current] += data

    def handle_endtag(self, tag):
        if tag == 'label':
            self.current = None


def luminance(hex_color):
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
              for v in channels]
    return sum(v * weight for v, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


class PolicyControlAccessibility(unittest.TestCase):
    def test_yaml_has_visible_associated_label(self):
        env = Environment(loader=FileSystemLoader(ROOT / 'templates'), autoescape=True)
        html = env.get_template('policies.html').render(
            user={'role': 'admin'}, active=1, rules=[], versions=[], csrf='test', content='rules: []')
        parser = Labels()
        parser.feed(html)
        self.assertEqual(parser.labels['policy-content'].strip(), 'YAML policy')
        self.assertEqual(parser.controls['policy-content']['name'], 'content')
        self.assertNotIn('hidden', parser.controls['policy-content'])
        self.assertNotIn('hidden', parser.labels['policy-content'])

    def test_control_border_has_three_to_one_contrast(self):
        css = (ROOT / 'static/app.css').read_text()
        tokens = dict(re.findall(r'(--[\w-]+):\s*(#[0-9a-f]{6})', css))
        rule = re.search(r'input, select, textarea\s*\{([^}]+)\}', css).group(1)
        self.assertIn('border: 1px solid var(--control-border)', rule)
        fill = re.search(r'background:\s*(#[0-9a-f]{6})', rule).group(1)
        border = luminance(tokens['--control-border'])
        for color in (fill, tokens['--bg'], tokens['--panel']):
            background = luminance(color)
            light, dark = sorted((border, background), reverse=True)
            with self.subTest(background=color):
                self.assertGreaterEqual((light + 0.05) / (dark + 0.05), 3)
        self.assertIn('.card { background: var(--panel); border: 1px solid var(--line)', css)
