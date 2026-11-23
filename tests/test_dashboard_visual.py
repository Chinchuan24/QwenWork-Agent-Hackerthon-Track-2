from pathlib import Path
import re
import unittest
import hashlib
import struct

ASSETS = Path(__file__).resolve().parents[1] / 'aegis' / 'assets'


def luminance(hex_color):
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
    return sum(c * w for c, w in zip(linear, (.2126, .7152, .0722)))


class DashboardVisualTests(unittest.TestCase):
    def test_palette_contrast_on_every_surface(self):
        css = (ASSETS / 'dashboard.css').read_text()
        colors = dict(re.findall(r'--([\w-]+):(#[0-9A-Fa-f]{6})', css))
        ratios = []
        for fg in ('text', 'secondary', 'muted', 'green', 'amber', 'red'):
            for bg in (('raised',) if fg == 'red' else ('bg', 'panel', 'raised', 'line', 'oxblood')):
                light, dark = sorted((luminance(colors[fg]), luminance(colors[bg])), reverse=True)
                ratio = (light + .05) / (dark + .05)
                ratios.append(ratio)
                self.assertGreaterEqual(ratio, 4.5, (fg, bg, ratio))
        ratio = (luminance(colors['amber']) + .05) / (luminance(colors['bg']) + .05)
        self.assertGreaterEqual(ratio, 4.5)
        self.assertIn('button:disabled{color:var(--secondary);background:var(--raised)', css)
        print(f'27 text/surface pairs: minimum {min(ratios):.3f}:1')

    def test_bright_red_only_for_stopped(self):
        css = (ASSETS / 'dashboard.css').read_text()
        rules = re.findall(r'([^{}]+)\{([^{}]*)\}', css)
        users = [selector.strip() for selector, body in rules if 'var(--red)' in body]
        self.assertEqual(users, ['.stopped', '.record-result.stopped'])
        self.assertIn('.brand span{color:var(--secondary)}', css)
        self.assertIn('--crimson:#8A0A1F;--oxblood:#4A0612;', css)
        self.assertIn('--line:#3A0E1E;', css)

    def test_r10_fonts_are_verified_local_woff2(self):
        expected = {
            'atkinson-hyperlegible-mono-400.woff2': '4c7fcd8365b4a89261a6d63ff3507937e0741c25ff18e022ba91853fb5eab0cc',
            'atkinson-hyperlegible-mono-500.woff2': 'cd29cf05b937c3d52db06e1c726c84f2af78041a4c3db55e06a03618b2e4f0ff',
            'atkinson-hyperlegible-next-400.woff2': 'e3eceb3d0b7a32fddf6b35af8302662d5a3a23e0cb8bd4c39237d6d34d2c5805',
            'atkinson-hyperlegible-next-700.woff2': 'eee973f8db596fed95e6cbe0db3e825f7c35ef0f63781c0f59bca1477ca9c49c',
            'barlow-condensed-600.woff2': '4644bc7876874a7f2eec58276b41bac38efb241dadd2800174096f60ea95aa22',
        }
        css = (ASSETS / 'dashboard.css').read_text()
        self.assertEqual(set(re.findall(r"url\('fonts/([^']+)'\)", css)), set(expected))
        for name, digest in expected.items():
            data = (ASSETS / 'fonts' / name).read_bytes()
            self.assertEqual(data[:4], b'wOF2')
            self.assertEqual(struct.unpack('>I', data[8:12])[0], len(data))
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        self.assertIn("body{font-family:'Atkinson Hyperlegible Next';", css)
        self.assertNotIn('body{font-family:system-ui', css)

    def test_motion_hooks_and_mobile_readability(self):
        css = (ASSETS / 'dashboard.css').read_text()
        for hook in ('#checks-panel.action-checked .pipeline:after', '[data-guard] .guard-icon',
                     '.record-link.locked', '.chain-icon', '#chain[data-sealed-decisions]',
                     '.guard-summary.muted', '#decision-input', 'body.paused:before'):
            self.assertIn(hook, css)
        for duration in re.findall(r'animation:[\w-]+ ([\d.]+)s', css):
            self.assertGreaterEqual(float(duration), 1 / 3)
        self.assertIn('animation:none!important;transition:none!important;scroll-behavior:auto!important', css)
        self.assertIn('@media(prefers-reduced-motion:reduce)', css)
        self.assertNotIn('.honesty{font-size:12px}', css)
        self.assertIn('.honesty{font-size:14px}', css)
        self.assertIn('pre{font-size:16px}', css)

    def test_svg_labels_and_safety_preserved(self):
        js = (ASSETS / 'dashboard.js').read_text()
        self.assertIn("document.createElementNS('http://www.w3.org/2000/svg','svg')", js)
        self.assertIn("document.createElementNS('http://www.w3.org/2000/svg','path')", js)
        self.assertIn("svg.setAttribute('aria-hidden','true')", js)
        self.assertIn("svg.setAttribute('focusable','false')", js)
        self.assertIn("chip.append(svg,make('span',label))", js)
        self.assertIn("resultChip(label,tone)", js)
        self.assertIn("el.replaceWith(resultChip(el.textContent,tone))", js)
        for label in ('ALLOWED', 'WAITING FOR YOU', 'STOPPED'):
            self.assertIn(label, js)
        self.assertNotIn('innerHTML', js)
        self.assertIn("'X-CSRF-Token':csrf", js)
        self.assertIn("prefers-reduced-motion: reduce", js)
        self.assertIn("window.addEventListener('pagehide'", js)


if __name__ == '__main__':
    unittest.main()
