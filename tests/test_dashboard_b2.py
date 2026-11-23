import hashlib
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch
import os
from aegis.production import create_app

ASSETS = Path(__file__).resolve().parents[1] / 'aegis' / 'assets'
SOURCE = Path('/Users/chin/Qwen/docs/website-design/media/demo-backdrops')

class BackdropTests(unittest.TestCase):
    def test_exact_allowlist_and_csp(self):
        with patch.dict(os.environ, {'AEGIS_ENV': 'production', 'AEGIS_DEMO_PUBLIC': '1', 'AEGIS_PRODUCTION_DATA_DIR': str(Path('/tmp/b2-unused').resolve()), 'AEGIS_TRUSTED_HOSTS': 'testserver'}, clear=True):
            client = TestClient(create_app(), base_url='https://testserver')
            for name, mime in [('B2-rainy-megacity.mp4', 'video/mp4'), ('B2-rainy-megacity.webm', 'video/webm'), ('B2-rainy-megacity-poster.jpg', 'image/jpeg')]:
                response = client.get('/dashboard/assets/backdrops/' + name)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers['content-type'], mime)
                self.assertIn("media-src 'self'", response.headers['content-security-policy'])
                self.assertEqual(response.content, (ASSETS / 'backdrops' / name).read_bytes())
                if SOURCE.exists():
                    self.assertEqual(hashlib.sha256(response.content).digest(), hashlib.sha256((SOURCE / name).read_bytes()).digest())
            for name in ['other.mp4', 'dashboard.html', '%2e%2e%2fproduction.py', 'B2-rainy-megacity.mp4.before-b2']:
                self.assertEqual(client.get('/dashboard/assets/backdrops/' + name).status_code, 404)
            response = client.get('/dashboard/assets/backdrops/B2-rainy-megacity.webm', headers={'Range': 'bytes=0-31'})
            self.assertEqual(response.status_code, 206)
            self.assertEqual(len(response.content), 32)
            self.assertEqual(client.get('/dashboard/assets/fonts/atkinson-hyperlegible-next-400.woff2').headers['content-type'], 'font/woff2')

    def test_deferred_markup(self):
        text = (ASSETS / 'dashboard.html').read_text()
        video = text.split('<video', 1)[1].split('</video>', 1)[0]
        self.assertIn('muted playsinline loop preload="none" hidden', video)
        self.assertNotIn('autoplay', video)
        self.assertNotIn('<source src=', video)
        self.assertEqual(video.count('data-src='), 2)
        css = (ASSETS / 'dashboard.css').read_text()
        self.assertIn('pointer-events:none;opacity:.35', css)
        self.assertIn('body:before,body:after{content:none!important;animation:none!important}', css)

if __name__ == '__main__':
    unittest.main()
