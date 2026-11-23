"""HTTP credential regressions. Missing dependencies fail import, never skip."""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, patch

try:
    from fastapi.testclient import TestClient
    from aegis.production import create_app
except ImportError as exc:
    raise ImportError('Key safety tests require FastAPI, httpx and cryptography; install nothing and do not skip.') from exc

FAKE_KEY = 'sk-test-FAKE-0000000000000000'
FAKE_CODE = 'test-access-' + '0' * 43


class LiveKeySafety(unittest.TestCase):
    def assert_clean(self):
        for body, headers in self.responses:
            self.assertNotIn(FAKE_KEY.encode(), body, 'HTTP body leaked credential')
            self.assertNotIn(FAKE_KEY, headers, 'HTTP headers leaked credential')
        for stream in (self.stdout, self.stderr, self.logs):
            self.assertNotIn(FAKE_KEY, stream.getvalue(), 'Captured output leaked credential')
        for file in self.root.rglob('*'):
            if file.is_file():
                self.assertNotIn(FAKE_KEY.encode(), file.read_bytes(), file.name)

    @contextmanager
    def flow(self, mode=None, outcome='success', **settings):
        self.responses = []
        self.stdout, self.stderr, self.logs = io.StringIO(), io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory(prefix='aegis-key-safety-') as folder:
            self.root = Path(folder).resolve()
            env = {
                'AEGIS_ENV': 'production', 'AEGIS_DEMO_PUBLIC': '1',
                'AEGIS_PRODUCTION_DATA_DIR': str(self.root / 'data'),
                'AEGIS_TRUSTED_HOSTS': 'testserver', 'AEGIS_WORKERS': '1',
                'AEGIS_MODEL_PROVIDER': 'deepseek', 'DEEPSEEK_API_KEY': FAKE_KEY,
                'AEGIS_LIVE_ACCESS_CODES': 'sha256:' + hashlib.sha256(FAKE_CODE.encode()).hexdigest(),
            }
            if mode is not None:
                env['AEGIS_LIVE_ACCESS_MODE'] = mode
            env.update(settings)
            handler = logging.StreamHandler(self.logs)
            handler.setFormatter(logging.Formatter('%(name)s %(levelname)s %(message)s'))
            loggers = [logging.getLogger()] + [x for x in logging.Logger.manager.loggerDict.values() if isinstance(x, logging.Logger)]
            levels = [(x, x.level) for x in loggers]
            for logger in loggers:
                logger.setLevel(logging.DEBUG)

            def provider_open(request, timeout):
                self.assertEqual(request.full_url, 'https://api.deepseek.com/chat/completions')
                self.assertEqual(request.get_header('Authorization'), 'Bearer ' + FAKE_KEY)
                self.assertNotIn(FAKE_KEY.encode(), request.data)
                self.assertEqual(timeout, 20)
                self.assertLessEqual(json.loads(request.data)['max_tokens'], 512)
                if outcome == 'error':
                    raise OSError('Synthetic upstream error: ' + FAKE_KEY)
                content = json.dumps({'verdict': 'safe', 'ignored': FAKE_KEY})
                if outcome == 'malformed_content':
                    content = content[:-1]
                raw = json.dumps({'usage': {'prompt_tokens': 10, 'completion_tokens': 2},
                                  'choices': [{'message': {'content': content}}],
                                  'ignored': FAKE_KEY}).encode()
                if outcome == 'malformed':
                    raw = ('{"ignored":"' + FAKE_KEY + '",').encode()
                response = Mock()
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                response.read.side_effect = lambda limit: raw[:limit]
                return response

            self.opener = Mock()
            self.opener.open.side_effect = provider_open
            try:
                with patch.dict(os.environ, env, clear=True), redirect_stdout(self.stdout), redirect_stderr(self.stderr), patch.object(logging.Logger, 'handle', handler.handle), patch('urllib.request.build_opener', return_value=self.opener), patch('socket.create_connection', side_effect=AssertionError('Real network forbidden')):
                    try:
                        with TestClient(create_app(), base_url='https://testserver', follow_redirects=False) as client:
                            self.client = client
                            home = self.request('GET', '/')
                            self.assertEqual(home.status_code, 200)
                            match = re.search(r'name="csrf" value="([^"]+)"', home.text)
                            self.assertIsNotNone(match)
                            self.csrf = match.group(1)
                            self.assertEqual(self.post('/session', role='approver').status_code, 303)
                            self.assertEqual(self.request('GET', '/').status_code, 200)
                            yield
                    finally:
                        # Scan again after lifespan shutdown and database closure.
                        self.assert_clean()
            finally:
                for logger, level in levels:
                    logger.setLevel(level)
                handler.close()

    def request(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        for item in [*response.history, response]:
            self.responses.append((item.content, repr(item.headers.multi_items())))
        self.assert_clean()
        return response

    def post(self, path, accept=None, **fields):
        return self.request('POST', path, data=dict(csrf=self.csrf, **fields),
                            headers={'Accept': accept} if accept else {})

    def action(self, accept=None):
        return self.post('/action', accept=accept, action='scenario_harbourbean')

    def assert_mode(self, response, mode):
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response.headers['content-type'])
        self.assertEqual(response.json()['model_mode'], mode)

    def pages(self):
        for path in ('/', '/world', '/audit', '/roles', '/audit/export', '/healthz', '/readyz'):
            self.assertEqual(self.request('GET', path).status_code, 200)
        self.assertEqual(self.post('/reset').status_code, 303)
        self.assertEqual(self.request('GET', '/world').status_code, 200)

    def test_explicit_access_code_and_unlock(self):
        with self.flow(mode='access-code'):
            self.assert_mode(self.action(), 'SCRIPTED')
            self.opener.open.assert_not_called()
            self.assertEqual(self.post('/live/unlock', code='invalid-test-code').status_code, 403)
            self.assertEqual(self.post('/live/unlock', code=FAKE_CODE).status_code, 303)
            self.assertEqual(self.request('GET', '/world').status_code, 200)
            self.assert_mode(self.action(), 'LIVE')
            self.assertEqual(self.opener.open.call_count, 2)
            self.pages()
            self.assertTrue(self.logs.getvalue(), 'Logging capture must not be empty')

    def test_default_open_mode_without_unlock(self):
        with self.flow():
            self.assertNotIn('Operator-issued live access code', self.request('GET', '/world').text)
            self.assert_mode(self.action(), 'LIVE')
            self.assertEqual(self.opener.open.call_count, 2)
            self.pages()

    def test_provider_failures_do_not_leak(self):
        for outcome in ('error', 'malformed', 'malformed_content'):
            with self.subTest(outcome=outcome), self.flow(mode='open', outcome=outcome):
                response = self.action()
                self.assert_mode(response, 'LIVE')
                self.assertEqual(response.json()['decision'], 'hold')
                self.assertEqual(self.opener.open.call_count, 1)
                self.pages()

    def test_browser_live_and_immediate_disabled_fallback(self):
        with self.flow(mode='open'):
            response = self.action('text/html')
            self.assertEqual(response.status_code, 200)
            self.assertIn('text/html', response.headers['content-type'])
            self.assertIn('LIVE', response.text)
            self.assertEqual(self.opener.open.call_count, 2)
            os.environ['AEGIS_LIVE_ENABLED'] = '0'
            response = self.action('text/html')
            self.assertEqual(response.status_code, 200)
            self.assertIn('text/html', response.headers['content-type'])
            self.assertIn('scripted demo instead', response.text.lower())
            self.assert_mode(self.action(), 'SCRIPTED')
            self.assertEqual(self.opener.open.call_count, 2)

    def test_browser_limit_fallback_json_default(self):
        with self.flow(mode='open', AEGIS_LIVE_SESSION_CALLS='2'):
            self.assert_mode(self.action(), 'LIVE')
            response = self.action('text/html')
            self.assertEqual(response.status_code, 200)
            self.assertIn('text/html', response.headers['content-type'])
            self.assertIn('limit reached', response.text.lower())
            self.assertIn('scripted demo instead', response.text.lower())
            self.assert_mode(self.action(), 'SCRIPTED')
            self.assertEqual(self.opener.open.call_count, 2)

    def test_disabled_at_start(self):
        with self.flow(mode='open', AEGIS_LIVE_ENABLED='0'):
            self.assert_mode(self.action(), 'SCRIPTED')
            self.opener.open.assert_not_called()
            self.pages()


if __name__ == '__main__':
    unittest.main()
