import concurrent.futures
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.mixed_demo import MixedDemo, RESERVE

FAKE = 'sk-test-FAKE-0000000000000000'
SCRIPTED = {'decision': 'allow'}


class LiveLimits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {'AEGIS_MODEL_PROVIDER': 'deepseek',
                             'DEEPSEEK_API_KEY': FAKE}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.demo = MixedDemo(Path(self.tmp.name) / 'live.db', b'test-salt')
        with self.demo.connect() as c:
            c.execute('INSERT INTO live_sessions VALUES(?)', ('v',))

    def mock_provider(self, fail=False):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return json.dumps({'usage': {'prompt_tokens': 10, 'completion_tokens': 2},
                                   'choices': [{'message': {'content': '{"verdict":"safe"}'}}]}).encode()
        def open_request(request, **kwargs):
            self.assertEqual(json.loads(request.data)['max_tokens'], self.demo.limits['MAX_OUTPUT_TOKENS'])
            if fail:
                raise ValueError(FAKE)
            return Response()
        return patch('urllib.request.OpenerDirector.open', side_effect=open_request)

    def test_defaults_and_existing_caps(self):
        for name, value in [('SESSION_CALLS', 30), ('IP_DAILY_CALLS', 60),
                            ('DAILY_CALLS', 1500), ('DAILY_TOKENS', 2000000),
                            ('MONTHLY_TOKENS', 10000000)]:
            self.assertEqual(self.demo.limits[name], value)
            with self.subTest(name=name):
                original = self.demo.limits[name]
                self.demo.limits[name] = 1 if 'CALLS' in name else RESERVE * 2 - 1
                self.assertEqual(self.demo.reserve('v', 'ip')[0], 'scripted')
                self.demo.limits[name] = original

    def test_access_and_immediate_switch(self):
        os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'access-code'
        self.assertFalse(self.demo.enabled('other'))
        os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'open'
        self.assertTrue(self.demo.enabled('other'))
        os.environ['AEGIS_LIVE_ENABLED'] = '0'
        with self.mock_provider() as provider:
            result = self.demo.evaluate('v', 'ip', {}, SCRIPTED)
            self.assertEqual(result['model_mode'], 'SCRIPTED')
            self.assertIn('scripted demo', result['note'])
            provider.assert_not_called()

    def test_open_default_call_caps_with_fresh_visitors(self):
        self.assertNotIn('AEGIS_LIVE_ACCESS_MODE', os.environ)
        for cap, evaluations, ips in (('IP_DAILY_CALLS', 30, 1), ('DAILY_CALLS', 750, 25)):
            with self.subTest(cap=cap):
                with self.demo.connect() as c:
                    c.execute('DELETE FROM live_attempts')
                with self.mock_provider() as provider:
                    for visitor in range(evaluations):
                        self.assertTrue(self.demo.enabled(f'fresh-{visitor}'))
                        result = self.demo.evaluate(f'fresh-{visitor}', f'ip-{visitor // 30}', {}, SCRIPTED)
                        self.assertEqual(result['model_mode'], 'LIVE')
                        with self.demo.connect() as c:
                            c.execute('UPDATE live_attempts SET active=0')
                    self.assertEqual(provider.call_count, self.demo.limits[cap])
                    address = 'ip-0' if ips == 1 else 'fresh-ip'
                    result = self.demo.evaluate('fresh-rejected', address, {}, SCRIPTED)
                    self.assertEqual(result['model_mode'], 'SCRIPTED')
                    self.assertEqual(provider.call_count, self.demo.limits[cap])
                with self.demo.connect() as c:
                    self.assertEqual(c.execute('SELECT COUNT(*), COUNT(DISTINCT visitor), COUNT(DISTINCT ip), SUM(tokens), SUM(active) FROM live_attempts').fetchone(),
                                     (evaluations * 2, evaluations, ips, evaluations * 24, 0))

    def test_open_default_token_caps_shared_across_visitors_and_ips(self):
        self.assertNotIn('AEGIS_LIVE_ACCESS_MODE', os.environ)
        for cap, evaluations in (('DAILY_TOKENS', 50), ('MONTHLY_TOKENS', 250)):
            with self.subTest(cap=cap):
                with self.demo.connect() as c:
                    c.execute('DELETE FROM live_attempts')
                for visitor in range(evaluations):
                    mode, ids = self.demo.reserve(f'fresh-{visitor}', f'ip-{visitor}')
                    self.assertEqual(mode, 'live')
                    self.assertEqual(len(ids), 2)
                    with self.demo.connect() as c:
                        c.execute('UPDATE live_attempts SET active=0')
                        if cap == 'MONTHLY_TOKENS':
                            # Retain monthly charges without exhausting the daily cap.
                            c.execute("UPDATE live_attempts SET day='prior-day'")
                with self.demo.connect() as c:
                    self.assertEqual(c.execute('SELECT COUNT(*), COUNT(DISTINCT visitor), COUNT(DISTINCT ip), SUM(tokens), SUM(active) FROM live_attempts').fetchone(),
                                     (evaluations * 2, evaluations, evaluations, self.demo.limits[cap], 0))
                self.assertEqual(self.demo.reserve('fresh-rejected', 'fresh-ip'), ('scripted', []))
                with self.demo.connect() as c:
                    self.assertEqual(c.execute('SELECT COUNT(*), SUM(tokens) FROM live_attempts').fetchone(),
                                     (evaluations * 2, self.demo.limits[cap]))

    def test_burst_and_expiration(self):
        self.demo.limits['BURST_ACTIONS'] = 2
        with self.mock_provider() as provider:
            for _ in range(2):
                self.assertEqual(self.demo.evaluate('v', 'ip', {}, SCRIPTED)['model_mode'], 'LIVE')
            self.assertEqual(self.demo.evaluate('v', 'ip', {}, SCRIPTED)['model_mode'], 'SCRIPTED')
            self.assertEqual(provider.call_count, 4)
        with self.demo.connect() as c:
            c.execute('UPDATE live_actions SET started=started-61')
        self.assertIsNotNone(self.demo.admit_action('v', 'ip'))

    def test_default_legacy_six_evaluations_twelve_calls(self):
        with self.mock_provider() as provider:
            for _ in range(6):
                self.assertEqual(self.demo.evaluate('v', 'ip', {}, SCRIPTED)['model_mode'], 'LIVE')
            self.assertEqual(self.demo.evaluate('v', 'ip', {}, SCRIPTED)['model_mode'], 'SCRIPTED')
            self.assertEqual(provider.call_count, 12)
        with self.demo.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*), SUM(calls) FROM live_actions').fetchone(), (6, 12))

    def test_atomic_action_admission(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            contexts = list(pool.map(lambda _: self.demo.admit_action('v', 'ip'), range(12)))
        self.assertEqual(sum(context is not None for context in contexts), 6)
        with self.demo.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0], 0)

    def test_bounded_startup_and_action_contexts(self):
        context = self.demo.admit_action('v', 'ip', startup=True)
        self.assertEqual(self.demo.reserve_call('v', 'ip', context, kind='helper'), ('scripted', []))
        self.assertEqual(self.demo.reserve_call('v', 'ip', context, kind='limits')[0], 'live')
        with self.demo.connect() as c:
            c.execute('UPDATE live_attempts SET active=0,tokens=12,pending=0')
        self.assertEqual(self.demo.reserve_call('v', 'ip', context, kind='limits'), ('scripted', []))
        context = self.demo.admit_action('v', 'ip')
        for _ in range(16):
            self.assertEqual(self.demo.reserve_call('v', 'ip', context)[0], 'live')
            with self.demo.connect() as c:
                c.execute('UPDATE live_attempts SET active=0,tokens=12,pending=0')
        self.assertEqual(self.demo.reserve_call('v', 'ip', context), ('scripted', []))

    def test_atomic_concurrency(self):
        os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'open'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda n: self.demo.reserve(str(n), str(n))[0], range(8)))
        self.assertEqual(results.count('live'), 1)
        self.assertEqual(results.count('scripted'), 7)

    def test_finally_release_and_unknown_usage_retained(self):
        with self.mock_provider(fail=True):
            result = self.demo.evaluate('v', 'ip', {}, SCRIPTED)
        self.assertNotIn(FAKE, json.dumps(result))
        with self.demo.connect() as c:
            self.assertEqual(c.execute('SELECT SUM(active), SUM(tokens) FROM live_attempts').fetchone(), (0, RESERVE * 2))
        os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'open'
        self.assertEqual(self.demo.reserve('other', 'other')[0], 'live')
        for file in Path(self.tmp.name).iterdir():
            self.assertNotIn(FAKE.encode(), file.read_bytes())

    def test_output_cap_and_success_release(self):
        self.demo.limits['MAX_OUTPUT_TOKENS'] = 64
        with self.mock_provider():
            self.assertEqual(self.demo.evaluate('v', 'ip', {}, SCRIPTED)['model_mode'], 'LIVE')
        with self.demo.connect() as c:
            self.assertEqual(c.execute('SELECT SUM(active), SUM(tokens) FROM live_attempts').fetchone(), (0, 24))

    def test_initial_database_error_uses_scripted_fallback(self):
        with patch.object(self.demo, 'connect', side_effect=sqlite3.OperationalError(FAKE)), self.mock_provider() as provider:
            result = self.demo.evaluate('v', 'ip', {}, SCRIPTED)
        self.assertEqual(result['model_mode'], 'SCRIPTED')
        self.assertEqual(result['decision'], SCRIPTED['decision'])
        self.assertNotIn(FAKE, json.dumps(result))
        provider.assert_not_called()
        with self.demo.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM live_attempts').fetchone()[0], 0)

    def test_cleanup_database_error_retains_active_reservations(self):
        connect = self.demo.connect
        class CleanupFailure(sqlite3.Connection):
            def executemany(self, sql, parameters):
                super().executemany(sql, parameters)
                raise sqlite3.OperationalError(FAKE)
        def failing_cleanup_connect():
            return sqlite3.connect(self.demo.database, factory=CleanupFailure)
        for fail in (False, True):
            with self.subTest(provider_failure=fail):
                with connect() as c:
                    c.execute('DELETE FROM live_attempts')
                with patch.object(self.demo, 'connect', side_effect=failing_cleanup_connect), self.mock_provider(fail=fail):
                    result = self.demo.evaluate('v', 'ip', {}, SCRIPTED)
                self.assertEqual(result['model_mode'], 'SCRIPTED')
                self.assertEqual(result['decision'], SCRIPTED['decision'])
                self.assertNotIn(FAKE, json.dumps(result))
                with connect() as c:
                    self.assertEqual(c.execute('SELECT SUM(active), SUM(tokens), SUM(pending) FROM live_attempts').fetchone(),
                                     (1, RESERVE * 2 if fail else 24, 2 if fail else 0))
                self.assertEqual(self.demo.reserve('v', 'ip')[0], 'scripted')

    def test_exact_existing_quota_boundaries(self):
        os.environ['AEGIS_LIVE_ACCESS_MODE'] = 'open'
        original_limits = self.demo.limits.copy()
        for name in ('SESSION_CALLS', 'IP_DAILY_CALLS', 'DAILY_CALLS', 'DAILY_TOKENS', 'MONTHLY_TOKENS'):
            self.demo.limits = dict(original_limits)
            for other in original_limits:
                if other != name and other != 'MAX_OUTPUT_TOKENS':
                    self.demo.limits[other] = 1000000000
            with self.subTest(name=name):
                with self.demo.connect() as c:
                    c.execute('DELETE FROM live_attempts')
                mode, ids = self.demo.reserve('v', 'ip')
                self.assertEqual(mode, 'live')
                with self.demo.connect() as c:
                    c.execute('UPDATE live_attempts SET active=0, started=0, tokens=0')
                    row = c.execute('SELECT visitor,ip,day,month FROM live_attempts LIMIT 1').fetchone()
                    if 'CALLS' in name:
                        c.executemany('INSERT INTO live_attempts(visitor,ip,day,month,tokens,pending) VALUES(?,?,?,?,0,0)',
                                      [row] * (self.demo.limits[name] - 4))
                    else:
                        c.execute('UPDATE live_attempts SET tokens=? WHERE id=?',
                                  (self.demo.limits[name] - RESERVE * 2, ids[0]))
                self.assertEqual(self.demo.reserve('v', 'ip')[0], 'live')
                with self.demo.connect() as c:
                    c.execute('UPDATE live_attempts SET active=0, started=0')
                self.assertEqual(self.demo.reserve('v', 'ip')[0], 'scripted')

    def test_switch_between_judges(self):
        with self.mock_provider() as provider:
            original = provider.side_effect
            def stop_after_first(request, **kwargs):
                response = original(request, **kwargs)
                os.environ['AEGIS_LIVE_ENABLED'] = '0'
                return response
            provider.side_effect = stop_after_first
            result = self.demo.evaluate('v', 'ip', {}, SCRIPTED)
            self.assertEqual(provider.call_count, 1)
            self.assertEqual(result['model_mode'], 'SCRIPTED')
        with self.demo.connect() as c:
            # The unissued second judge remains conservatively charged.
            self.assertEqual(c.execute('SELECT SUM(active), SUM(tokens), SUM(pending) FROM live_attempts').fetchone(),
                             (0, RESERVE + 12, 1))

    def test_invalid_settings_fail_closed(self):
        for name, value in [('BURST_ACTIONS', '0'), ('CONCURRENCY', '-1'),
                            ('MAX_OUTPUT_TOKENS', '513'), ('ACCESS_MODE', 'invalid')]:
            with self.subTest(name=name), patch.dict(os.environ, {'AEGIS_LIVE_' + name: value}):
                with self.assertRaises(ValueError):
                    MixedDemo(Path(self.tmp.name) / 'invalid.db', b'test')


if __name__ == '__main__':
    unittest.main()
