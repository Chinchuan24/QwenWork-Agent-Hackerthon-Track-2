"""Standalone focused tests: no shared conftest or application imports."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import signal
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/sponsor_story.py'


class SponsorStoryTests(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def reviewed_manifest(self, reviewed14_sandbox_tools):
        self.manifest = {'version': 1, 'approved_records': reviewed14_sandbox_tools}

    def test_cli(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), '--reviewed-manifest',
                               json.dumps(self.manifest)], cwd=ROOT,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report['scenario'], 'S1')
        self.assertEqual(report['steps'][-1]['verdict'], 'block')
        self.assertIn('R15', report['steps'][-1]['rules'])
        for key in ('passed', 'audit_ok', 'decision_bindings_ok', 'documents_unchanged'):
            self.assertTrue(report[key])
        self.assertEqual(report['effects'], 0)
        self.assertIn('simulated', report['disclaimer'])

    def test_omission_fails_closed(self):
        proc = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT,
                              capture_output=True, text=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('passed', proc.stdout)

    def test_timeout_kills_owned_group_and_reaps(self):
        spec = importlib.util.spec_from_file_location('story_timeout', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        proc = mock.Mock(pid=43210)
        proc.communicate.side_effect = [subprocess.TimeoutExpired('story', 30), ('', '')]
        events = mock.Mock()
        events.attach_mock(proc.communicate, 'communicate')
        helper = mock.Mock()
        with mock.patch.dict(sys.modules, local_setup=helper), \
                mock.patch.object(module.subprocess, 'Popen', return_value=proc) as launch, \
                mock.patch.object(module.os, 'killpg') as killpg:
            events.attach_mock(killpg, 'killpg')
            with self.assertRaises(RuntimeError):
                module.run_story()
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            self.assertEqual(events.mock_calls, [
                mock.call.communicate(input='null', timeout=30),
                mock.call.killpg(43210, signal.SIGKILL),
                mock.call.communicate()])

    def test_failure_gate(self):
        spec = importlib.util.spec_from_file_location('story', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        good = dict(steps=[dict(verdict='allow', rules=[]),
                           dict(verdict='block', rules=['R15'])],
                    audit_ok=True, decision_bindings_ok=True,
                    documents_unchanged=True, effects=0, api_ok=True)
        self.assertTrue(module.story_passed(good))
        for key in ('audit_ok', 'decision_bindings_ok', 'documents_unchanged', 'api_ok'):
            self.assertFalse(module.story_passed(dict(good, **{key: False})))
        self.assertFalse(module.story_passed(dict(good, effects=1)))
        good['steps'][-1]['rules'] = ['HARD-ERROR']
        self.assertFalse(module.story_passed(good))


if __name__ == '__main__':
    unittest.main()
