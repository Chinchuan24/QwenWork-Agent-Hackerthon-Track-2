import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import signer_client


class SignerPortStartupTests(unittest.TestCase):
    def run_startup(self, contents, *, exits=False, ready=True):
        with tempfile.TemporaryDirectory() as directory:
            pf = Path(directory) / 'signer.port'
            clock = [0.0]
            reads = []

            class Process:
                def poll(self):
                    return 1 if exits else None

            def publish(index):
                value = contents[min(index, len(contents) - 1)]
                if value is not None:
                    pf.write_text(value)

            def sleep(seconds):
                clock[0] += seconds
                publish(round(clock[0] / 0.05))

            def request(client, obj):
                reads.append(client.port)
                if not ready or client.port != 43210:
                    raise signer_client.SignerUnavailable('not listening')
                self.assertEqual(obj, {'op': 'ping'})
                return {'ok': True}

            publish(0)
            manager = signer_client.SignerManager.__new__(signer_client.SignerManager)
            manager.state_dir, manager.port, manager.proc = directory, 0, None
            with patch.object(signer_client.tempfile, 'mkdtemp', return_value=directory), \
                 patch.object(signer_client.subprocess, 'Popen', return_value=Process()), \
                 patch.object(signer_client.time, 'time', side_effect=lambda: clock[0]), \
                 patch.object(signer_client.time, 'monotonic', side_effect=lambda: clock[0]), \
                 patch.object(signer_client.time, 'sleep', side_effect=sleep), \
                 patch.object(signer_client.SignerClient, 'request', request):
                manager.start()
            return manager.port, reads, clock[0]

    def test_empty_then_complete(self):
        self.assertEqual(self.run_startup(['', '43210'])[0], 43210)

    def test_numeric_partial_then_complete(self):
        port, reads, elapsed = self.run_startup(['4', '432', '43210'])
        self.assertEqual(port, 43210)
        self.assertGreaterEqual(elapsed, 0.1)
        self.assertIn(43210, reads)

    def test_missing_then_complete(self):
        self.assertEqual(self.run_startup([None, '43210'])[0], 43210)

    def test_dead_process_with_valid_file_is_not_ready(self):
        with self.assertRaisesRegex(signer_client.SignerUnavailable, 'exited'):
            self.run_startup(['43210'], exits=True)

    def test_malformed_final_is_reported(self):
        for content in ['', 'broken', '0', '65536', '-1', '12.5']:
            with self.subTest(content=content):
                with self.assertRaisesRegex(signer_client.SignerUnavailable, 'invalid.*port'):
                    self.run_startup([content])

    def test_valid_port_without_ready_server_times_out(self):
        with self.assertRaisesRegex(signer_client.SignerUnavailable, 'not ready'):
            self.run_startup(['43210'], ready=False)

    def test_missing_final_times_out(self):
        with self.assertRaisesRegex(signer_client.SignerUnavailable, 'did not write'):
            self.run_startup([None])
