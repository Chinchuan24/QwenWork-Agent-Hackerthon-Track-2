"""Process-isolated original gateway. Executors operate on fictional World only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import selectors
import time

MAX_FRAME = 65536


class RealBackend:
    def __init__(self, root, judge):
        root = Path(root).resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.judge = judge
        self.lock = threading.RLock()
        self.timeout = 30
        self.buffer = b''
        env = {k: v for k, v in os.environ.items()
               if k in ('PATH', 'SYSTEMROOT', 'LANG', 'LC_ALL')}
        env.update(AEGIS_DATA_DIR=str(root / 'data'),
                   AEGIS_SIGNER_STATE=str(root / 'signer'),
                   AEGIS_ANCHOR_EXTERNAL=str(root / 'external.json'),
                   AEGIS_EVIDENCE_KEY_FILE=str(root / 'evidence.key'))
        self.proc = subprocess.Popen(
            [sys.executable, '-m', 'aegis.real_backend', '--worker'],
            cwd=Path(__file__).resolve().parent.parent, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            bufsize=0)
        try:
            self.request('ready')
        except BaseException:
            self.close()
            raise

    def request(self, op, **fields):
        with self.lock:
            self._send(dict(op=op, **fields))
            deadline = time.monotonic() + self.timeout
            request_failed = False
            exchanges = 0
            while True:
                line = self._receive(deadline)
                reply = json.loads(line)
                if reply.get('op') == 'judge':
                    exchanges += 1
                    if exchanges > 100:
                        self.close()
                        raise RuntimeError('Judge exchange limit exceeded')
                    try:
                        answers = []
                        def evaluate():
                            try:
                                answers.append({'result': self.judge(reply['kind'], reply['payload'])})
                            except Exception:
                                answers.append({'error': 'Quota or judge unavailable'})
                        thread = threading.Thread(target=evaluate, daemon=True)
                        thread.start()
                        thread.join(max(0, deadline - time.monotonic()))
                        if thread.is_alive():
                            self.close()
                            raise RuntimeError('Judge deadline exceeded')
                        answer = answers[0]
                    except Exception:
                        answer = {'error': 'Quota or judge unavailable'}
                    request_failed |= 'error' in answer
                    self._send(answer)
                    continue
                if 'error' in reply:
                    raise RuntimeError(reply['error'])
                result = reply['result']
                if request_failed and isinstance(result, dict):
                    result['request_failed'] = True
                return result

    def _send(self, value):
        frame = json.dumps(value, allow_nan=False).encode() + b'\n'
        if len(frame) > MAX_FRAME:
            raise ValueError('IPC frame too large')
        os.set_blocking(self.proc.stdin.fileno(), False)
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdin, selectors.EVENT_WRITE)
            while frame:
                if not selector.select(max(0, deadline - time.monotonic())):
                    self.close()
                    raise RuntimeError('IPC write timeout')
                count = os.write(self.proc.stdin.fileno(), frame)
                frame = frame[count:]

    def _receive(self, deadline):
        with selectors.DefaultSelector() as selector:
            selector.register(self.proc.stdout, selectors.EVENT_READ)
            while b'\n' not in self.buffer:
                if not selector.select(max(0, deadline - time.monotonic())):
                    self.close()
                    raise RuntimeError('IPC read timeout')
                chunk = os.read(self.proc.stdout.fileno(), 4096)
                if not chunk or len(self.buffer) + len(chunk) > MAX_FRAME:
                    self.close()
                    raise RuntimeError('IPC unavailable or oversized')
                self.buffer += chunk
            line, self.buffer = self.buffer.split(b'\n', 1)
            return line

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc.stdin.close()
        self.proc.stdout.close()


def worker():
    from cryptography.fernet import Fernet
    key = Path(os.environ['AEGIS_EVIDENCE_KEY_FILE'])
    if not key.exists():
        if (key.parent / 'data' / 'aegis.db').exists():
            raise RuntimeError('Existing evidence requires original key')
        with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as handle:
            handle.write(Fernet.generate_key())
            handle.flush()
            os.fsync(handle.fileno())
    from .real_runtime import config
    import tempfile
    import time
    port_dir = tempfile.TemporaryDirectory()
    port_file = Path(port_dir.name) / 'port'
    signer = subprocess.Popen(
        [sys.executable, '-m', 'aegis.real_runtime.signer', '--state-dir',
         config.AEGIS_SIGNER_STATE, '--port-file', str(port_file),
         '--owner-pid', str(os.getpid())], stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while not port_file.exists():
            if signer.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('Signer startup unavailable')
            time.sleep(0.02)
        config.AEGIS_SIGNER_PORT = int(port_file.read_text())
        from .real_runtime import audit, db, evidence, gateway, policy, qwen_client
        db.init_db()
        evidence.require_key_for_startup()
        policy.ensure_default(str(Path(__file__).parent / 'real_runtime' / 'default.yaml'))
        policy.ensure_security_rules(str(Path(__file__).parent / 'real_runtime' / 'default.yaml'))
        audit.migrate_to_signer()
        evidence.migrate_once()
        if not audit.verify()['ok']:
            raise RuntimeError('Original audit verification failed')

        def judge(kind, payload, **kwargs):
            print(json.dumps({'op': 'judge', 'kind': kind, 'payload': payload}), flush=True)
            reply = json.loads(sys.stdin.readline())
            if 'error' in reply:
                raise qwen_client.JudgeUnavailable(reply['error'])
            return reply['result']

        qwen_client.judge = judge
        from .backend_mount import install_sandbox_hooks
        install_sandbox_hooks(gateway)
        while True:
            line = sys.stdin.readline(MAX_FRAME + 1)
            if not line:
                break
            try:
                if len(line.encode()) > MAX_FRAME or not line.endswith('\n'):
                    raise ValueError('IPC frame too large')
                req = json.loads(line)
                op = req['op']
                if op == 'ready' or op == 'verify':
                    result = audit.verify()
                elif op == 'start':
                    rid = gateway.create_run('enforce', req['owner'])
                    result = gateway.start_session(rid, req['task'], req['owner'])
                    result['run_id'] = rid
                elif op in ('review', 'card', 'snapshot', 'approval', 'action_explanations', 'sealed_decisions'):
                    from .backend_mount import configure_runtime
                    result = configure_runtime(audit, db, evidence, gateway, req)
                elif op == 'call':
                    result = gateway.handle_call(req['token'], req['tool'], req['args'], req.get('idem_key'))
                else:
                    raise ValueError('Operation not supported')
                print(json.dumps({'result': result}), flush=True)
            except Exception:
                print(json.dumps({'error': 'Original gateway failed closed'}), flush=True)
    finally:
        signer.terminate()
        signer.wait(timeout=5)
        port_dir.cleanup()


if __name__ == '__main__' and sys.argv[1:] == ['--worker']:
    worker()
