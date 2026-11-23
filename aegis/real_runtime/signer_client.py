"""Client + process manager for the separate audit signer. The main app only
ever speaks the JSON-line protocol; it never reads the signing key."""
import atexit
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class SignerUnavailable(Exception):
    pass


class SignerClient:
    def __init__(self, host: str, port: int, timeout: float = 2.0):
        self.host, self.port, self.timeout = host, int(port or 0), timeout

    def request(self, obj: dict) -> dict:
        if self.port <= 0:
            raise SignerUnavailable("signer not configured")
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall((canonical(obj) + "\n").encode())
                line = s.makefile("rb").readline()
                if not line:
                    raise SignerUnavailable("empty reply from signer")
                reply = json.loads(line.decode())
                if type(reply) is not dict:
                    raise SignerUnavailable('malformed reply from signer')
                return reply
        except (OSError, ValueError) as e:
            raise SignerUnavailable(str(e))


class SignerManager:
    """Launches/owns the signer subprocess (app startup or tests)."""

    def __init__(self, state_dir: str, port: int = 0):
        self.state_dir = str(state_dir)
        self.port = int(port)
        self.proc = None
        self.start()

    def start(self):
        pf = Path(tempfile.mkdtemp(prefix="aegis-signer-")) / "signer.port"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "aegis.signer", "--state-dir", self.state_dir,
             "--port-file", str(pf), "--port", str(self.port),
             "--owner-pid", str(os.getpid())],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        atexit.register(self.stop)
        try:
            self._wait_ready(pf)
        except BaseException:
            self.stop()
            raise

    def _wait_ready(self, pf):
        deadline = time.monotonic() + 15
        failure = "signer did not write its port file"
        while True:
            if self.proc.poll() is not None:
                raise SignerUnavailable("signer process exited at startup; " + failure)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SignerUnavailable(failure)
            try:
                text = pf.read_text().strip()
            except FileNotFoundError:
                failure = "signer did not write its port file"
            except (OSError, UnicodeError) as exc:
                failure = "signer could not read its port file: " + str(exc)
            else:
                if (not text.isascii() or not text.isdecimal() or len(text) > 5
                        or not 1 <= int(text) <= 65535):
                    failure = "signer wrote an invalid startup port: " + repr(text)
                else:
                    port = int(text)
                    failure = "signer not ready on startup port " + str(port)
                    # A numeric prefix is valid too; file existence is not readiness.
                    try:
                        reply = SignerClient("127.0.0.1", port,
                                             timeout=min(0.2, remaining)).request({"op": "ping"})
                    except SignerUnavailable as exc:
                        failure += ": " + str(exc)
                    else:
                        if reply.get("ok") is True and self.proc.poll() is None:
                            self.port = port
                            return
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def restart(self):
        self.stop()
        self.start()   # same state dir, same port -> continues its own record

    def stop(self):
        proc = self.proc
        if proc is not None:
            if proc.poll() is None:
                # The unreaped session leader pins the group identity we own.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()
        self.proc = None
        atexit.unregister(self.stop)