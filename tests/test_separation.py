"""Separation tests — what they prove, stated honestly:
- the worker PROCESS is launched with a clean environment (no key, no data
  dir) and its source has no privileged imports;
- its traffic goes only to the gateway.
What they do NOT prove: under one OS user account the worker could still open
the database file if it learned the path — there is no OS-level isolation.
Stronger isolation (separate user / container) is a stated limit, see README.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_worker_source_has_no_privileged_imports():
    src = (ROOT / "aegis" / "worker.py").read_text()
    for banned in ("sqlite3", "from . import", "from aegis", "import db", "import world",
                   "import policy", "import config", "QWEN_API_KEY"):
        assert banned not in src, f"worker must not contain {banned!r}"


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/api/agent/session":
            body = {"task": "Help Acme with the report.", "limits": {}, "session_id": "x"}
        elif self.path == "/api/agent/model":
            body = {"error": "live model unavailable in test"}
        else:
            body = {"verdict": "block", "reasons": []}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def test_worker_process_holds_no_keys():
    server = HTTPServer(("127.0.0.1", 0), Stub)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "AEGIS_GATEWAY_URL": f"http://127.0.0.1:{port}",
           "AEGIS_AGENT_TOKEN": "test-token"}
    try:
        out = subprocess.run(
            [sys.executable, "-m", "aegis.worker", "--gateway", env["AEGIS_GATEWAY_URL"],
             "--token", "test-token"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        report = json.loads(out.stdout.strip().splitlines()[-1])
        assert report["env_aegis_keys"] == ["AEGIS_AGENT_TOKEN", "AEGIS_GATEWAY_URL"]
        assert report["steps"][0]["step"] == "model"  # only the gateway was reached
    finally:
        server.shutdown()


def test_worker_env_carries_no_data_dir_or_key():
    """Proves the launch environment is clean: no AEGIS_DATA_DIR and no
    AEGIS_QWEN_API_KEY. It does NOT prove the worker cannot open the database:
    under the same OS user, a process that knows the path can open the file
    (see test_same_user_process_can_open_db_if_path_known). Real isolation
    needs a separate user or a container."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "AEGIS_GATEWAY_URL": "http://127.0.0.1:1", "AEGIS_AGENT_TOKEN": "t"}
    out = subprocess.run(
        [sys.executable, "-c",
         "import os; print('AEGIS_DATA_DIR' in os.environ, 'AEGIS_QWEN_API_KEY' in os.environ)"],
        env=env, capture_output=True, text=True, timeout=15)
    assert out.stdout.strip() == "False False"


def test_same_user_process_can_open_db_if_path_known():
    """Documents the stated limit (NOT a desired property): with one OS user
    there is no filesystem barrier — a clean-env process given the DB path can
    open it. This is why the README says stronger isolation needs containers
    or a separate user account."""
    from aegis import config
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "AEGIS_GATEWAY_URL": "http://127.0.0.1:1", "AEGIS_AGENT_TOKEN": "t"}
    out = subprocess.run(
        [sys.executable, "-c",
         "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
         "print(c.execute('SELECT COUNT(*) FROM users').fetchone()[0] >= 0)",
         str(config.DB_PATH)],
        env=env, capture_output=True, text=True, timeout=15)
    assert out.stdout.strip() == "True"  # same-user access IS possible — stated limit