"""Separate audit signer — its OWN process. The main app asks it to sign; the
main app never reads the signing key. The signer keeps a forward-only record
of every signed checkpoint in its own state directory (outside the data
folder, owner-only permissions).

Run: python -m aegis.signer --state-dir DIR --port-file FILE [--port N]

Protocol (JSON lines over TCP on 127.0.0.1):
  {"op":"ping"}                          -> {"ok":true}
  {"op":"sign","stream":S,"body":B}      -> {"seq","sig","prev_sig"} or {"error"}
  {"op":"latest","stream":S}             -> latest record or {"seq":0}
  {"op":"reload"}                        -> re-read the record from disk
  {"op":"shutdown"}                      -> stop the process
Anything else (including "key") is refused. The key is never returned.

Ordering is by sequence number, never by clock — a backwards clock cannot
reorder the chain. Sign requests are forward-only per stream: a smaller
count/max_id is refused, and a rewrite at the same position is refused.
"""
import argparse
import fcntl
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import socketserver
import threading
import tempfile
import re
from pathlib import Path

_LOCK = threading.RLock()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class SignerState:
    def __init__(self, state_dir):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.key_file = self.dir / "signing.key"
        self.rec_file = self.dir / "records.jsonl"
        with self.lock():
            if self.key_file.exists():
                self.key = bytes.fromhex(self.key_file.read_text().strip())
            else:
                self.key = os.urandom(32)
                with open(self.key_file, 'x') as handle:
                    os.chmod(self.key_file, 0o600)
                    handle.write(self.key.hex())
                    handle.flush()
                    os.fsync(handle.fileno())
                self._sync_directory()
            os.chmod(self.key_file, 0o600)
            self._load()

    @contextmanager
    def lock(self):
        with _LOCK, open(self.dir / 'state.lock', 'a') as handle:
            os.chmod(self.dir / 'state.lock', 0o600)
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _sync_directory(self):
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _load(self):
        self.latest = {}
        self.records = {}
        if self.rec_file.exists():
            for line in self.rec_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                    s = r['stream']
                    last = self.latest.get(s)
                    previous = last['sig'] if last else 'genesis'
                    expected = hmac.new(self.key, canonical({
                        'stream': s, 'seq': r['seq'], 'body': r['body']
                    }).encode(), hashlib.sha256).hexdigest()
                    b = r['body']
                    if (type(s) is not str or not s or type(b) is not dict
                            or type(b.get('count')) is not int or b['count'] <= 0
                            or type(b.get('max_id')) is not int or b['max_id'] < b['count']
                            or type(b.get('last_hash')) is not str
                            or re.fullmatch(r'[0-9a-f]{64}', b['last_hash']) is None
                            or type(r['seq']) is not int
                            or r['seq'] != (last['seq'] + 1 if last else 1)
                            or r['prev_sig'] != previous
                            or r['body']['prev_sig'] != previous
                            or not hmac.compare_digest(expected, r['sig'])
                            or (last and (r['body']['count'] <= last['body']['count']
                                or r['body']['max_id'] <= last['body']['max_id']))):
                        raise ValueError('Invalid signer history')
                except (ValueError, KeyError, TypeError) as exc:
                    raise ValueError('Invalid signer history') from exc
                self.records.setdefault(s, {})[r['seq']] = r
                self.latest[s] = r

    def sign(self, stream, body):
        if (type(stream) is not str or not stream or type(body) is not dict
                or type(body.get('count')) is not int or body['count'] <= 0
                or type(body.get('max_id')) is not int or body['max_id'] < body['count']
                or type(body.get('last_hash')) is not str
                or re.fullmatch(r'[0-9a-f]{64}', body['last_hash']) is None):
            return {"error": "bad sign request"}
        with self.lock():
            self._load()
            last = self.latest.get(stream)
            if last:
                lb = last["body"]
                if body["count"] < lb["count"] or body["max_id"] < lb["max_id"]:
                    return {"error": "regression refused: signer record is forward-only"}
                if body["count"] == lb["count"] and body["max_id"] == lb["max_id"]:
                    if body["last_hash"] == lb["last_hash"]:
                        with open(self.rec_file, 'rb') as handle:
                            os.fsync(handle.fileno())
                        self._sync_directory()
                        return {"seq": last["seq"], "sig": last["sig"],
                                "prev_sig": last["prev_sig"], "body": last["body"]}
                    return {"error": "rewrite refused: same position, different hash"}
                if body["count"] == lb["count"] or body["max_id"] == lb["max_id"]:
                    return {"error": "partial advance refused: count and max_id must both advance"}
            seq = (last["seq"] + 1) if last else 1
            prev_sig = last["sig"] if last else "genesis"
            signed_body = {**body, "prev_sig": prev_sig}
            sig = hmac.new(self.key,
                           canonical({"stream": stream, "seq": seq,
                                      "body": signed_body}).encode(),
                           hashlib.sha256).hexdigest()
            rec = {"stream": stream, "seq": seq, "body": signed_body, "sig": sig,
                   "prev_sig": prev_sig}
            with open(self.rec_file, "a") as f:
                os.chmod(self.rec_file, 0o600)
                f.write(canonical(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._sync_directory()
            self.latest[stream] = rec
            self.records.setdefault(stream, {})[seq] = rec
            return {"seq": seq, "sig": sig, "prev_sig": prev_sig, "body": signed_body}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            try:
                req = json.loads(line.decode())
            except (ValueError, UnicodeDecodeError):
                self._send({"error": "bad json"})
                continue
            op = req.get("op")
            if op == "ping":
                self._send({"ok": True})
            elif op == "sign":
                self._send(self.server.state.sign(req.get("stream", ""), req.get("body")))
            elif op == "latest":
                with self.server.state.lock():
                    self.server.state._load()
                    r = self.server.state.latest.get(req.get("stream", ""))
                self._send(r if r else {"seq": 0})
            elif op == "verify_batch":
                with self.server.state.lock():
                    # One fresh, authenticated history for both signatures and high water mark.
                    self.server.state._load()
                    records = self.server.state.records.get(req.get("stream", ""), {})
                    results = []
                    for line in req.get("lines", []):
                        rec = (records.get(line.get("seq")) if type(line) is dict
                               and type(line.get('seq')) is int else None)
                        results.append(rec is not None and rec["sig"] == line.get("sig")
                                       and canonical(rec["body"]) == canonical(line.get("body")))
                    latest = self.server.state.latest.get(req.get("stream", ""), {"seq": 0})
                self._send({"results": results, "latest": latest})
            elif op == "verify_line":
                line = req.get("line") or {}
                with self.server.state.lock():
                    self.server.state._load()
                    rec = (self.server.state.records.get(req.get("stream", ""), {}).get(line.get("seq"))
                           if type(line) is dict and type(line.get('seq')) is int else None)
                if rec is None:
                    self._send({"ok": False, "reason": "unknown seq"})
                else:
                    ok = rec["sig"] == line.get("sig") and canonical(rec["body"]) == canonical(line.get("body"))
                    self._send({"ok": ok, "reason": "" if ok else "signature invalid"})
            elif op == "reload":
                with self.server.state.lock():
                    self.server.state._load()
                self._send({"ok": True})
            elif op == "shutdown":
                self._send({"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._send({"error": "unknown op"})

    def _send(self, obj):
        try:
            self.wfile.write((canonical(obj) + "\n").encode())
            self.wfile.flush()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()
    state = SignerState(a.state_dir)
    srv = Server(("127.0.0.1", a.port), Handler)
    srv.state = state
    port_file = Path(a.port_file)
    fd, name = tempfile.mkstemp(prefix=port_file.name + '.', dir=port_file.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(str(srv.server_address[1]))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(port_file)
        directory_fd = os.open(port_file.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()