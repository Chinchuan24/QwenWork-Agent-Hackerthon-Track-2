"""One command starts everything:  python run.py  (default port 8080).
AEGIS_HOST defaults to 127.0.0.1; containers set it to 0.0.0.0.
Refuses to start without an evidence encryption key (says why)."""
import os
import sys

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("AEGIS_PORT", "8080"))
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    from aegis import evidence
    from aegis.app import startup
    try:
        startup()
    except evidence.EvidenceKeyError as e:
        print(f"Twinguard refused to start: {e}", file=sys.stderr)
        sys.exit(1)
    uvicorn.run("aegis.app:app", host=host, port=port, log_level="info")