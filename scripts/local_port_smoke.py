"""Reserve 8000 ourselves, verify fallback and stop only the owned launcher."""
import os
from pathlib import Path
import socket
import subprocess
import time
root = Path(__file__).resolve().parents[1]
with socket.socket() as dummy:
    dummy.bind(('127.0.0.1', 8000))
    dummy.listen()
    process = subprocess.Popen([str(root / 'run-local-demo.sh')], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        line = process.stdout.readline()
        assert 'Ready http://localhost:8001 child PID' in line, line
        print(line.strip())
        subprocess.run([str(root / 'run-local-demo.sh'), 'stop'], cwd=root, check=True)
        process.wait(timeout=20)
        assert dummy.getsockname()[1] == 8000
        print('Occupied 8000 fallback passed; owned dummy remained bound; demo stopped.')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=20)
