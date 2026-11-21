"""Submission files must not embed a developer's Mac home path."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MARKER = b'/' + b'Users' + b'/'


def test_tracked_files_have_no_mac_home_paths():
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    offending = []
    for raw in paths:
        if raw:
            path = ROOT / raw.decode()
            if path.is_file() and MARKER in path.read_bytes():
                offending.append(raw.decode())
    assert not offending, f'Mac-specific paths in tracked files: {offending}'
