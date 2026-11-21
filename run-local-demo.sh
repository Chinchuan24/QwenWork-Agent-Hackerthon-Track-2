#!/bin/sh
# Offline runtime discovery only. Never installs packages or reads .env files.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${TWINGUARD_LOCAL_PYTHON:-}" ]; then
    PYTHON=$TWINGUARD_LOCAL_PYTHON
elif [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON=$ROOT/.venv/bin/python
elif [ -x /Users/chin/Qwen/aegis/.venv/bin/python ]; then
    PYTHON=/Users/chin/Qwen/aegis/.venv/bin/python
else
    printf '%s\n' 'Offline prerequisite missing: set TWINGUARD_LOCAL_PYTHON to a trusted installed Python 3.12 with requirements.txt packages. No installation attempted.' >&2
    exit 1
fi
exec "$PYTHON" -I "$ROOT/scripts/local_demo.py" "$@"
