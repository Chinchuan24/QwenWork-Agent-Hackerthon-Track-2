#!/bin/sh
# Trusted runtime discovery only. Python securely reads optional root .env.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${TWINGUARD_LOCAL_PYTHON:-}" ]; then
    PYTHON=$TWINGUARD_LOCAL_PYTHON
elif [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON=$ROOT/.venv/bin/python
elif [ -x $HOME/Qwen/aegis/.venv/bin/python ]; then
    PYTHON=$HOME/Qwen/aegis/.venv/bin/python
else
    printf '%s\n' 'Offline prerequisite missing: set TWINGUARD_LOCAL_PYTHON to a trusted installed Python 3.12 with requirements.txt packages. No installation attempted.' >&2
    exit 1
fi
exec "$PYTHON" -I "$ROOT/scripts/local_demo.py" "$@"
