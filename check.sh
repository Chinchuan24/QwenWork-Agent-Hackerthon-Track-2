#!/bin/zsh
# One command runs every automated check: tests + dependency audit.
set -e
cd "$(dirname "$0")"
echo "== tests =="
.venv/bin/python -m pytest tests -q
echo "== dependency audit =="
if .venv/bin/pip-audit --version >/dev/null 2>&1; then
  .venv/bin/pip-audit
else
  echo "pip-audit not installed; run: .venv/bin/pip install pip-audit"
  exit 1
fi
echo "== all checks passed =="