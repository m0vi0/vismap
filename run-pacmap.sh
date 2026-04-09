#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT/client"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build

cd "$ROOT"
PYTHON_BIN="python3"
if [ -x "$ROOT/venv/bin/python" ]; then
  PYTHON_BIN="$ROOT/venv/bin/python"
fi

"$PYTHON_BIN" server.py "$@"
