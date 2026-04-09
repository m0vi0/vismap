#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT/client"
if [ ! -d node_modules ]; then
  npm install
fi
npm run dev -- --host 127.0.0.1 &
VITE_PID=$!

cd "$ROOT"
PYTHON_BIN="python3"
if [ -x "$ROOT/venv/bin/python" ]; then
  PYTHON_BIN="$ROOT/venv/bin/python"
fi

cleanup() {
  kill "$VITE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PYTHON_BIN" server.py --app-url http://127.0.0.1:5173 "$@"
