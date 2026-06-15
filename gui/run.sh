#!/usr/bin/env bash
# FastIR Collector GUI launcher (macOS/Linux, for development against the demo stub).
# Note: a REAL collection requires Windows + admin + Python 2; on other OSes use
# the bundled demo stub via the Settings panel.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
backend="$root/backend"
frontend="$root/frontend"
port=8099

echo "==> FastIR Collector GUI"

venvpy="$backend/.venv/bin/python"
if [ ! -x "$venvpy" ]; then
  echo "==> Creating backend virtualenv..."
  python3 -m venv "$backend/.venv"
  "$venvpy" -m pip install --upgrade pip >/dev/null
fi
echo "==> Installing backend dependencies..."
"$venvpy" -m pip install -q -r "$backend/requirements.txt"

if [ ! -d "$frontend/dist" ] || [ "${1:-}" = "--rebuild" ]; then
  if command -v npm >/dev/null 2>&1; then
    echo "==> Building frontend..."
    ( cd "$frontend" && [ -d node_modules ] || npm install; npm run build )
  else
    echo "!! npm not found - serving API only (no built UI)."
  fi
fi

echo "==> Starting server at http://127.0.0.1:$port"
cd "$backend"
exec "$venvpy" -m uvicorn app:app --host 127.0.0.1 --port "$port"
