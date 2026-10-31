#!/bin/bash
# GhostTrace All-in-One Launcher (macOS / Linux)
# Automatically ensures Python dependencies, starts backend in background with keep-alive,
# and starts the frontend dev server.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  🚀 GhostTrace All-in-One Launcher"
echo "=============================================="

# Detect Python binary
if [ -f ".venv/bin/python3" ]; then
  PYTHON_CMD=".venv/bin/python3"
elif command -v python3 &>/dev/null; then
  PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
  PYTHON_CMD="python"
else
  echo "❌ Error: Python 3 not found. Please install Python 3.10+."
  exit 1
fi

echo "✔ Using Python: $($PYTHON_CMD --version)"

# Check if backend is already listening on port 8000
if curl -s http://127.0.0.1:8000/health &>/dev/null; then
  echo "✔ Backend is already running on http://127.0.0.1:8000"
else
  echo "▶ Starting backend supervisor on port 8000..."
  (
    while true; do
      $PYTHON_CMD -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload --log-level info
      EXIT_CODE=$?
      if [ $EXIT_CODE -eq 0 ]; then
        break
      fi
      echo "⚠️  Backend exited ($EXIT_CODE). Auto-restarting in 2s..."
      sleep 2
    done
  ) &
  BACKEND_PID=$!
  trap "kill $BACKEND_PID 2>/dev/null" EXIT
fi

# Start frontend
echo "▶ Starting frontend..."
npm --prefix frontend run dev
