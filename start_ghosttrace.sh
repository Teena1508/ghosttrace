#!/bin/bash
# GhostTrace Auto-Restart Backend Launcher
# Keeps backend online — restarts automatically on crash.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔴 GhostTrace Backend Keep-Alive Launcher"
echo "   Working dir: $SCRIPT_DIR"
echo "   Press Ctrl+C to stop."
echo ""

while true; do
  echo "[$(date '+%H:%M:%S')] ▶ Starting backend on port 8000..."
  .venv/bin/python3 -m uvicorn backend.app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info

  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 0 ]; then
    echo "[$(date '+%H:%M:%S')] ✅ Backend stopped cleanly. Exiting."
    break
  else
    echo "[$(date '+%H:%M:%S')] ⚠️  Backend exited with code $EXIT_CODE. Restarting in 3s..."
    sleep 3
  fi
done

