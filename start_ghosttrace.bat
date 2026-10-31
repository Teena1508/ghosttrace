@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo     GhostTrace All-in-One Launcher (Windows)
echo ===================================================

:: Check Python availability
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

:: Test if backend is already listening
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 1 -UseBasicParsing; exit 0 } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Backend is already running on http://127.0.0.1:8000.
) else (
    echo [INFO] Starting GhostTrace Backend in background...
    start "GhostTrace Backend Supervisor" /min cmd /c "python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"
)

:: Start frontend
echo [INFO] Starting GhostTrace Frontend dev server...
cd frontend
npm run dev

pause

