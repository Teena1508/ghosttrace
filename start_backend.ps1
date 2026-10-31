Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   GhostTrace Backend Launcher (Windows PowerShell)" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

