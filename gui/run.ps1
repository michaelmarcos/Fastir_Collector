# FastIR Collector GUI launcher (Windows).
# Sets up the backend venv, builds the frontend if needed, and starts the app.
# Run AS ADMINISTRATOR if you intend to perform a real collection.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$port = 8099

Write-Host "==> FastIR Collector GUI" -ForegroundColor Green

# --- backend venv ---
$venvPy = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "==> Creating backend virtualenv..." -ForegroundColor Cyan
    python -m venv (Join-Path $backend ".venv")
    & $venvPy -m pip install --upgrade pip | Out-Null
}
Write-Host "==> Installing backend dependencies..." -ForegroundColor Cyan
& $venvPy -m pip install -q -r (Join-Path $backend "requirements.txt")

# --- frontend build (skip if dist exists; pass -Rebuild to force) ---
$dist = Join-Path $frontend "dist"
if ((-not (Test-Path $dist)) -or ($args -contains "-Rebuild")) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host "==> Building frontend..." -ForegroundColor Cyan
        Push-Location $frontend
        if (-not (Test-Path (Join-Path $frontend "node_modules"))) { npm install }
        npm run build
        Pop-Location
    } else {
        Write-Host "!! npm not found - serving API only (no built UI)." -ForegroundColor Yellow
    }
}

# --- launch ---
$url = "http://127.0.0.1:$port"
Write-Host "==> Starting server at $url" -ForegroundColor Green
Start-Process $url
Push-Location $backend
try {
    & $venvPy -m uvicorn app:app --host 127.0.0.1 --port $port
} finally {
    Pop-Location
}
