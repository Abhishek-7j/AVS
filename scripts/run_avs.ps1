# Run AVS GUI from repo root (AutoVulnScanner folder).
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Create venv first: py -3 -m venv .venv; .\.venv\Scripts\pip install -r requirements.txt"
    exit 1
}
& ".\.venv\Scripts\python.exe" main.py
