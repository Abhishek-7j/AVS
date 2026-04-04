$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
py -3 -m venv .venv
& ".\.venv\Scripts\pip.exe" install --upgrade pip
& ".\.venv\Scripts\pip.exe" install -r requirements.txt
Write-Host "Done. Install Nmap from https://nmap.org/download.html and ensure `nmap` is on PATH."
