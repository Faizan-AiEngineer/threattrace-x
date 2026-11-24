
param([int]$Port = 8000)
. "$PSScriptRoot/common.ps1"
Assert-Python
Push-Location (Join-Path $ProjectRoot 'backend')
try { Invoke-Checked $Python -m uvicorn app.main:app --host 127.0.0.1 --port $Port }
finally { Pop-Location }
