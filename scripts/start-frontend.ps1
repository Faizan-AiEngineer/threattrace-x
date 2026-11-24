
param([int]$Port = 5173, [int]$ApiPort = 8000, [switch]$Preview)
. "$PSScriptRoot/common.ps1"
$env:TTX_API_TARGET = "http://127.0.0.1:$ApiPort"
Push-Location (Join-Path $ProjectRoot 'frontend')
try {
    $vite = Join-Path (Get-Location).Path 'node_modules\vite\bin\vite.js'
    if (!(Test-Path -LiteralPath $vite)) { throw 'Frontend dependencies are missing. Run scripts/setup.ps1.' }
    if ($Preview) {
        Invoke-Npm run build
        Invoke-Checked node $vite preview --host 127.0.0.1 --strictPort --port $Port
    } else {
        Invoke-Checked node $vite --host 127.0.0.1 --strictPort --port $Port
    }
} finally { Pop-Location }
