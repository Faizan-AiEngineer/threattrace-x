
param([switch]$BackendOnly)
. "$PSScriptRoot/common.ps1"
Assert-Python
function Wait-TestService([string]$Url, $Service) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($Service.HasExited) { throw "Test service exited at $Url." }
        try { Invoke-WebRequest $Url -TimeoutSec 1 -UseBasicParsing | Out-Null; return }
        catch { Start-Sleep -Milliseconds 300 }
    }
    throw "Test service failed to start at $Url."
}
Push-Location (Join-Path $ProjectRoot 'backend')
try {
    Invoke-Checked $Python -m pytest -q
    Invoke-Checked $Python -m ruff check .
} finally { Pop-Location }
if ($BackendOnly) { return }
$prior = @{}
foreach ($name in @('TTX_DATA_DIR','TTX_DATABASE_URL','TTX_SETUP_PASSWORD','TTX_TEST_PASSWORD','TTX_BROWSER_URL','TTX_ORIGINS')) {
    $prior[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
}
$env:TTX_DATA_DIR = Join-Path $ProjectRoot ('runtime\browser-tests\' + [guid]::NewGuid().ToString('N'))
$env:TTX_TEST_PASSWORD = [guid]::NewGuid().ToString('N')
$env:TTX_SETUP_PASSWORD = $env:TTX_TEST_PASSWORD
$env:TTX_BROWSER_URL = 'http://127.0.0.1:55173'
$env:TTX_ORIGINS = $env:TTX_BROWSER_URL
Remove-Item Env:TTX_DATABASE_URL -ErrorAction SilentlyContinue
$runner = (Get-Process -Id $PID).Path
$backend = $frontend = $null
try {
    & (Join-Path $PSScriptRoot 'seed-demo.ps1')
    Remove-Item Env:TTX_SETUP_PASSWORD
    $backend = Start-Process -FilePath $runner -ArgumentList ('-NoProfile -File "{0}" -Port 58000' -f (Join-Path $PSScriptRoot 'start-backend.ps1')) -WindowStyle Hidden -PassThru -WorkingDirectory $ProjectRoot
    Wait-TestService 'http://127.0.0.1:58000/api/v1/health' $backend
    $frontend = Start-Process -FilePath $runner -ArgumentList ('-NoProfile -File "{0}" -Port 55173 -ApiPort 58000' -f (Join-Path $PSScriptRoot 'start-frontend.ps1')) -WindowStyle Hidden -PassThru -WorkingDirectory $ProjectRoot
    Wait-TestService $env:TTX_BROWSER_URL $frontend
    Push-Location (Join-Path $ProjectRoot 'frontend')
    try {
        if (!(Test-Path -LiteralPath 'C:\Program Files\Google\Chrome\Application\chrome.exe')) {
            Invoke-Checked node (Join-Path (Get-Location).Path 'node_modules\@playwright\test\cli.js') install chromium
        }
        Invoke-Npm run lint
        Invoke-Npm run build
        Invoke-Npm test
    } finally { Pop-Location }
} finally {
    foreach ($service in @($frontend,$backend)) {
        if ($service -and !$service.HasExited) { & taskkill.exe /PID $service.Id /T /F | Out-Null }
    }
    foreach ($name in $prior.Keys) { [Environment]::SetEnvironmentVariable($name,$prior[$name],'Process') }
}
