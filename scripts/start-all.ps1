
param([int]$BackendPort = 8000, [int]$FrontendPort = 5173)
. "$PSScriptRoot/common.ps1"
Assert-Python
$runner = (Get-Process -Id $PID).Path
$backendScript = Join-Path $PSScriptRoot 'start-backend.ps1'
$backend = Start-Process -FilePath $runner -ArgumentList ('-NoProfile -File "{0}" -Port {1}' -f $backendScript,$BackendPort) -WindowStyle Hidden -PassThru -WorkingDirectory $ProjectRoot
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:$BackendPort/api/v1/health" -TimeoutSec 1
            if ($health.status -eq 'ok') { $ready = $true; break }
        } catch {
            if ($backend.HasExited) { throw 'Backend exited. Run start-backend.ps1 directly to see its error.' }
            Start-Sleep -Milliseconds 400
        }
    }
    if (!$ready) { throw 'Backend did not become healthy.' }
    & (Join-Path $PSScriptRoot 'start-frontend.ps1') -Port $FrontendPort -ApiPort $BackendPort
} finally {
    if (!$backend.HasExited) { & taskkill.exe /PID $backend.Id /T /F | Out-Null }
}
