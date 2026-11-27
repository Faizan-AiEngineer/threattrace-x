param([int]$BackendPort = 8000, [int]$FrontendPort = 5173, [int]$Seed = 42)
. "$PSScriptRoot/common.ps1"
Assert-Python

$previous = @{}
foreach ($name in @('TTX_DATA_DIR','TTX_DATABASE_URL','TTX_ORIGINS','TTX_SETUP_PASSWORD','TTX_SECURE_COOKIE')) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
}
try {
    $env:TTX_DATA_DIR = Join-Path $ProjectRoot 'runtime\demo'
    $env:TTX_ORIGINS = "http://127.0.0.1:$FrontendPort,http://localhost:$FrontendPort"
    $env:TTX_SECURE_COOKIE = '0'
    Remove-Item Env:TTX_DATABASE_URL,Env:TTX_SETUP_PASSWORD -ErrorAction SilentlyContinue
    & (Join-Path $PSScriptRoot 'seed-demo.ps1') -Seed $Seed
    & (Join-Path $PSScriptRoot 'start-all.ps1') -BackendPort $BackendPort -FrontendPort $FrontendPort
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name,$previous[$name],'Process')
    }
}
