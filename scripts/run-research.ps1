
param([int]$Seed = 42, [int[]]$Sizes = @(1000,10000,50000,100000))
. "$PSScriptRoot/common.ps1"
Assert-Python
$prior = $env:TTX_DATA_DIR
$priorDb = $env:TTX_DATABASE_URL
$env:TTX_DATA_DIR = Join-Path $ProjectRoot 'runtime\research'
Remove-Item Env:TTX_DATABASE_URL -ErrorAction SilentlyContinue
Push-Location (Join-Path $ProjectRoot 'backend')
try { Invoke-Checked $Python -m app.research --seed $Seed --sizes @Sizes }
finally {
    Pop-Location
    $env:TTX_DATA_DIR = $prior
    $env:TTX_DATABASE_URL = $priorDb
}
