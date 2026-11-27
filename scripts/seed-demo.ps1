
param([string]$Username = 'demo-investigator', [int]$Seed = 42, [switch]$AdminOnly)
. "$PSScriptRoot/common.ps1"
Assert-Python
$action = if ($AdminOnly) { 'admin' } else { 'seed' }
$priorDataDir = $env:TTX_DATA_DIR
if (!$AdminOnly -and !$env:TTX_DATA_DIR) { $env:TTX_DATA_DIR = Join-Path $ProjectRoot 'runtime\demo' }
Push-Location (Join-Path $ProjectRoot 'backend')
try { Invoke-Checked $Python -m app.demo $action --username $Username --seed $Seed }
finally {
    Pop-Location
    $env:TTX_DATA_DIR = $priorDataDir
}
