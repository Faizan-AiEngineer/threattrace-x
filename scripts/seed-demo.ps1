
param([string]$Username = 'demo-investigator', [int]$Seed = 42, [switch]$AdminOnly)
. "$PSScriptRoot/common.ps1"
Assert-Python
$action = if ($AdminOnly) { 'admin' } else { 'seed' }
Push-Location (Join-Path $ProjectRoot 'backend')
try { Invoke-Checked $Python -m app.demo $action --username $Username --seed $Seed }
finally { Pop-Location }
