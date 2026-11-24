
. "$PSScriptRoot/common.ps1"
Get-PSDrive -Name C,D | Select-Object Name,@{Name='FreeGiB';Expression={[math]::Round($_.Free / 1GB, 2)}} | Format-Table
$locations = @($ProjectRoot,(Join-Path $ProjectRoot '.venv'),(Join-Path $ProjectRoot 'frontend\node_modules'),$env:PIP_CACHE_DIR,
    $env:npm_config_cache,$env:PYTHONPYCACHEPREFIX,$env:TEMP)
foreach ($target in $locations) {
    if (Test-Path -LiteralPath $target) {
        $item = Get-Item -LiteralPath $target
        $bytes = if ($item.PSIsContainer) {
            (Get-ChildItem -LiteralPath $target -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        } else { $item.Length }
        [pscustomobject]@{ Location = $target; MiB = [math]::Round($bytes / 1MB, 2) }
    }
}
if (Test-Path -LiteralPath $Python) { Invoke-Checked $Python -m pip cache dir }
if ((Get-Command npm.cmd -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $NpmCli)) { Invoke-Npm config get cache }
