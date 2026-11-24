
. "$PSScriptRoot/common.ps1"
$pythonVersion = & python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))"
if ($LASTEXITCODE -ne 0 -or $pythonVersion -ne '3.13') { throw 'Python 3.13 is required.' }
$nodeVersion = & node -p "process.versions.node"
if ($LASTEXITCODE -ne 0 -or [version]$nodeVersion -lt [version]'22.12.0') { throw 'Node.js 22.12 or newer is required.' }
Push-Location -LiteralPath $ProjectRoot
try {
    if (!(Test-Path -LiteralPath $Python)) { Invoke-Checked python -m venv .venv }
    if (!(Get-Command npm.cmd -ErrorAction SilentlyContinue) -and !(Test-Path -LiteralPath $NpmCli)) {
        $archive = Join-Path $env:TEMP 'threattrace-npm-12.2.3.tgz'
        $directory = Join-Path $ToolsRoot 'npm'
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        $package = Invoke-RestMethod 'https://registry.npmjs.org/npm/12.2.3'
        Invoke-WebRequest $package.dist.tarball -OutFile $archive
        $bytes = [IO.File]::ReadAllBytes($archive)
        $algorithm = [Security.Cryptography.SHA512]::Create()
        try { $digest = 'sha512-' + [Convert]::ToBase64String($algorithm.ComputeHash($bytes)) }
        finally { $algorithm.Dispose() }
        if ($digest -ne $package.dist.integrity) { throw 'npm package digest did not match the registry metadata.' }
        Invoke-Checked tar.exe -xzf $archive -C $directory
        Remove-Item -LiteralPath $archive
    }
    Invoke-Checked $Python -m pip install -r backend/requirements-dev.txt
    Invoke-Checked $Python -m pip check
    Push-Location frontend
    try { Invoke-Npm ci --no-fund }
    finally { Pop-Location }
    Write-Host "Python environment on D: $Python"
    Write-Host "npm cache on D: $env:npm_config_cache"
} finally { Pop-Location }
