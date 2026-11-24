
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ToolsRoot = 'D:\ThreatTraceTools'
$env:TEMP = Join-Path $ToolsRoot 'temp'
$env:TMP = $env:TEMP
$env:PIP_CACHE_DIR = Join-Path $ToolsRoot 'cache\pip'
$env:npm_config_cache = Join-Path $ToolsRoot 'cache\npm'
$env:PYTHONPYCACHEPREFIX = Join-Path $ToolsRoot 'cache\pycache'
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $ToolsRoot 'browsers'
$env:PYTHONUTF8 = '1'
New-Item -ItemType Directory -Force -Path $env:TEMP,$env:PIP_CACHE_DIR,$env:npm_config_cache,$env:PYTHONPYCACHEPREFIX | Out-Null
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$NpmCli = Join-Path $ToolsRoot 'npm\package\bin\npm-cli.js'

function Invoke-Checked {
    param([string]$Program, [Parameter(ValueFromRemainingArguments)] [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with code $LASTEXITCODE." }
}

function Invoke-Npm {
    param([Parameter(ValueFromRemainingArguments)] [string[]]$Arguments)
    if (Get-Command npm.cmd -ErrorAction SilentlyContinue) {
        Invoke-Checked npm.cmd @Arguments
    } elseif (Test-Path -LiteralPath $NpmCli) {
        Invoke-Checked node $NpmCli @Arguments
    } else {
        throw 'npm is unavailable. Run scripts/setup.ps1.'
    }
}

function Assert-Python {
    if (!(Test-Path -LiteralPath $Python)) { throw 'Python environment is missing. Run scripts/setup.ps1.' }
}
