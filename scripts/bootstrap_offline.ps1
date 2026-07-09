[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$VenvDir = ".venv",
    [string]$Wheelhouse = ".wheelhouse"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $PathValue))
}

$VenvPath = Resolve-RepoPath $VenvDir
$WheelhousePath = Resolve-RepoPath $Wheelhouse
$LockFile = Join-Path $RepoRoot "requirements-offline-test.lock"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $LockFile -PathType Leaf)) {
    throw "Offline lock file is missing: $LockFile"
}
if (-not (Test-Path -LiteralPath $WheelhousePath -PathType Container)) {
    throw "Offline wheelhouse is missing: $WheelhousePath"
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    & $Python -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment: $VenvPath"
    }
}

$BootstrapTemp = Join-Path $VenvPath ".bootstrap-tmp"
New-Item -ItemType Directory -Force -Path $BootstrapTemp | Out-Null
$env:TEMP = $BootstrapTemp
$env:TMP = $BootstrapTemp

& $VenvPython -m pip install --no-cache-dir --no-index --find-links $WheelhousePath --require-hashes -r $LockFile
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install the locked offline dependencies."
}

& $VenvPython -m pip install --no-cache-dir --no-index --find-links $WheelhousePath --no-deps --no-build-isolation --editable $RepoRoot
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install BELIEF from the local checkout."
}

& $VenvPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "pip check failed for the offline environment."
}

Write-Host "Offline BELIEF environment is ready: $VenvPython"
