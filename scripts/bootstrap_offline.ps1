[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$VenvDir = ".venv-offline",
    [string]$Wheelhouse = ".wheelhouse",
    [string]$LockFile = "requirements-offline-test.lock"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Offline bootstrap is validated only on Windows CPython 3.12 x64."
}

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $PathValue))
}

function Assert-Cpython312x64 {
    param(
        [Parameter(Mandatory = $true)][string]$Interpreter,
        [Parameter(Mandatory = $true)][string]$Role
    )

    $versionCheck = @'
import struct
import sys

valid = (
    sys.implementation.name == 'cpython'
    and sys.version_info[:2] == (3, 12)
    and struct.calcsize('P') * 8 == 64
)
print(sys.implementation.name, sys.version.split()[0], str(struct.calcsize('P') * 8) + '-bit')
raise SystemExit(0 if valid else 1)
'@
    $identity = & $Interpreter -I -c $versionCheck
    if ($LASTEXITCODE -ne 0) {
        throw "$Role must be CPython 3.12 x64; received: $identity"
    }
    Write-Verbose "${Role}: $identity"
}

function Get-LockedRequirements {
    param([Parameter(Mandatory = $true)][string]$LockFilePath)

    $requirements = @()
    $lineNumber = 0
    $linePattern = (
        '^(?<name>[A-Za-z0-9_.-]+)==(?<version>[A-Za-z0-9_.!+]+)' +
        '(?<hashes>(?:\s+--hash=sha256:[A-Fa-f0-9]{64})+)\s*$'
    )
    foreach ($rawLine in Get-Content -LiteralPath $LockFilePath) {
        $lineNumber += 1
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            continue
        }
        if ($line -notmatch $linePattern) {
            throw (
                "Invalid offline lock entry at line $lineNumber. " +
                "Every entry must use name==version with one or more SHA-256 --hash values."
            )
        }

        $hashes = @(
            [regex]::Matches($Matches["hashes"], '--hash=sha256:(?<hash>[A-Fa-f0-9]{64})') |
                ForEach-Object { $_.Groups["hash"].Value.ToLowerInvariant() }
        )
        $requirements += [pscustomobject]@{
            Name = $Matches["name"]
            Version = $Matches["version"]
            Hashes = $hashes
        }
    }
    if ($requirements.Count -eq 0) {
        throw "Offline lock contains no requirements: $LockFilePath"
    }
    return $requirements
}

function Normalize-DistributionName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return ($Name -replace '[-_.]', '_').ToLowerInvariant()
}

function Assert-WheelhouseMatchesLock {
    param(
        [Parameter(Mandatory = $true)][string]$WheelhousePath,
        [Parameter(Mandatory = $true)][object[]]$Requirements
    )

    $wheelFiles = @(Get-ChildItem -LiteralPath $WheelhousePath -File -Filter "*.whl")
    if ($wheelFiles.Count -eq 0) {
        throw "Offline wheelhouse contains no wheel files: $WheelhousePath"
    }

    foreach ($requirement in $Requirements) {
        $distribution = Normalize-DistributionName $requirement.Name
        $candidatePattern = (
            "^{0}-{1}-.*\.whl$" -f
            [regex]::Escape($distribution),
            [regex]::Escape($requirement.Version)
        )
        $candidates = @($wheelFiles | Where-Object { $_.Name -match $candidatePattern })
        if ($candidates.Count -eq 0) {
            throw (
                "Required wheel is missing: $($requirement.Name)==$($requirement.Version). " +
                "Expected a matching .whl in $WheelhousePath."
            )
        }

        $matchingCandidate = $false
        foreach ($candidate in $candidates) {
            $hash = (Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($requirement.Hashes -contains $hash) {
                $matchingCandidate = $true
                break
            }
        }
        if (-not $matchingCandidate) {
            throw (
                "Wheel hash mismatch for $($requirement.Name)==$($requirement.Version). " +
                "No matching wheel in $WheelhousePath satisfies the lock hash."
            )
        }
    }
}

$VenvPath = Resolve-RepoPath $VenvDir
$WheelhousePath = Resolve-RepoPath $Wheelhouse
$LockFilePath = Resolve-RepoPath $LockFile
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $LockFilePath -PathType Leaf)) {
    throw "Offline lock file is missing: $LockFilePath"
}
if (-not (Test-Path -LiteralPath $WheelhousePath -PathType Container)) {
    throw "Offline wheelhouse is missing: $WheelhousePath"
}
if (Test-Path -LiteralPath $VenvPath) {
    throw (
        "Offline bootstrap requires a fresh virtual environment. " +
        "The requested path already exists: $VenvPath. Choose a new -VenvDir."
    )
}

Assert-Cpython312x64 -Interpreter $Python -Role "Bootstrap interpreter"
$Requirements = Get-LockedRequirements -LockFilePath $LockFilePath
Assert-WheelhouseMatchesLock -WheelhousePath $WheelhousePath -Requirements $Requirements

& $Python -I -m venv $VenvPath
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create fresh virtual environment: $VenvPath"
}
if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    throw "Fresh virtual environment does not contain Python: $VenvPython"
}
$venvConfig = Get-Content -Raw -LiteralPath (Join-Path $VenvPath "pyvenv.cfg")
if ($venvConfig -notmatch '(?im)^\s*include-system-site-packages\s*=\s*false\s*$') {
    throw "Fresh virtual environment unexpectedly enables system site-packages: $VenvPath"
}
Assert-Cpython312x64 -Interpreter $VenvPython -Role "Fresh virtual environment"

$BootstrapTemp = Join-Path $VenvPath ".bootstrap-tmp"
New-Item -ItemType Directory -Force -Path $BootstrapTemp | Out-Null
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
try {
    $env:TEMP = $BootstrapTemp
    $env:TMP = $BootstrapTemp
    $pipGlobal = @("--isolated", "--disable-pip-version-check", "--no-cache-dir")
    $pipOffline = @("--no-index", "--find-links", $WheelhousePath)

    & $VenvPython -I -m pip @pipGlobal install @pipOffline --only-binary=:all: --require-hashes -r $LockFilePath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install locked offline dependency wheels from: $WheelhousePath"
    }

    & $VenvPython -I -m pip @pipGlobal install @pipOffline --no-deps --no-build-isolation --editable $RepoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install BELIEF from the local checkout: $RepoRoot"
    }

    & $VenvPython -I -m pip @pipGlobal check
    if ($LASTEXITCODE -ne 0) {
        throw "pip check failed for the offline environment."
    }
}
finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}

Write-Host "Offline BELIEF environment is ready: $VenvPython"
