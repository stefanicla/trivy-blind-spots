<#
.SYNOPSIS
    Copies a repository and generates the lock files Trivy needs, so that projects which do
    not commit lock files can still be assessed.

.DESCRIPTION
    Trivy cannot assess:
      C#      .csproj PackageReference without packages.lock.json
      Python  pyproject.toml without a lock file; requirements.txt with ranges (>=, ~=)
      Node    package.json without package-lock.json / yarn.lock / pnpm-lock.yaml / bun.lock
    This script copies the source tree (without .git) to workspace/<name>-locked and, for
    every such project found, generates a lock file inside a pinned container:
      C#      dotnet restore -p:RestorePackagesWithLockFile=true   (packages.lock.json)
      Python  uv lock / uv pip compile, binary wheels only            (uv.lock / requirements.txt)
      Node    npm install --package-lock-only --ignore-scripts      (package-lock.json)

    SECURITY: the copy is untrusted code. npm and uv run with scripts and source builds
    disabled, but `dotnet restore` evaluates MSBuild project files, which can execute
    arbitrary code. Everything runs in a throw-away container that sees only the copy and
    no credentials; still, only use this on code you are entitled to assess.

    CAVEAT: the resolved versions are those available today, which may differ from what is
    actually built and deployed. Report findings as "assessed with a generated lock file".

.EXAMPLE
    .\scripts\New-LockFile.ps1 -Source .\workspace\WebGoat.NET
    .\scripts\Invoke-TrivyScan.ps1 -Target .\workspace\WebGoat.NET-locked -Method fs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Source,

    [string]$Destination
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Images = @{
    dotnet = 'mcr.microsoft.com/dotnet/sdk:8.0@sha256:ff39a765f04619c8d146796fc09b38499ae5984f4a2a4c3a0a57d0022855daee'
    python = 'python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
    node   = 'node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$Source = (Resolve-Path $Source).Path
if (-not $Destination) {
    $Destination = Join-Path $repoRoot ("workspace\" + (Split-Path -Leaf $Source) + '-locked')
}
if (Test-Path $Destination) { throw "$Destination already exists; remove it first." }

Write-Host "Copying $Source -> $Destination"
robocopy $Source $Destination /E /XD .git node_modules bin obj .venv venv /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

function Invoke-InContainer([string]$Image, [string]$Dir, [string]$Script) {
    $rel = [IO.Path]::GetRelativePath($Destination, $Dir) -replace '\\', '/'
    Write-Host "  [$rel] $Script"
    # Hardened throw-away container: only the copy is mounted, no credentials, no Linux
    # capabilities, no privilege escalation, bounded resources. Network stays on because
    # the package registries are needed.
    docker run --rm --network bridge --cap-drop ALL --security-opt no-new-privileges `
        --pids-limit 512 --memory 4g --cpus 2 -v "${Destination}:/w" -w "/w/$rel" `
        -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -e PIP_DISABLE_PIP_VERSION_CHECK=1 `
        $Image sh -c $Script
    if ($LASTEXITCODE -ne 0) { Write-Warning "Lock generation failed in $rel (exit code $LASTEXITCODE)" }
}

$files = Get-ChildItem $Destination -Recurse -File
$generated = 0

# C#: one restore per project without a lock file next to it.
foreach ($proj in $files | Where-Object Extension -eq '.csproj') {
    if (-not (Test-Path (Join-Path $proj.DirectoryName 'packages.lock.json'))) {
        Invoke-InContainer $Images.dotnet $proj.DirectoryName `
            "dotnet restore '$($proj.Name)' -p:RestorePackagesWithLockFile=true -p:NuGetAudit=false -p:TreatWarningsAsErrors=false >/dev/null; rm -rf obj bin; ls packages.lock.json"
        $generated++
    }
}

# Python: pyproject.toml without any lock file; requirements files containing ranges.
$pyLocks = 'uv.lock', 'poetry.lock', 'Pipfile.lock', 'pdm.lock'
foreach ($pp in $files | Where-Object Name -eq 'pyproject.toml') {
    if (-not ($pyLocks | Where-Object { Test-Path (Join-Path $pp.DirectoryName $_) }) -and
        (Select-String -Path $pp.FullName -Pattern '^\s*dependencies\s*=' -Quiet)) {
        Invoke-InContainer $Images.python $pp.DirectoryName 'pip install -q uv 2>/dev/null && uv lock --no-build -q; ls uv.lock'
        $generated++
    }
}
foreach ($req in $files | Where-Object { $_.Name -like 'requirements*.txt' }) {
    if (Select-String -Path $req.FullName -Pattern '^[^#\s-][^=]*(>=|~=|<|>|!=)|^[A-Za-z0-9_.\[\]-]+\s*$' -Quiet) {
        $out = $req.BaseName + '.locked.txt'
        Invoke-InContainer $Images.python $req.DirectoryName "pip install -q uv 2>/dev/null && uv pip compile -q --no-build --python-version 3.12 '$($req.Name)' -o '$out'; ls '$out'"
        $generated++
    }
}

# Node: package.json without any lock file (skipping workspace members, which share the root lock).
$nodeLocks = 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'
foreach ($pj in $files | Where-Object Name -eq 'package.json') {
    $dir = $pj.DirectoryName
    $hasLock = $false
    while ($dir -and $dir.Length -ge $Destination.Length) {
        if ($nodeLocks | Where-Object { Test-Path (Join-Path $dir $_) }) { $hasLock = $true; break }
        $dir = Split-Path -Parent $dir
    }
    if (-not $hasLock) {
        Invoke-InContainer $Images.node $pj.DirectoryName 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps >/dev/null 2>&1; ls package-lock.json'
        $generated++
    }
}

Write-Host "Lock generation attempted for $generated project(s). Scan with:"
Write-Host "  .\scripts\Invoke-TrivyScan.ps1 -Target '$Destination' -Method fs"
