<#
.SYNOPSIS
    Downloads a pinned Trivy release into tools/ and verifies its SHA-256 checksum.

.DESCRIPTION
    The version and the expected hash are pinned below on purpose: Trivy suffered a
    supply-chain compromise in March 2026 (CVE-2026-33634; malicious v0.69.4 binary,
    v0.69.5/v0.69.6 Docker Hub images). Never install "latest" and never install
    v0.69.4 - v0.69.6. To upgrade, review the release notes, then update both values.

.EXAMPLE
    .\scripts\Install-Trivy.ps1
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$TrivyVersion   = '0.76.1'
$ExpectedSha256 = '1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf'

$repoRoot = Split-Path -Parent $PSScriptRoot
$toolsDir = Join-Path $repoRoot 'tools'
$trivyExe = Join-Path $toolsDir 'trivy.exe'

if ((Test-Path $trivyExe) -and -not $Force) {
    $installed = (& $trivyExe --version | Select-String '^Version:').ToString().Split(':')[1].Trim()
    if ($installed -eq $TrivyVersion) {
        Write-Host "Trivy $TrivyVersion is already installed at $trivyExe"
        return
    }
    Write-Host "Found Trivy $installed; replacing it with the pinned $TrivyVersion"
}

$archive = "trivy_${TrivyVersion}_windows-64bit.zip"
$url     = "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVersion/$archive"
$tmpDir  = Join-Path ([IO.Path]::GetTempPath()) "trivy-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    $zipPath = Join-Path $tmpDir $archive
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

    $actual = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256) {
        throw "Checksum mismatch for $archive. Expected $ExpectedSha256, got $actual. Aborting."
    }
    Write-Host "Checksum verified: $actual"

    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    Copy-Item (Join-Path $tmpDir 'trivy.exe') $trivyExe -Force
}
finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}

& $trivyExe --version
