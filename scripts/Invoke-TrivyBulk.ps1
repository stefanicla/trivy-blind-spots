<#
.SYNOPSIS
    Scans every target listed in a targets file and prints a summary.

.DESCRIPTION
    Targets file format: one target per line, optionally followed by a method and then
    extra Trivy arguments.
        https://github.com/OWASP/NodeGoat
        https://github.com/bridgecrewio/terragoat   repo  --skip-dirs packages
        ./workspace/fixture-local                   fs
    Blank lines and lines starting with '#' are ignored.

    A failing target is logged and skipped; it never stops the batch.
    To scan every repository of a GitHub organisation instead, use -GitHubOrg
    (requires the GitHub CLI, `gh`, authenticated).

.EXAMPLE
    .\scripts\Invoke-TrivyBulk.ps1 -Scanners vuln,secret,misconfig

.EXAMPLE
    .\scripts\Invoke-TrivyBulk.ps1 -GitHubOrg my-org -Limit 20
#>
[CmdletBinding()]
param(
    [string]$TargetsFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'targets\targets.txt'),

    [string]$GitHubOrg,
    [int]$Limit = 100,

    [string]$DefaultMethod = 'repo',

    [string[]]$Scanners,
    [string[]]$Severity,
    [string]$Server
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scanScript = Join-Path $PSScriptRoot 'Invoke-TrivyScan.ps1'
$repoRoot   = Split-Path -Parent $PSScriptRoot

if ($GitHubOrg) {
    $entries = gh repo list $GitHubOrg --limit $Limit --no-archived --json url --jq '.[].url' |
        ForEach-Object { [pscustomobject]@{ Target = $_; Method = $DefaultMethod; ExtraArgs = @() } }
}
else {
    $entries = Get-Content $TargetsFile |
        Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') } |
        ForEach-Object {
            $parts = $_.Trim() -split '\s+'
            $target = $parts[0]
            # Relative local paths are relative to the repository root, not the caller's directory.
            if ($target -notmatch '^(https?|ssh|git)://|^git@' -and -not [IO.Path]::IsPathRooted($target)) {
                $target = Join-Path $repoRoot $target
            }
            [pscustomobject]@{
                Target    = $target
                Method    = if ($parts.Count -gt 1) { $parts[1] } else { $DefaultMethod }
                ExtraArgs = if ($parts.Count -gt 2) { [string[]]$parts[2..($parts.Count - 1)] } else { @() }
            }
        }
}

$common = @{}
if ($Scanners) { $common.Scanners = $Scanners }
if ($Severity) { $common.Severity = $Severity }
if ($Server)   { $common.Server   = $Server }

$startedAt = Get-Date
$results = foreach ($e in $entries) {
    Write-Host "`n=== $($e.Target) [$($e.Method)] ===" -ForegroundColor Cyan
    try {
        & $scanScript -Target $e.Target -Method $e.Method -ExtraArgs $e.ExtraArgs @common
        [pscustomobject]@{ Target = $e.Target; Method = $e.Method; ExitCode = $LASTEXITCODE; Error = $null }
    }
    catch {
        Write-Warning "Failed: $($e.Target): $_"
        [pscustomobject]@{ Target = $e.Target; Method = $e.Method; ExitCode = -1; Error = "$_" }
    }
}

Write-Host "`n=== Batch summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

$newReports = Get-ChildItem (Join-Path $repoRoot 'reports') -Filter *.json -File |
    Where-Object { $_.LastWriteTime -ge $startedAt -and $_.Name -notmatch '\.(meta|cdx|spdx|github)\.json$' }
if ($newReports) {
    & (Join-Path $PSScriptRoot 'Convert-Report.ps1') -Path $newReports.FullName | Format-Table -AutoSize
}
