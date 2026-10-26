<#
.SYNOPSIS
    Summarises one or more Trivy JSON reports: findings by class and severity, top packages.

.DESCRIPTION
    Accepts report files or a directory (all *.json except *.meta.json and SBOMs).
    Output is a PowerShell object per report, or a Markdown table with -Markdown
    (ready to paste into docs/results.md).

.EXAMPLE
    .\scripts\Convert-Report.ps1 -Path .\reports -Markdown

.EXAMPLE
    .\scripts\Convert-Report.ps1 -Path .\reports\fixture-local_repo_20261026T090000Z.json -Top 10
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    # Show the N packages with the most vulnerabilities for each report.
    [int]$Top = 0,

    [switch]$Markdown
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$severities = 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'

function Get-Prop($Object, [string]$Name) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { $Object.$Name } else { $null }
}

$files = foreach ($p in $Path) {
    if (Test-Path $p -PathType Container) {
        Get-ChildItem $p -Filter *.json -File |
            Where-Object { $_.Name -notmatch '\.(meta|cdx|spdx|github)\.json$' }
    }
    else { Get-Item $p }
}

$rows = foreach ($file in ($files | Sort-Object Name)) {
    $report = Get-Content -Raw $file.FullName | ConvertFrom-Json
    if (-not (Get-Prop $report 'SchemaVersion')) { continue }   # not a Trivy JSON report

    $vulns = @(); $secrets = @(); $misconfigs = @(); $licences = @(); $suppressed = @(); $depFiles = 0
    foreach ($r in @(Get-Prop $report 'Results')) {
        if ($null -eq $r) { continue }
        # Dependency files Trivy could analyse; 0 means vulnerabilities were not assessed at all.
        if ((Get-Prop $r 'Class') -eq 'lang-pkgs') { $depFiles++ }
        $v = Get-Prop $r 'Vulnerabilities'
        if ($v) { $vulns += $v }
        $s = Get-Prop $r 'Secrets'
        if ($s) { $secrets += $s }
        $m = Get-Prop $r 'Misconfigurations'
        if ($m) { $misconfigs += @($m | Where-Object { $_.Status -eq 'FAIL' }) }
        $l = Get-Prop $r 'Licenses'
        if ($l) { $licences += $l }
        # Present only with --show-suppressed; the property name is still marked experimental in 0.76.
        $x = Get-Prop $r 'ExperimentalModifiedFindings'
        if ($x) { $suppressed += $x }
    }

    $metaFile = $file.FullName -replace '\.json$', '.meta.json'
    $meta = if (Test-Path $metaFile) { Get-Content -Raw $metaFile | ConvertFrom-Json } else { $null }

    $row = [ordered]@{
        Report     = $file.Name
        Duration   = Get-Prop $meta 'durationSeconds'
        DepFiles   = $depFiles
        Vulns      = $vulns.Count
        UniqueCVEs = @($vulns | Select-Object -ExpandProperty VulnerabilityID -Unique).Count
    }
    foreach ($sev in $severities) {
        $row[$sev] = @($vulns | Where-Object { $_.Severity -eq $sev }).Count
    }
    $row['Secrets']     = $secrets.Count
    $row['Misconfigs']  = $misconfigs.Count
    $row['Licences']    = $licences.Count
    $row['Suppressed']  = $suppressed.Count
    $row['DbUpdatedAt'] = Get-Prop $meta 'dbUpdatedAt'
    [pscustomobject]$row

    if ($Top -gt 0 -and $vulns.Count -gt 0 -and -not $Markdown) {
        Write-Host "`nTop $Top vulnerable packages in $($file.Name):"
        $vulns | Group-Object PkgName | Sort-Object Count -Descending | Select-Object -First $Top |
            ForEach-Object { '  {0,-40} {1,4} findings' -f $_.Name, $_.Count } | Write-Host
    }
}

if ($Markdown) {
    $cols = 'Report', 'Duration', 'DepFiles', 'Vulns', 'UniqueCVEs', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'Secrets', 'Misconfigs', 'Licences', 'Suppressed'
    '| ' + ($cols -join ' | ') + ' |'
    '|' + (($cols | ForEach-Object { '---' }) -join '|') + '|'
    foreach ($r in $rows) { '| ' + (($cols | ForEach-Object { $r.$_ }) -join ' | ') + ' |' }
}
else {
    $rows
}
