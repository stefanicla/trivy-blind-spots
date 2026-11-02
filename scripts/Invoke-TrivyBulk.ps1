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

    A failing target is logged and skipped; it never stops the batch. At the end a summary
    is printed and saved as reports/bulk-<UTC stamp>.html, linking each scan's HTML report.
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
. (Join-Path $PSScriptRoot 'lib\TrivyLab.ps1')

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
$summary = @()
if ($newReports) {
    $summary = @(& (Join-Path $PSScriptRoot 'Convert-Report.ps1') -Path $newReports.FullName)
    $summary | Format-Table -AutoSize
}

# Batch page: one row per report, linking to the HTML page Invoke-TrivyScan.ps1 wrote for each scan.
$failed = @($results | Where-Object { $_.Error -or $_.ExitCode -ne 0 })
$source = if ($GitHubOrg) { "GitHub organisation $GitHubOrg" } else { Get-RepoRelativePath $TargetsFile $repoRoot }
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('<h1>Trivy batch scan</h1>')
[void]$sb.AppendLine(("<p class=""muted"">Started {0} UTC &middot; {1} targets from {2} &middot; {3} with errors</p>" -f
    $startedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm'), @($results).Count, (ConvertTo-HtmlText $source), $failed.Count))
$cols = 'Duration', 'DepFiles', 'Vulns', 'UniqueCVEs', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'Secrets', 'Misconfigs', 'Licences', 'Suppressed'
if ($summary) {
    [void]$sb.AppendLine('<p>0 dependency files means vulnerabilities were <strong>not assessed</strong>, not that the target is clean.</p>')
    [void]$sb.Append('<div class="wrap"><table><thead><tr><th>Report</th>')
    foreach ($c in $cols) { [void]$sb.Append("<th class=""num"">$c</th>") }
    [void]$sb.AppendLine('</tr></thead><tbody>')
    foreach ($r in $summary) {
        $html = $r.Report -replace '\.json$', '.html'
        [void]$sb.Append("<tr><td class=""mono""><a href=""$(ConvertTo-HtmlText $html)"">$(ConvertTo-HtmlText ($r.Report -replace '\.json$', ''))</a></td>")
        foreach ($c in $cols) {
            $cell = if ($c -eq 'DepFiles' -and $r.$c -eq 0) { '<td class="num miss" title="not assessed">0</td>' } else { "<td class=""num"">$($r.$c)</td>" }
            [void]$sb.Append($cell)
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table></div>')
}
if ($failed) {
    [void]$sb.AppendLine("<h2>Targets with errors or a non-zero exit code ($($failed.Count))</h2>")
    [void]$sb.AppendLine('<div class="wrap"><table><thead><tr><th>Target</th><th>Method</th><th class="num">Exit code</th><th>Error</th></tr></thead><tbody>')
    foreach ($f in $failed) {
        [void]$sb.AppendLine(("<tr><td class=""mono"">{0}</td><td>{1}</td><td class=""num"">{2}</td><td>{3}</td></tr>" -f
            (ConvertTo-HtmlText (Get-RepoRelativePath $f.Target $repoRoot)), (ConvertTo-HtmlText $f.Method), $f.ExitCode, (ConvertTo-HtmlText $f.Error)))
    }
    [void]$sb.AppendLine('</tbody></table></div>')
}
[void]$sb.AppendLine('<p class="muted">Generated by scripts/Invoke-TrivyBulk.ps1.</p>')
$bulkHtml = Join-Path $repoRoot ('reports\bulk-' + $startedAt.ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '.html')
ConvertTo-HtmlPage -Title 'Trivy batch scan' -Body $sb.ToString() | Set-Content -Encoding utf8 $bulkHtml
Write-Host "Readable batch summary: $bulkHtml"
