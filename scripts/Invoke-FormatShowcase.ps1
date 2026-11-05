<#
.SYNOPSIS
    Produces every report format Trivy supports natively from one scan, for side-by-side review (E19).

.DESCRIPTION
    1. Scans the known-answer fixture (workspace/fixture-local) once with
       vuln,secret,misconfig,license, through Invoke-TrivyScan.ps1. Later runs reuse the
       newest such scan unless -Rescan is given; -FromJson uses any existing JSON report.
    2. Converts that JSON report into each requested format with `trivy convert` and prints
       each command, so it can be copied and re-run by hand.
    3. Checks, per format, how many findings of each class from the JSON baseline appear in
       the output file (a presence check on identifiers: CVE IDs, secret rule IDs or titles,
       check IDs, licence names, package name + version). It is a quick hint; open the files
       to confirm. A CVE ID counts even when a format only carries it as an advisory link
       (SPDX does that).
    4. Writes reports/formats-<UTC>/index.html: the overview table, then one section per
       format with its command, a link to the file and its first lines.

    The output folder is self-contained and can be zipped and shared.
    Formats and how to review each one by hand: docs/report-formats.md

    Exit code 1 if any conversion fails or produces an empty file, 0 otherwise.

.EXAMPLE
    .\scripts\Invoke-FormatShowcase.ps1
    Every format; opens nothing. The first run scans the fixture.

.EXAMPLE
    .\scripts\Invoke-FormatShowcase.ps1 -Format html,table -Open
    Only two formats, from the newest showcase scan; opens index.html in the browser.

.EXAMPLE
    .\scripts\Invoke-FormatShowcase.ps1 -FromJson .\reports\NodeGoat_repo_20261101T100000Z.json -Format html
    Converts a report of a real repository instead of the fixture.
#>
[CmdletBinding()]
param(
    # Must match Get-TrivyFormatCatalog in lib/TrivyLab.ps1.
    [ValidateSet('all', 'json', 'table', 'table-summary', 'sarif', 'cyclonedx', 'spdx', 'spdx-json', 'github', 'cosign-vuln',
        'html', 'junit', 'gitlab', 'gitlab-codequality', 'asff')]
    [string[]]$Format = 'all',

    # An existing Trivy JSON report to convert, instead of the fixture scan.
    [string]$FromJson,

    # Scan the fixture again even if an earlier showcase scan exists.
    [switch]$Rescan,

    # Open index.html in the default browser at the end.
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\TrivyLab.ps1')

$repoRoot   = Split-Path -Parent $PSScriptRoot
$trivyExe   = Join-Path $repoRoot 'tools\trivy.exe'
$reportsDir = Join-Path $repoRoot 'reports'

if (-not (Test-Path $trivyExe) -or -not (Test-Path (Join-Path $repoRoot 'tools\contrib\html.tpl'))) {
    throw 'Trivy or its report templates are missing. Run scripts\Install-Trivy.ps1 first.'
}

# --- 1. The JSON report every format is converted from ----------------------------------
function Get-LatestShowcaseScan {
    Get-ChildItem $reportsDir -Filter 'formats_repo_*.json' -File -ErrorAction SilentlyContinue |
        Where-Object Name -NotMatch '\.meta\.json$' | Sort-Object Name | Select-Object -Last 1
}

if ($FromJson) {
    $source = Get-Item (Resolve-Path $FromJson)
}
else {
    $source = if ($Rescan) { $null } else { Get-LatestShowcaseScan }
    if ($source) {
        Write-Host "Reusing the scan $($source.Name) (use -Rescan for a fresh one)."
    }
    else {
        & (Join-Path $PSScriptRoot 'New-Fixture.ps1') | Out-Null
        & (Join-Path $PSScriptRoot 'Invoke-TrivyScan.ps1') -Target (Join-Path $repoRoot 'workspace\fixture-local') -Method repo `
            -Scanners vuln, secret, misconfig, license -Name 'formats' | Out-Host
        $source = Get-LatestShowcaseScan
        if (-not $source) { throw 'The fixture scan wrote no report.' }
    }
}
$sourceMetaPath = $source.FullName -replace '\.json$', '.meta.json'
$sourceMeta = if (Test-Path $sourceMetaPath) { Get-Content -Raw $sourceMetaPath | ConvertFrom-Json } else { $null }

$stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$outDir = Join-Path $reportsDir "formats-$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$inputJson = Join-Path $outDir 'scan.json'
Copy-Item $source.FullName $inputJson
if ($sourceMeta) { Copy-Item $sourceMetaPath (Join-Path $outDir 'scan.meta.json') }

# --- 2. What the baseline contains, per finding class -------------------------------------
$report  = Get-Content -Raw $inputJson | ConvertFrom-Json
$results = @(Get-Prop $report 'Results' | Where-Object { $_ })
function Get-Items([string]$Property) { @($results | ForEach-Object { Get-Prop $_ $Property } | Where-Object { $_ }) }

# Each class: the distinct findings, as the identifiers to look for in an output file.
# A secret is "RuleID|Title" and a misconfiguration "ID|AVDID" (either may appear; ASFF names a secret by its
# title only); a package is "name|version" (both, close together).
$classes = [ordered]@{
    Vulns      = @(Get-Items 'Vulnerabilities' | ForEach-Object { $_.VulnerabilityID })
    Secrets    = @(Get-Items 'Secrets' | ForEach-Object { (@($_.RuleID, (Get-Prop $_ 'Title')) | Where-Object { $_ }) -join '|' })
    Misconfigs = @(Get-Items 'Misconfigurations' | Where-Object Status -eq 'FAIL' |
            ForEach-Object { (@((Get-Prop $_ 'ID'), (Get-Prop $_ 'AVDID')) | Where-Object { $_ }) -join '|' })
    Licences   = @(Get-Items 'Licenses' | ForEach-Object { $_.Name })
    Packages   = @(Get-Items 'Packages' | ForEach-Object { "$($_.Name)|$($_.Version)" })
}
foreach ($k in @($classes.Keys)) { $classes[$k] = @($classes[$k] | Where-Object { $_ } | Sort-Object -Unique) }

function Test-Present([string]$Text, [string]$Id, [string]$Class) {
    if ($Class -eq 'Packages') {
        # Name, then version within a short distance: "Django 2.2.0", "pkg:pypi/django@2.2.0", JSON fields, table cells.
        $name, $version = $Id -split '\|', 2
        return [regex]::IsMatch($Text, [regex]::Escape($name) + '[\s\S]{0,160}?' + [regex]::Escape($version), 'IgnoreCase')
    }
    foreach ($alias in $Id -split '\|') {
        if ($Text.IndexOf($alias, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    $false
}

# --- 3. Convert ---------------------------------------------------------------------------
$catalog  = @(Get-TrivyFormatCatalog $repoRoot | Where-Object { $Format -contains 'all' -or $Format -contains $_.Name })
$rows     = [System.Collections.Generic.List[object]]::new()
$failures = 0
foreach ($f in $catalog) {
    $out = Join-Path $outDir "report.$($f.Extension)"
    $convertArgs = @('convert') + $f.Arguments + @('--output', $out, $inputJson)
    Write-TrivyCommand "Trivy: convert to $($f.Name)" $trivyExe $convertArgs $repoRoot
    & $trivyExe @convertArgs
    $exit = $LASTEXITCODE

    $text = if (Test-Path $out) { Get-Content -Raw $out } else { '' }
    $ok   = $exit -eq 0 -and $text.Trim().Length -gt 0
    if (-not $ok) { $failures++; Write-Warning "Conversion to $($f.Name) failed (exit code $exit) or produced an empty file." }

    $row = [ordered]@{ Format = $f.Name; Status = if ($ok) { 'OK' } else { 'FAIL' }; SizeKB = [math]::Round($text.Length / 1KB, 1) }
    foreach ($c in $classes.GetEnumerator()) {
        $total = @($c.Value).Count
        $found = if ($ok) { @($c.Value | Where-Object { Test-Present $text $_ $c.Key }).Count } else { 0 }
        $row[$c.Key] = if ($total) { "$found/$total" } else { '-' }
    }
    $row.Word = $f.Word
    $rows.Add([pscustomobject]@{ Entry = $f; File = $out; Text = $text; Row = [pscustomobject]$row; Arguments = $convertArgs })
}

# --- 4. index.html ------------------------------------------------------------------------
# A command line to paste into PowerShell at the repository root. Arguments with spaces, and
# "@file" (which PowerShell would read as splatting), are single-quoted.
function Get-PasteableCommand([string]$Exe, [string[]]$Arguments) {
    $parts = @($Exe) + $Arguments | ForEach-Object {
        $a = Get-RepoRelativePath $_ $repoRoot
        if ($a -match '[\s@]') { "'" + ($a -replace "'", "''") + "'" } else { $a }
    }
    $parts -join ' '
}

function Get-CountCell([string]$Value) {
    if ($Value -eq '-') { return '<td class="na">-</td>' }
    $found, $total = $Value -split '/'
    $css = if ($found -eq $total) { 'ok' } elseif ([int]$found -eq 0) { 'miss' } else { 'part' }
    "<td class=""num $css"">$Value</td>"
}
$wordCell = @{ yes = '<td class="ok">Yes</td>'; poor = '<td class="part">Poor</td>'; no = '<td class="na">No</td>' }

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('<h1>Trivy report formats</h1>')
$versionText = if ($sourceMeta) { "Trivy $(ConvertTo-HtmlText $sourceMeta.trivyVersion) &middot; DB updated $(ConvertTo-HtmlText $sourceMeta.dbUpdatedAt) &middot; " } else { '' }
[void]$sb.AppendLine("<p class=""muted"">$versionText" + "Generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC from <a href=""scan.json"">scan.json</a> ($(ConvertTo-HtmlText $source.Name)). Every format is produced from that one scan with <code>trivy convert</code>.</p>")
[void]$sb.AppendLine('<div class="banner">The counts are a presence check: how many identifiers from the JSON baseline (CVE IDs, secret rule IDs, check IDs, licence names, package name + version) appear anywhere in each file. They show which classes a format carries; open the files to confirm. How to review each format by hand: <code>docs/report-formats.md</code>.</div>')

if ($sourceMeta) {
    [void]$sb.AppendLine('<h2>The scan</h2>')
    [void]$sb.AppendLine("<p>Target: <span class=""mono"">$(ConvertTo-HtmlText (Get-RepoRelativePath $sourceMeta.target $repoRoot))</span></p>")
    [void]$sb.AppendLine('<div class="wrap">' + (ConvertTo-CommandHtml $sourceMeta.command ([string[]]$sourceMeta.arguments) $repoRoot) + '</div>')
}

[void]$sb.AppendLine('<h2>Overview</h2><div class="wrap"><table><thead><tr><th>Format</th><th>For</th><th>In Word</th>')
foreach ($c in $classes.Keys) { [void]$sb.Append("<th class=""num"">$c</th>") }
[void]$sb.AppendLine('<th class="num">Size (KB)</th><th>File</th></tr></thead><tbody>')
[void]$sb.AppendLine("<tr><td class=""mono""><b>baseline</b></td><td>The JSON scan report</td><td class=""na"">No</td>")
foreach ($c in $classes.GetEnumerator()) { [void]$sb.Append("<td class=""num"">$(@($c.Value).Count)</td>") }
[void]$sb.AppendLine("<td class=""num"">$([math]::Round((Get-Item $inputJson).Length / 1KB, 1))</td><td class=""mono""><a href=""scan.json"">scan.json</a></td></tr>")
foreach ($r in $rows) {
    $leaf = Split-Path -Leaf $r.File
    $status = if ($r.Row.Status -eq 'OK') { '' } else { ' <span class="miss">FAILED</span>' }
    [void]$sb.Append("<tr><td class=""mono""><a href=""#$($r.Entry.Name)"">$(ConvertTo-HtmlText $r.Entry.Name)</a>$status</td><td>$(ConvertTo-HtmlText $r.Entry.Audience)</td>$($wordCell[$r.Entry.Word])")
    foreach ($c in $classes.Keys) { [void]$sb.Append((Get-CountCell $r.Row.$c)) }
    [void]$sb.AppendLine("<td class=""num"">$($r.Row.SizeKB)</td><td class=""mono""><a href=""$(ConvertTo-HtmlText $leaf)"">$(ConvertTo-HtmlText $leaf)</a></td></tr>")
}
[void]$sb.AppendLine('</tbody></table></div>')

foreach ($r in $rows) {
    $leaf = Split-Path -Leaf $r.File
    [void]$sb.AppendLine("<h2 id=""$($r.Entry.Name)"">$(ConvertTo-HtmlText $r.Entry.Name)</h2>")
    [void]$sb.AppendLine("<p>$(ConvertTo-HtmlText $r.Entry.Description)</p>")
    [void]$sb.AppendLine("<p>For: $(ConvertTo-HtmlText $r.Entry.Audience) &middot; In Word: $(ConvertTo-HtmlText $r.Entry.Word) &middot; File: <a class=""mono"" href=""$(ConvertTo-HtmlText $leaf)"">$(ConvertTo-HtmlText $leaf)</a></p>")
    [void]$sb.AppendLine('<div class="wrap">' + (ConvertTo-CommandHtml $trivyExe ([string[]]$r.Arguments) $repoRoot) + '</div>')
    [void]$sb.AppendLine("<p>Re-run by hand, in PowerShell at the repository root:</p><pre>$(ConvertTo-HtmlText (Get-PasteableCommand $trivyExe $r.Arguments))</pre>")
    $lines = @($r.Text -split "`r?`n" | Select-Object -First 30 | ForEach-Object { if ($_.Length -gt 220) { $_.Substring(0, 220) + ' ...' } else { $_ } })
    [void]$sb.AppendLine("<details><summary>First $($lines.Count) lines</summary><pre>$(ConvertTo-HtmlText ($lines -join "`n"))</pre></details>")
}
[void]$sb.AppendLine('<p class="muted">Generated by scripts/Invoke-FormatShowcase.ps1.</p>')
$indexHtml = Join-Path $outDir 'index.html'
ConvertTo-HtmlPage -Title 'Trivy report formats' -Body $sb.ToString() | Set-Content -Encoding utf8 $indexHtml

# --- 5. Console summary -------------------------------------------------------------------
$baseline = [ordered]@{ Format = 'baseline'; Status = ''; SizeKB = [math]::Round((Get-Item $inputJson).Length / 1KB, 1) }
foreach ($c in $classes.GetEnumerator()) { $baseline[$c.Key] = @($c.Value).Count }
$baseline.Word = ''
@([pscustomobject]$baseline) + @($rows | ForEach-Object Row) | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "Formats: $(Get-RepoRelativePath $outDir $repoRoot)"
Write-Host "Overview: $(Get-RepoRelativePath $indexHtml $repoRoot)"
if ($Open) { Invoke-Item $indexHtml }
if ($failures) { Write-Host "$failures conversion(s) failed."; exit 1 }
