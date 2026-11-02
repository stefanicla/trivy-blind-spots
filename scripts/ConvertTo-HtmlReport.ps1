<#
.SYNOPSIS
    Renders one Trivy JSON report as a self-contained HTML page for people to read.

.DESCRIPTION
    The page shows the scan metadata and the Trivy command (from the .meta.json sidecar
    written by Invoke-TrivyScan.ps1, when present), counts by severity, a warning when no
    dependency files were analysed, and every finding grouped by file: vulnerabilities,
    secrets, failed misconfiguration checks, licences and suppressed findings.

    Secrets are listed by file, line and rule only; the matched text is never copied into
    the page.

    Invoke-TrivyScan.ps1 runs this for every scan; run it by hand for older reports.

.EXAMPLE
    .\scripts\ConvertTo-HtmlReport.ps1 -Path .\reports\known-answer_repo_20261030T081059Z.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    # Defaults to the report path with .html instead of .json.
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\TrivyLab.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$Path     = (Resolve-Path $Path).Path
if (-not $OutFile) { $OutFile = $Path -replace '\.json$', '.html' }

$report = Get-Content -Raw $Path | ConvertFrom-Json
if (-not (Get-Prop $report 'SchemaVersion')) { throw "$Path is not a Trivy JSON report." }
$metaFile = $Path -replace '\.json$', '.meta.json'
$meta = if (Test-Path $metaFile) { Get-Content -Raw $metaFile | ConvertFrom-Json } else { $null }

function Enc($Text) { ConvertTo-HtmlText $Text }

function Get-Link([string]$Text, [string]$Url) {
    if ($Url -match '^https?://') { "<a href=""$(Enc $Url)"">$(Enc $Text)</a>" } else { Enc $Text }
}

function Get-LineRange($Start, $End) {
    if (-not $Start) { return '' }
    if ($End -and $End -ne $Start) { "$Start-$End" } else { "$Start" }
}

# --- Collect findings per result -------------------------------------------------------------
$results = @(Get-Prop $report 'Results' | Where-Object { $_ })
$all = @{ Vulns = @(); Secrets = @(); Misconfigs = @(); Licences = @(); Suppressed = @() }
$depFiles = @()
foreach ($r in $results) {
    if ((Get-Prop $r 'Class') -eq 'lang-pkgs') { $depFiles += $r }
    $v = Get-Prop $r 'Vulnerabilities';              if ($v) { $all.Vulns      += $v }
    $s = Get-Prop $r 'Secrets';                      if ($s) { $all.Secrets    += $s }
    $m = Get-Prop $r 'Misconfigurations';            if ($m) { $all.Misconfigs += @($m | Where-Object { $_.Status -eq 'FAIL' }) }
    $l = Get-Prop $r 'Licenses';                     if ($l) { $all.Licences   += $l }
    $x = Get-Prop $r 'ExperimentalModifiedFindings'; if ($x) { $all.Suppressed += $x }
}

# Scanners from the recorded command; without one Trivy uses config/trivy.yaml, which includes vuln.
$arguments = @(Get-Prop $meta 'arguments')
$scanners  = $null
$idx = [array]::IndexOf($arguments, '--scanners')
if ($idx -ge 0 -and $idx + 1 -lt $arguments.Count) { $scanners = $arguments[$idx + 1] }
$method   = Get-Prop $meta 'method'
$vulnScan = $method -ne 'sbom' -and (-not $scanners -or ($scanners -split ',') -contains 'vuln')

$name = if (Get-Prop $meta 'name') { $meta.name } else { [IO.Path]::GetFileNameWithoutExtension($Path) }
$started = Get-Prop $meta 'startedUtc'
if ($started) {
    $started = [datetime]::ParseExact($started, "yyyyMMdd'T'HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
}

$sb = [System.Text.StringBuilder]::new()
function Add([string]$Html) { [void]$sb.AppendLine($Html) }

# --- Header ------------------------------------------------------------------------------------
Add "<h1>Trivy report: $(Enc $name)</h1>"
Add '<table class="meta"><tbody>'
$target = if ($meta) { $meta.target } else { Get-Prop $report 'ArtifactName' }
$metaRows = [ordered]@{
    'Target'          = Get-RepoRelativePath $target $repoRoot
    'Method'          = $method
    'Scanners'        = if ($scanners) { $scanners } elseif ($meta) { 'config default (config/trivy.yaml)' } else { $null }
    'Started'         = $started
    'Duration'        = if (Get-Prop $meta 'durationSeconds') { "$($meta.durationSeconds) s" } else { $null }
    'Exit code'       = Get-Prop $meta 'exitCode'
    'Trivy version'   = Get-Prop $meta 'trivyVersion'
    'DB updated at'   = Get-Prop $meta 'dbUpdatedAt'
}
foreach ($k in $metaRows.Keys) {
    if ($null -ne $metaRows[$k] -and "$($metaRows[$k])" -ne '') { Add "<tr><th>$k</th><td>$(Enc $metaRows[$k])</td></tr>" }
}
$leaf = Split-Path -Leaf $Path
Add "<tr><th>JSON report</th><td><a href=""$(Enc $leaf)"">$(Enc $leaf)</a></td></tr>"
Add '</tbody></table>'

if ($vulnScan -and $depFiles.Count -eq 0) {
    Add ('<div class="banner"><strong>Not assessed:</strong> no dependency lock files or manifests were analysed, ' +
        'so 0 vulnerabilities means "not assessed", not "clean". Check for missing lock files (see docs/methods.md).</div>')
}

# --- Summary cards -----------------------------------------------------------------------------
Add '<div class="cards">'
foreach ($sev in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN') {
    $n = @($all.Vulns | Where-Object { $_.Severity -eq $sev }).Count
    Add "<div class=""card $sev""><div class=""n"">$n</div><div class=""l"">$sev</div></div>"
}
$cards = [ordered]@{
    'unique vulnerability IDs' = @($all.Vulns | ForEach-Object VulnerabilityID | Sort-Object -Unique).Count
    'secrets'                  = $all.Secrets.Count
    'failed misconfig checks'  = $all.Misconfigs.Count
    'licence findings'         = $all.Licences.Count
    'suppressed'               = $all.Suppressed.Count
}
foreach ($k in $cards.Keys) { Add "<div class=""card""><div class=""n"">$($cards[$k])</div><div class=""l"">$k</div></div>" }
$warn = if ($vulnScan -and $depFiles.Count -eq 0) { ' warn' } else { '' }
Add "<div class=""card$warn""><div class=""n"">$($depFiles.Count)</div><div class=""l"">dependency files analysed</div></div>"
Add '</div>'

# --- Findings, one <details> per file ----------------------------------------------------------
function Add-Section([string]$Title, [string]$Property, [string[]]$Columns, [scriptblock]$Filter, [object[]]$Sort, [scriptblock]$Row) {
    $groups = foreach ($r in $results) {
        $items = @(Get-Prop $r $Property | Where-Object { $_ } | Where-Object $Filter)
        if ($items) { [pscustomobject]@{ Result = $r; Items = @($items | Sort-Object $Sort) } }
    }
    if (-not $groups) { return }
    $total = ($groups | ForEach-Object { $_.Items.Count } | Measure-Object -Sum).Sum
    Add "<h2>$Title ($total)</h2>"
    foreach ($g in $groups) {
        $type = Get-Prop $g.Result 'Type'
        $label = if ($type) { "$($g.Result.Target) ($type)" } else { $g.Result.Target }
        $bySev = $g.Items | Where-Object { $_.PSObject.Properties['Severity'] } | Group-Object Severity |
            Sort-Object { $script:SeverityOrder["$($_.Name)"] } | ForEach-Object { "$(Get-SeverityHtml $_.Name) $($_.Count)" }
        $open = if ($total -le 100) { ' open' } else { '' }
        Add "<details$open><summary><span class=""mono"">$(Enc $label)</span> &mdash; $($g.Items.Count) $($bySev -join ' ')</summary>"
        Add ('<div class="wrap"><table><thead><tr>' + (($Columns | ForEach-Object { "<th>$_</th>" }) -join '') + '</tr></thead><tbody>')
        foreach ($i in $g.Items) { Add ('<tr>' + ((& $Row $i) -join '') + '</tr>') }
        Add '</tbody></table></div></details>'
    }
}

$bySeverity = { $script:SeverityOrder["$($_.Severity)"] }

Add-Section 'Vulnerabilities' 'Vulnerabilities' @('Severity', 'Package', 'Installed', 'Fixed in', 'ID', 'Status', 'Title') { $true } @($bySeverity, 'PkgName', 'VulnerabilityID') {
    param($v)
    "<td>$(Get-SeverityHtml $v.Severity)</td>"
    "<td class=""mono"">$(Enc $v.PkgName)</td>"
    "<td class=""mono"">$(Enc (Get-Prop $v 'InstalledVersion'))</td>"
    "<td class=""mono"">$(Enc (Get-Prop $v 'FixedVersion'))</td>"
    "<td class=""mono nowrap"">$(Get-Link $v.VulnerabilityID (Get-Prop $v 'PrimaryURL'))</td>"
    "<td>$(Enc (Get-Prop $v 'Status'))</td>"
    "<td>$(Enc (Get-Prop $v 'Title'))</td>"
}

Add-Section 'Secrets' 'Secrets' @('Severity', 'Line', 'Rule', 'Category', 'Title') { $true } @($bySeverity, 'StartLine') {
    param($s)
    "<td>$(Get-SeverityHtml $s.Severity)</td>"
    "<td class=""num"">$(Get-LineRange (Get-Prop $s 'StartLine') (Get-Prop $s 'EndLine'))</td>"
    "<td class=""mono"">$(Enc $s.RuleID)</td>"
    "<td>$(Enc (Get-Prop $s 'Category'))</td>"
    "<td>$(Enc (Get-Prop $s 'Title'))</td>"
}

Add-Section 'Failed misconfiguration checks' 'Misconfigurations' @('Severity', 'Lines', 'ID', 'Title', 'Message', 'Resolution') { $_.Status -eq 'FAIL' } @($bySeverity, 'ID') {
    param($m)
    $cause = Get-Prop $m 'CauseMetadata'
    "<td>$(Get-SeverityHtml $m.Severity)</td>"
    "<td class=""num"">$(Get-LineRange (Get-Prop $cause 'StartLine') (Get-Prop $cause 'EndLine'))</td>"
    "<td class=""mono nowrap"">$(Get-Link $m.ID (Get-Prop $m 'PrimaryURL'))</td>"
    "<td>$(Enc (Get-Prop $m 'Title'))</td>"
    "<td>$(Enc (Get-Prop $m 'Message'))</td>"
    "<td>$(Enc (Get-Prop $m 'Resolution'))</td>"
}

Add-Section 'Licences' 'Licenses' @('Severity', 'Package', 'Licence', 'Category', 'File') { $true } @($bySeverity, 'PkgName') {
    param($l)
    "<td>$(Get-SeverityHtml $l.Severity)</td>"
    "<td class=""mono"">$(Enc (Get-Prop $l 'PkgName'))</td>"
    "<td>$(Enc (Get-Prop $l 'Name'))</td>"
    "<td>$(Enc (Get-Prop $l 'Category'))</td>"
    "<td class=""mono"">$(Enc (Get-Prop $l 'FilePath'))</td>"
}

# Present only with --show-suppressed; the property name is still marked experimental in 0.76.
Add-Section 'Suppressed findings' 'ExperimentalModifiedFindings' @('Type', 'Finding', 'Status', 'Source', 'Statement') { $true } @('Type') {
    param($x)
    $f  = Get-Prop $x 'Finding'
    $id = @('VulnerabilityID', 'ID', 'RuleID', 'Name' | ForEach-Object { Get-Prop $f $_ } | Where-Object { $_ })
    "<td>$(Enc (Get-Prop $x 'Type'))</td>"
    "<td class=""mono"">$(Enc ($id | Select-Object -First 1))</td>"
    "<td>$(Enc (Get-Prop $x 'Status'))</td>"
    "<td class=""mono"">$(Enc (Get-RepoRelativePath (Get-Prop $x 'Source') $repoRoot))</td>"
    "<td>$(Enc (Get-Prop $x 'Statement'))</td>"
}

# --- Analysed dependency files and command -----------------------------------------------------
if ($depFiles) {
    Add "<h2>Dependency files analysed ($($depFiles.Count))</h2>"
    Add '<div class="wrap"><table><thead><tr><th>File</th><th>Type</th><th class="num">Packages</th><th class="num">Vulnerabilities</th></tr></thead><tbody>'
    foreach ($d in $depFiles) {
        Add ("<tr><td class=""mono"">$(Enc $d.Target)</td><td>$(Enc (Get-Prop $d 'Type'))</td>" +
            "<td class=""num"">$(@(Get-Prop $d 'Packages' | Where-Object { $_ }).Count)</td>" +
            "<td class=""num"">$(@(Get-Prop $d 'Vulnerabilities' | Where-Object { $_ }).Count)</td></tr>")
    }
    Add '</tbody></table></div>'
}

if ($meta -and (Get-Prop $meta 'command')) {
    Add '<h2>Trivy command</h2>'
    Add ('<p class="muted">Main pass. When misconfiguration scanning is enabled, Invoke-TrivyScan.ps1 also runs a ' +
        'Docker Compose pass and merges its failed checks into this report.</p>')
    Add (ConvertTo-CommandHtml $meta.command ([string[]]$arguments) $repoRoot)
}

Add "<p class=""muted"">Generated by scripts/ConvertTo-HtmlReport.ps1 from $(Enc $leaf).</p>"

ConvertTo-HtmlPage -Title "Trivy: $name" -Body $sb.ToString() | Set-Content -Encoding utf8 $OutFile
Get-Item $OutFile
