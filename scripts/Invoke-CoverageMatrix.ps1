<#
.SYNOPSIS
    Scans every ecosystem fixture and reports which expected findings Trivy detects.

.DESCRIPTION
    For each fixtures/ecosystems/<case>/ the fixture is scanned twice with vuln, secret
    and misconfig scanners:
      default   the shared config (exact pins only, dev dependencies excluded)
      maximum   plus --include-dev-deps and --detection-priority comprehensive
    and each line of expected.txt is checked:
      <package> direct|transitive|dev   the package has at least one vulnerability
      <file> misconfig                  at least one failed check on that file
      <file> secret                     at least one secret in that file

    Reports go to reports/matrix-<UTC stamp>/; a summary is printed and saved there as
    summary.md (Markdown) and matrix.html (colour-coded, variants side by side). Cases containing the __FAKE_GITHUB_TOKEN__ placeholder are scanned
    from a temporary copy (reports/matrix-<stamp>/cases/) with a freshly generated, invalid
    token injected, so no token-shaped string is ever committed.

.EXAMPLE
    .\scripts\Invoke-CoverageMatrix.ps1
#>
[CmdletBinding()]
param(
    [string]$FixturesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'fixtures\ecosystems'),

    # Run only the cases whose name matches this pattern, e.g. 'cs-*'.
    [string]$Filter = '*',

    # Also write the result rows to the pipeline (used by Update-ReadmeImages.ps1).
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\TrivyLab.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$trivyExe = Join-Path $repoRoot 'tools\trivy.exe'
$started  = (Get-Date).ToUniversalTime()
$outDir   = Join-Path $repoRoot ("reports\matrix-" + $started.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
# Must match the placeholder written by New-EcosystemFixtures.ps1.
$TokenPlaceholder = '__FAKE_GITHUB_TOKEN__'

$variants = [ordered]@{
    default = @()
    maximum = @('--include-dev-deps', '--detection-priority', 'comprehensive')
}

# PyPI names are case- and separator-insensitive; NuGet and npm names are compared case-insensitively.
function Get-NormalisedName([string]$Name) { $Name.ToLowerInvariant() -replace '[-_.]+', '-' }

function Get-ReportFinding([string]$ReportPath) {
    $report = Get-Content -Raw $ReportPath | ConvertFrom-Json
    $f = @{ DepFiles = 0; Packages = 0; VulnPkgs = @{}; MisconfigFiles = @{}; SecretFiles = @{} }
    $results = if ($report.PSObject.Properties['Results']) { @($report.Results) } else { @() }
    foreach ($r in $results) {
        if (-not $r) { continue }
        if ($r.Class -eq 'lang-pkgs') {
            $f.DepFiles++
            if ($r.PSObject.Properties['Packages'] -and $r.Packages) { $f.Packages += @($r.Packages).Count }
        }
        if ($r.PSObject.Properties['Vulnerabilities'] -and $r.Vulnerabilities) {
            $r.Vulnerabilities | ForEach-Object { $f.VulnPkgs[(Get-NormalisedName $_.PkgName)] = $true }
        }
        if ($r.PSObject.Properties['Misconfigurations'] -and @($r.Misconfigurations | Where-Object Status -eq 'FAIL')) {
            $f.MisconfigFiles[$r.Target] = $true
        }
        if ($r.PSObject.Properties['Secrets'] -and $r.Secrets) { $f.SecretFiles[$r.Target] = $true }
    }
    $f
}

$cases = Get-ChildItem $FixturesPath -Directory | Where-Object Name -like $Filter | Sort-Object Name
$rows = foreach ($case in $cases) {
    $expected = Get-Content (Join-Path $case.FullName 'expected.txt') | Where-Object { $_.Trim() } |
        ForEach-Object { $n, $k = $_.Trim() -split '\s+', 2; [pscustomobject]@{ Name = $n; Kind = $k } }

    # Fixtures never contain token-shaped strings; inject a fresh, invalid fake token into a
    # temporary copy so the secret scanner has something to find.
    $scanPath = $case.FullName
    if (Get-ChildItem $case.FullName -Recurse -File | Select-String -SimpleMatch $TokenPlaceholder -Quiet) {
        $scanPath = Join-Path $outDir "cases\$($case.Name)"
        Copy-Item -Recurse $case.FullName $scanPath
        $fakeToken = 'ghp_' + -join (1..36 | ForEach-Object { 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[(Get-Random -Maximum 62)] })
        Get-ChildItem $scanPath -Recurse -File | Where-Object { Select-String -Path $_.FullName -SimpleMatch $TokenPlaceholder -Quiet } |
            ForEach-Object { [IO.File]::WriteAllText($_.FullName, ([IO.File]::ReadAllText($_.FullName) -replace $TokenPlaceholder, $fakeToken)) }
    }

    foreach ($v in $variants.Keys) {
        $report = Join-Path $outDir "$($case.Name)_$v.json"
        $trivyArgs = @('fs', '--scanners', 'vuln,secret,misconfig', '--format', 'json', '--quiet',
            '--config', (Join-Path $repoRoot 'config\trivy.yaml'),
            '--ignorefile', (Join-Path $repoRoot 'config\trivyignore.yaml'),
            '--cache-dir', (Join-Path $repoRoot 'cache'),
            '--output', $report) + $variants[$v] + @($scanPath)
        Write-TrivyCommand "Trivy: $($case.Name) [$v] main pass" $trivyExe $trivyArgs $repoRoot
        & $trivyExe @trivyArgs
        if ($LASTEXITCODE -ne 0) { Write-Warning "$($case.Name) [$v]: Trivy exit code $LASTEXITCODE"; continue }

        $f = Get-ReportFinding $report

        # Separate Docker Compose pass, as in Invoke-TrivyScan.ps1 (see the comment there).
        $composeReport = Join-Path $outDir "$($case.Name)_$v.compose.json"
        $composeArgs = @('fs', '--scanners', 'misconfig', '--misconfig-scanners', 'yaml', '--format', 'json', '--quiet',
            '--config-check', (Join-Path $repoRoot 'config\checks'), '--check-namespaces', 'user',
            '--cache-dir', (Join-Path $repoRoot 'cache'), '--output', $composeReport, $scanPath)
        Write-TrivyCommand "Trivy: $($case.Name) [$v] Docker Compose pass" $trivyExe $composeArgs $repoRoot
        & $trivyExe @composeArgs
        if ($LASTEXITCODE -eq 0) {
            (Get-ReportFinding $composeReport).MisconfigFiles.Keys | ForEach-Object { $f.MisconfigFiles[$_] = $true }
        }
        $hits = foreach ($e in $expected) {
            $found = switch ($e.Kind) {
                'misconfig' { $f.MisconfigFiles.ContainsKey($e.Name) }
                'secret'    { $f.SecretFiles.ContainsKey($e.Name) }
                default     { $f.VulnPkgs.ContainsKey((Get-NormalisedName $e.Name)) }
            }
            [pscustomobject]@{ Name = $e.Name; Kind = $e.Kind; Found = $found }
        }
        $byKind = { param($k) $h = @($hits | Where-Object Kind -eq $k); if ($h.Count) { '{0}/{1}' -f @($h | Where-Object Found).Count, $h.Count } else { '' } }
        [pscustomobject]@{
            Case       = $case.Name
            Variant    = $v
            DepFiles   = $f.DepFiles
            Packages   = $f.Packages
            Direct     = & $byKind 'direct'
            Transitive = & $byKind 'transitive'
            Dev        = & $byKind 'dev'
            Misconfig  = & $byKind 'misconfig'
            Secret     = & $byKind 'secret'
            Missed     = (@($hits | Where-Object { -not $_.Found } | ForEach-Object Name) -join ', ')
        }
    }
}

$cols = 'Case', 'Variant', 'DepFiles', 'Packages', 'Direct', 'Transitive', 'Dev', 'Misconfig', 'Secret', 'Missed'
$md = @(
    '| ' + ($cols -join ' | ') + ' |'
    '|' + (($cols | ForEach-Object { '---' }) -join '|') + '|'
    foreach ($r in $rows) { '| ' + (($cols | ForEach-Object { $r.$_ }) -join ' | ') + ' |' }
)
$md | Set-Content -Encoding utf8 (Join-Path $outDir 'summary.md')

# Human-readable page: one row per case with the two variants side by side, grouped by ecosystem.
function Get-CellClass([string]$Value) {
    if (-not $Value) { return 'na' }
    $found, $expected = [int[]]($Value -split '/')
    if ($found -eq $expected) { 'ok' } elseif ($found -eq 0) { 'miss' } else { 'part' }
}
function Get-Score([object[]]$Rows) {
    $found = 0; $expected = 0
    foreach ($r in $Rows) {
        foreach ($c in 'Direct', 'Transitive', 'Dev', 'Misconfig', 'Secret') {
            if ($r.$c) { $n = [int[]]($r.$c -split '/'); $found += $n[0]; $expected += $n[1] }
        }
    }
    '{0}/{1}' -f $found, $expected
}

$versionInfo = & $trivyExe version --format json --cache-dir (Join-Path $repoRoot 'cache') 2>$null | ConvertFrom-Json
$ecosystems  = [ordered]@{ cs = 'C# / .NET'; py = 'Python'; node = 'JavaScript / TypeScript'; iac = 'Infrastructure as code' }
$metrics     = [ordered]@{ DepFiles = 'Dependency files'; Packages = 'Packages'; Direct = 'Direct'; Transitive = 'Transitive'
                           Dev = 'Dev'; Misconfig = 'Misconfig'; Secret = 'Secret'; Missed = 'Missed' }
$compared    = @($metrics.Keys)
$caseRows    = $rows | Group-Object Case

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('<h1>Ecosystem coverage matrix</h1>')
$db = if ($versionInfo -and $versionInfo.PSObject.Properties['VulnerabilityDB']) { $versionInfo.VulnerabilityDB.UpdatedAt } else { 'unknown' }
[void]$sb.AppendLine("<p class=""muted"">Run $($started.ToString('yyyy-MM-dd HH:mm')) UTC &middot; Trivy $(ConvertTo-HtmlText (Get-Prop $versionInfo 'Version')) &middot; DB updated $(ConvertTo-HtmlText $db) &middot; $(@($caseRows).Count) cases</p>")
[void]$sb.AppendLine('<div class="cards">')
foreach ($v in $variants.Keys) {
    [void]$sb.AppendLine("<div class=""card""><div class=""n"">$(Get-Score @($rows | Where-Object Variant -eq $v))</div><div class=""l"">expected findings detected, $v</div></div>")
}
[void]$sb.AppendLine('</div>')
[void]$sb.AppendLine(@'
<p><strong>default</strong>: the shared config (exact pins only, dev dependencies excluded).
<strong>maximum</strong>: plus <code>--include-dev-deps --detection-priority comprehensive</code>.<br>
Cells show found / expected:
<span class="ok">&nbsp;all found&nbsp;</span> <span class="part">&nbsp;some missed&nbsp;</span> <span class="miss">&nbsp;none found&nbsp;</span> <span class="na">&nbsp;&mdash; not applicable&nbsp;</span>.
0 dependency files means vulnerabilities were <strong>not assessed</strong>.
<span class="diffmark">&ne;</span> marks cases where the two variants differ.</p>
'@)
[void]$sb.Append('<div class="wrap"><table><thead><tr><th rowspan="2">Case</th>')
foreach ($m in $metrics.Values) { [void]$sb.Append("<th colspan=""2"">$m</th>") }
[void]$sb.Append('</tr><tr>')
foreach ($m in $metrics.Keys) { foreach ($v in $variants.Keys) { [void]$sb.Append("<th>$v</th>") } }
[void]$sb.AppendLine('</tr></thead><tbody>')

$groups = $caseRows | Group-Object { ($_.Name -split '-')[0] } |
    Sort-Object { $i = [array]::IndexOf(@($ecosystems.Keys), $_.Name); if ($i -lt 0) { 99 } else { $i } }
foreach ($g in $groups) {
    $title = if ($ecosystems.Contains($g.Name)) { $ecosystems[$g.Name] } else { $g.Name }
    [void]$sb.AppendLine("<tr class=""group""><th colspan=""$(1 + 2 * $metrics.Count)"">$(ConvertTo-HtmlText $title)</th></tr>")
    foreach ($c in $g.Group) {
        $byVariant = @{}
        foreach ($r in $c.Group) { $byVariant[$r.Variant] = $r }
        $values = foreach ($v in $variants.Keys) { ($compared | ForEach-Object { if ($byVariant[$v]) { "$($byVariant[$v].$_)" } }) -join '|' }
        $differs = @($values | Select-Object -Unique).Count -gt 1
        $links = ($variants.Keys | ForEach-Object { "<a href=""$($c.Name)_$_.json"">$_</a>" }) -join ' '
        $mark = if ($differs) { ' <span class="diffmark" title="the variants differ">&ne;</span>' } else { '' }
        [void]$sb.Append($(if ($differs) { '<tr class="diff">' } else { '<tr>' }))
        [void]$sb.Append("<td class=""nowrap""><span class=""mono"">$(ConvertTo-HtmlText $c.Name)</span>$mark<br><span class=""muted"">JSON: $links</span></td>")
        foreach ($m in $metrics.Keys) {
            foreach ($v in $variants.Keys) {
                $r = $byVariant[$v]
                if (-not $r) { [void]$sb.Append('<td class="na" title="Trivy failed">error</td>'); continue }
                $val = "$($r.$m)"
                $cell = switch ($m) {
                    'DepFiles' { if ($val -eq '0') { '<td class="num miss" title="not assessed">0</td>' } else { "<td class=""num"">$val</td>" } }
                    'Packages' { "<td class=""num"">$val</td>" }
                    'Missed'   { "<td class=""mono"">$(ConvertTo-HtmlText $val)</td>" }
                    default    { $cls = Get-CellClass $val; "<td class=""num $cls"">$(if ($val) { $val } else { '&mdash;' })</td>" }
                }
                [void]$sb.Append($cell)
            }
        }
        [void]$sb.AppendLine('</tr>')
    }
}
[void]$sb.AppendLine('</tbody></table></div>')
[void]$sb.AppendLine('<p class="muted">Generated by scripts/Invoke-CoverageMatrix.ps1. Raw results: summary.md and the JSON files in this folder.</p>')
$htmlFile = Join-Path $outDir 'matrix.html'
ConvertTo-HtmlPage -Title 'Trivy ecosystem coverage matrix' -Body $sb.ToString() | Set-Content -Encoding utf8 $htmlFile

$rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
Write-Host "Reports and summary.md in $outDir"
Write-Host "Readable matrix: $htmlFile"
if ($PassThru) { $rows }
