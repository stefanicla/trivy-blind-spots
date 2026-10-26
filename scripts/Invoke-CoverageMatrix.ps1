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

    Reports go to reports/matrix-<UTC stamp>/; a Markdown summary is printed and saved
    there as summary.md. Cases containing the __FAKE_GITHUB_TOKEN__ placeholder are scanned
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

$repoRoot = Split-Path -Parent $PSScriptRoot
$trivyExe = Join-Path $repoRoot 'tools\trivy.exe'
$outDir   = Join-Path $repoRoot ("reports\matrix-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
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
        & $trivyExe @trivyArgs
        if ($LASTEXITCODE -ne 0) { Write-Warning "$($case.Name) [$v]: Trivy exit code $LASTEXITCODE"; continue }

        $f = Get-ReportFinding $report

        # Separate Docker Compose pass, as in Invoke-TrivyScan.ps1 (see the comment there).
        $composeReport = Join-Path $outDir "$($case.Name)_$v.compose.json"
        & $trivyExe fs --scanners misconfig --misconfig-scanners yaml --format json --quiet `
            --config-check (Join-Path $repoRoot 'config\checks') --check-namespaces user `
            --cache-dir (Join-Path $repoRoot 'cache') --output $composeReport $scanPath
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
$rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host
Write-Host "Reports and summary.md in $outDir"
if ($PassThru) { $rows }
