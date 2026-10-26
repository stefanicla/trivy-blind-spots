<#
.SYNOPSIS
    Runs one Trivy scan against one target and stores a JSON report plus a metadata sidecar.

.DESCRIPTION
    Methods:
      repo         trivy repo <local path | remote URL>   (native binary)
      fs           trivy fs <local path>                  (native binary)
      sbom         trivy sbom <SBOM file>                 (native binary)
      docker-repo  trivy repo inside the pinned container image
      docker-fs    trivy fs inside the pinned container image (path mounted read-only)

    Outputs, in reports/:
      <name>_<method>_<UTC stamp>.json        Trivy JSON report (always produced)
      <name>_<method>_<UTC stamp>.meta.json   Trivy version, DB date, duration, exit code, arguments
      <name>_<method>_<UTC stamp>.<ext>       Extra formats requested with -Format, produced with
                                              `trivy convert` from the JSON (no second scan)

    Private repositories: set GITHUB_TOKEN or GITLAB_TOKEN in the environment beforehand.
    Tokens are never passed on the command line or written to the reports.

.EXAMPLE
    .\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/aquasecurity/trivy-ci-test

.EXAMPLE
    .\scripts\Invoke-TrivyScan.ps1 -Target .\workspace\fixture-local -Method fs -Scanners vuln,secret,misconfig -Format table,sarif
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Target,

    [ValidateSet('repo', 'fs', 'sbom', 'docker-repo', 'docker-fs')]
    [string]$Method = 'repo',

    [string[]]$Scanners,

    [ValidateSet('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
    [string[]]$Severity,

    # Additional output formats converted from the JSON report.
    [ValidateSet('table', 'sarif', 'cyclonedx', 'spdx-json', 'github')]
    [string[]]$Format,

    # Remote repository reference (repo / docker-repo only; mutually exclusive).
    [string]$Branch,
    [string]$Tag,
    [string]$Commit,

    # Report name prefix; derived from the target when omitted.
    [string]$Name,

    # Trivy server address for client/server mode, e.g. http://localhost:4954
    [string]$Server,

    # Use the cached DB only and make no network calls for dependency resolution.
    [switch]$Offline,

    [switch]$IgnoreUnfixed,

    # Suppression file; defaults to config/trivyignore.yaml.
    [string]$IgnoreFile,

    # Anything else is passed through to Trivy unchanged, e.g. @('--skip-dirs', 'test').
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pinned by digest (identical on Docker Hub and GHCR). See README before changing.
$DockerImage = 'aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$trivyExe   = Join-Path $repoRoot 'tools\trivy.exe'
$configDir  = Join-Path $repoRoot 'config'
$reportsDir = Join-Path $repoRoot 'reports'
$cacheDir   = Join-Path $repoRoot 'cache'
$ignorePath = if ($IgnoreFile) { (Resolve-Path $IgnoreFile).Path } else { Join-Path $configDir 'trivyignore.yaml' }

$isDocker  = $Method -like 'docker-*'
$subcmd    = $Method -replace '^docker-', ''
$isRemote  = $Target -match '^(https?|ssh|git)://|^git@'

if (-not $isDocker -and -not (Test-Path $trivyExe)) {
    throw "Trivy not found at $trivyExe. Run scripts\Install-Trivy.ps1 first."
}
if ($subcmd -eq 'fs' -and $isRemote) {
    throw "Method '$Method' needs a local path. Use 'repo' for URLs, or clone first."
}
if (@($Branch, $Tag, $Commit | Where-Object { $_ }).Count -gt 1) {
    throw 'Use only one of -Branch, -Tag, -Commit.'
}
if (($Branch -or $Tag -or $Commit) -and $subcmd -ne 'repo') {
    throw '-Branch/-Tag/-Commit apply to the repo methods only.'
}

# Resolve local targets to absolute paths (needed for Docker mounts and stable reporting).
if (-not $isRemote) {
    $Target = (Resolve-Path $Target).Path
}

if (-not $Name) {
    $leaf = if ($isRemote) { ($Target.TrimEnd('/') -split '[/:]')[-1] -replace '\.git$', '' }
            else { Split-Path -Leaf $Target }
    $ref  = @($Branch, $Tag, $Commit | Where-Object { $_ })
    $Name = if ($ref) { "$leaf@$($ref[0])" } else { $leaf }
}
$safeName = $Name -replace '[^\w.@-]', '_'
$stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$baseName = "${safeName}_${Method}_${stamp}"
New-Item -ItemType Directory -Force -Path $reportsDir, $cacheDir | Out-Null
$jsonReport = Join-Path $reportsDir "$baseName.json"
$metaReport = Join-Path $reportsDir "$baseName.meta.json"

# Arguments common to every method; paths are rewritten below for Docker.
# `trivy sbom` accepts only vuln and license, so the config default (vuln,secret) would be rejected.
if ($subcmd -eq 'sbom' -and -not $Scanners) { $Scanners = @('vuln') }

$scanArgs = [System.Collections.Generic.List[string]]::new()
$scanArgs.Add($subcmd)
if ($Scanners)      { $scanArgs.AddRange([string[]]@('--scanners', ($Scanners -join ','))) }
if ($Severity)      { $scanArgs.AddRange([string[]]@('--severity', ($Severity -join ','))) }
if ($Branch)        { $scanArgs.AddRange([string[]]@('--branch', $Branch)) }
if ($Tag)           { $scanArgs.AddRange([string[]]@('--tag', $Tag)) }
if ($Commit)        { $scanArgs.AddRange([string[]]@('--commit', $Commit)) }
if ($Server)        { $scanArgs.AddRange([string[]]@('--server', $Server)) }
if ($Offline)       { $scanArgs.AddRange([string[]]@('--skip-db-update', '--skip-java-db-update', '--skip-check-update', '--offline-scan')) }
if ($IgnoreUnfixed) { $scanArgs.Add('--ignore-unfixed') }
$scanArgs.AddRange([string[]]@('--format', 'json', '--quiet'))
if ($ExtraArgs) { $scanArgs.AddRange([string[]]$ExtraArgs) }

# Builds the full command line for one Trivy pass; paths differ between native and Docker.
function Get-TrivyInvocation([string[]]$PassArgs, [string]$ReportFile, [switch]$CustomChecks) {
    if ($isDocker) {
        $dockerCache = Join-Path $cacheDir 'docker'
        New-Item -ItemType Directory -Force -Path $dockerCache | Out-Null
        $dockerArgs = @(
            'run', '--rm',
            '-e', 'GITHUB_TOKEN', '-e', 'GITLAB_TOKEN',          # forwarded only if set; values stay in the environment
            '-v', "${dockerCache}:/root/.cache/trivy",
            '-v', "${configDir}:/config:ro",
            '-v', "${ignorePath}:/ignore/trivyignore.yaml:ro",
            '-v', "${reportsDir}:/reports"
        )
        $containerTarget = $Target
        if (-not $isRemote) {
            $dockerArgs += @('-v', "${Target}:/src:ro")
            $containerTarget = '/src'
        }
        $checkArgs = if ($CustomChecks) { @('--config-check', '/config/checks', '--check-namespaces', 'user') } else { @() }
        return 'docker', ($dockerArgs + @($DockerImage) + $PassArgs + $checkArgs + @(
            '--config', '/config/trivy.yaml',
            '--ignorefile', '/ignore/trivyignore.yaml',
            '--output', "/reports/$(Split-Path -Leaf $ReportFile)",
            $containerTarget))
    }
    $checkArgs = if ($CustomChecks) { @('--config-check', (Join-Path $configDir 'checks'), '--check-namespaces', 'user') } else { @() }
    return $trivyExe, (@($PassArgs) + $checkArgs + @(
        '--config', (Join-Path $configDir 'trivy.yaml'),
        '--ignorefile', $ignorePath,
        '--cache-dir', $cacheDir,
        '--output', $ReportFile,
        $Target))
}

$cmd, $trivyArgs = Get-TrivyInvocation $scanArgs $jsonReport
Write-Host "> $cmd $($trivyArgs -join ' ')"
$sw = [Diagnostics.Stopwatch]::StartNew()
& $cmd @trivyArgs
$exitCode = $LASTEXITCODE

# Docker Compose pass. Trivy has no built-in Compose checks; the custom check in
# config/checks needs the generic "yaml" misconfig scanner, but enabling that scanner
# together with custom checks makes Trivy treat Kubernetes manifests as plain YAML and
# drop every Kubernetes finding. So Compose runs as a separate pass, merged in below.
$composePass = $exitCode -eq 0 -and $subcmd -ne 'sbom' -and $Scanners -contains 'misconfig' -and (Test-Path $jsonReport)
if ($composePass) {
    $composeReport = Join-Path $reportsDir "$baseName.compose.tmp.json"
    $composeArgs = @($subcmd, '--scanners', 'misconfig', '--misconfig-scanners', 'yaml', '--format', 'json', '--quiet') +
        @($scanArgs | Where-Object { $_ -in '--skip-db-update', '--skip-check-update', '--offline-scan' })
    foreach ($ref in @{ '--branch' = $Branch; '--tag' = $Tag; '--commit' = $Commit }.GetEnumerator()) {
        if ($ref.Value) { $composeArgs += @($ref.Key, $ref.Value) }
    }
    if ($ExtraArgs) { $composeArgs += $ExtraArgs }
    $composeCmd, $composeTrivyArgs = Get-TrivyInvocation $composeArgs $composeReport -CustomChecks
    Write-Host "> (compose pass) $composeCmd $($composeTrivyArgs -join ' ')"
    & $composeCmd @composeTrivyArgs
    if ($LASTEXITCODE -eq 0 -and (Test-Path $composeReport)) {
        $main  = Get-Content -Raw $jsonReport | ConvertFrom-Json
        $extra = Get-Content -Raw $composeReport | ConvertFrom-Json
        $composeResults = @($extra.PSObject.Properties['Results'] | ForEach-Object Value | Where-Object {
            $_ -and $_.PSObject.Properties['Misconfigurations'] -and @($_.Misconfigurations | Where-Object Status -eq 'FAIL')
        })
        if ($composeResults) {
            $existing = if ($main.PSObject.Properties['Results']) { @($main.Results) } else { @() }
            $main | Add-Member -NotePropertyName Results -NotePropertyValue ($existing + $composeResults) -Force
            $main | ConvertTo-Json -Depth 100 | Set-Content -Encoding utf8 $jsonReport
        }
        Remove-Item $composeReport
    }
    else {
        Write-Warning "Compose pass failed (exit code $LASTEXITCODE); the main report is unaffected."
    }
}
$sw.Stop()

# Trivy and DB versions, for comparability between runs.
$versionInfo = $null
if (-not $isDocker) {
    $versionInfo = & $trivyExe version --format json --cache-dir $cacheDir 2>$null | ConvertFrom-Json
}
else {
    $versionInfo = & docker run --rm -v "$(Join-Path $cacheDir 'docker'):/root/.cache/trivy" $DockerImage version --format json 2>$null | ConvertFrom-Json
}

$meta = [ordered]@{
    target          = $Target
    method          = $Method
    name            = $Name
    startedUtc      = $stamp
    durationSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    exitCode        = $exitCode
    trivyVersion    = if ($versionInfo) { $versionInfo.Version } else { $null }
    dbUpdatedAt     = if ($versionInfo -and $versionInfo.PSObject.Properties['VulnerabilityDB']) { $versionInfo.VulnerabilityDB.UpdatedAt } else { $null }
    dbDownloadedAt  = if ($versionInfo -and $versionInfo.PSObject.Properties['VulnerabilityDB']) { $versionInfo.VulnerabilityDB.DownloadedAt } else { $null }
    command         = $cmd
    arguments       = $trivyArgs
    report          = (Split-Path -Leaf $jsonReport)
}
$meta | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $metaReport

if (-not (Test-Path $jsonReport)) {
    Write-Error "Scan failed (exit code $exitCode); no report written. Metadata: $metaReport"
    exit $(if ($exitCode) { $exitCode } else { 1 })
}

# Trivy reports "0 vulnerabilities" both for a clean project and for one whose dependency
# files it could not use (e.g. no lock file). Make the second case explicit.
if ($subcmd -ne 'sbom' -and (-not $Scanners -or $Scanners -contains 'vuln')) {
    $parsed = Get-Content -Raw $jsonReport | ConvertFrom-Json
    $allResults = if ($parsed.PSObject.Properties['Results']) { @($parsed.Results) } else { @() }
    $depResults = @($allResults | Where-Object { $_ -and $_.Class -eq 'lang-pkgs' })
    if ($depResults.Count -eq 0) {
        Write-Warning ('No dependency lock files or manifests were analysed. A result of 0 vulnerabilities ' +
            'means "not assessed", not "clean". Check for missing lock files (see docs/methods.md).')
    }
}

# Extra formats are derived from the JSON report, so the target is scanned only once.
foreach ($f in $Format) {
    $ext = switch ($f) {
        'table'     { 'txt' }
        'sarif'     { 'sarif' }
        'cyclonedx' { 'cdx.json' }
        'spdx-json' { 'spdx.json' }
        'github'    { 'github.json' }
    }
    $out = Join-Path $reportsDir "$baseName.$ext"
    & $trivyExe convert --format $f --output $out $jsonReport
    if ($LASTEXITCODE -ne 0) { Write-Warning "Conversion to $f failed (exit code $LASTEXITCODE)." }
}

Write-Host ("Done in {0}s, exit code {1}. Report: {2}" -f $meta.durationSeconds, $exitCode, $jsonReport)
exit $exitCode
