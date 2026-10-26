<#
.SYNOPSIS
    Known-answer test: builds the local fixture, scans it and checks every seeded finding.

.DESCRIPTION
    Used by the CI smoke job and runnable locally. Checks are presence-based (each seeded
    package has at least one vulnerability, etc.) so vulnerability-DB updates do not break
    them. It also asserts the documented gap: a secret that exists only in Git history is
    NOT reported by Trivy.

    Exit code 0 when every check passes, 1 otherwise.

.EXAMPLE
    .\scripts\Install-Trivy.ps1
    .\scripts\Test-KnownAnswer.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$fixture  = Join-Path $repoRoot 'workspace\fixture-local'

& (Join-Path $PSScriptRoot 'New-Fixture.ps1') | Out-Null
& (Join-Path $PSScriptRoot 'Invoke-TrivyScan.ps1') -Target $fixture -Method repo -Scanners vuln, secret, misconfig -Name 'known-answer' | Out-Host

$report = Get-ChildItem (Join-Path $repoRoot 'reports') -Filter 'known-answer_*.json' -File |
    Where-Object Name -NotMatch '\.meta\.json$' | Sort-Object Name | Select-Object -Last 1
$results = @((Get-Content -Raw $report.FullName | ConvertFrom-Json).Results)

$vulnPkgs = @($results | Where-Object { $_.PSObject.Properties['Vulnerabilities'] -and $_.Vulnerabilities } |
    ForEach-Object { $_.Vulnerabilities.PkgName }) | Sort-Object -Unique
$secrets = @($results | Where-Object { $_.PSObject.Properties['Secrets'] -and $_.Secrets } |
    ForEach-Object { $t = $_.Target; $_.Secrets | ForEach-Object { "$t|$($_.RuleID)" } })
$misconfigTargets = @($results | Where-Object {
        $_.PSObject.Properties['Misconfigurations'] -and @($_.Misconfigurations | Where-Object Status -eq 'FAIL')
    } | ForEach-Object Target)

$checks = [ordered]@{}
foreach ($pkg in 'Django', 'Jinja2', 'requests', 'PyYAML', 'lodash') {
    $checks["vulnerability in $pkg"] = $vulnPkgs -contains $pkg
}
$checks['GitHub token in config/settings.py']    = $secrets -contains 'config/settings.py|github-pat'
$checks['misconfiguration in Dockerfile']        = $misconfigTargets -contains 'Dockerfile'
$checks['misconfiguration in main.tf']           = $misconfigTargets -contains 'main.tf'
$checks['history-only AWS key NOT reported (documented gap)'] = -not ($secrets | Where-Object { $_ -like 'config/aws.env|*' })

$failed = 0
foreach ($c in $checks.GetEnumerator()) {
    $mark = if ($c.Value) { 'PASS' } else { $failed++; 'FAIL' }
    Write-Host ('{0}  {1}' -f $mark, $c.Key)
}
if ($failed) {
    Write-Host "$failed check(s) failed."
    exit 1
}
Write-Host 'All known-answer checks passed.'
