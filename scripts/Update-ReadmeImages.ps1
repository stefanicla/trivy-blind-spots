<#
.SYNOPSIS
    Re-creates the terminal screenshots in docs/images/ from real runs of the lab.

.DESCRIPTION
    Runs the lab scripts, captures their console output and renders each capture with
    New-TerminalSvg.ps1 (which removes local paths). The HTML pages are captured as PNG
    screenshots with a headless browser. Produces:
      coverage-matrix.svg        Invoke-CoverageMatrix.ps1 (rows where the variants differ are shown twice)
      coverage-matrix.png        the matrix.html page of the same run
      trivy-command.svg          the command table printed before every Trivy call
      silent-zero.svg            a .csproj-only project: "not assessed" warning
      lockfile-before-after.svg  the same project before/after New-LockFile.ps1   (needs Docker)
      compose-check.svg          custom Docker Compose check findings
      scan-report.png            the HTML report of the known-answer test
      bulk-summary.svg           latest real-repository reports in reports/ (run Invoke-TrivyBulk.ps1 first)

    Prerequisites: scripts\Install-Trivy.ps1 has been run; Docker is running; Microsoft Edge
    or Google Chrome is installed for the PNG screenshots (skipped with a warning otherwise).

.EXAMPLE
    .\scripts\Update-ReadmeImages.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Stable, English number formatting in the captures regardless of the host locale.
[Threading.Thread]::CurrentThread.CurrentCulture   = 'en-GB'
[Threading.Thread]::CurrentThread.CurrentUICulture = 'en-GB'

$repoRoot = Split-Path -Parent $PSScriptRoot
$images   = Join-Path $repoRoot 'docs\images'
$svg      = Join-Path $PSScriptRoot 'New-TerminalSvg.ps1'
$scan     = Join-Path $PSScriptRoot 'Invoke-TrivyScan.ps1'
$convert  = Join-Path $PSScriptRoot 'Convert-Report.ps1'
$fixtures = Join-Path $repoRoot 'fixtures\ecosystems'
$tmp      = Join-Path $repoRoot ('reports\readme-images-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Push-Location $repoRoot

# Runs a script block and returns its console output (all streams) as text, without the
# Trivy command boxes printed by Write-TrivyCommand (lines starting with a box-drawing corner,
# side or tee) and the "Readable report:" line, so the screenshots keep their compact layout.
# -KeepCommand keeps them.
function Get-ConsoleText([scriptblock]$Block, [switch]$KeepCommand) {
    $out = & $Block *>&1 | ForEach-Object {
        if ($_ -is [Management.Automation.WarningRecord]) { "WARNING: $($_.Message)" } else { "$_" }
    }
    $lines = (@($out) -join "`n") -split "`n"
    if (-not $KeepCommand) { $lines = $lines | Where-Object { $_ -notmatch '^[\u250C\u2502\u251C\u2514]|^Readable report: ' } }
    $lines | Out-String -Width 200
}

# Saves the top of an HTML page as a PNG with a headless Edge or Chrome. A PNG cannot be
# sanitised afterwards like the SVG text, so a page that shows a local path is not captured.
function Save-PageScreenshot([string]$Path, [string]$OutFile, [string]$Size) {
    $browser = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                 "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
                 "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $browser) { Write-Warning "Microsoft Edge or Google Chrome not found; $(Split-Path -Leaf $OutFile) not updated."; return }
    $html = Get-Content -Raw $Path
    foreach ($local in $repoRoot, $HOME) {
        if ($html.Contains($local)) { Write-Warning "$Path shows the local path $local; $(Split-Path -Leaf $OutFile) not updated."; return }
    }
    $url  = 'file:///' + ($Path -replace '\\', '/' -replace ' ', '%20')
    $shot = Join-Path $tmp (Split-Path -Leaf $OutFile)
    # Dark theme, like the terminal screenshots, whatever the theme of this machine.
    $browserArgs = '--headless', '--disable-gpu', '--hide-scrollbars', '--force-dark-mode', "--user-data-dir=""$tmp\browser-profile""",
                   "--window-size=$Size", "--screenshot=""$shot""", """$url"""
    Start-Process -FilePath $browser -ArgumentList $browserArgs -Wait -NoNewWindow `
        -RedirectStandardOutput "$tmp\browser.out" -RedirectStandardError "$tmp\browser.err"
    if (-not (Test-Path $shot)) { throw "Screenshot of $Path failed." }
    Move-Item -Force $shot $OutFile
    Write-Host "Wrote $OutFile ($Size)"
}

function Get-ShortName([string]$Report) { $Report -replace '_(repo|fs|sbom|docker-\w+)_\d{8}T\d{6}Z\.json$', '' }

function Get-LatestReport([string]$Prefix) {
    Get-ChildItem (Join-Path $repoRoot 'reports') -Filter "${Prefix}_*.json" -File |
        Where-Object Name -NotMatch '\.(meta|cdx|spdx|github)\.json$' | Sort-Object Name | Select-Object -Last 1
}

try {
    # 1. Coverage matrix
    $rows = & (Join-Path $PSScriptRoot 'Invoke-CoverageMatrix.ps1') -PassThru 6>$null
    $cols = 'Case', 'Variant', 'DepFiles', 'Packages', 'Direct', 'Transitive', 'Dev', 'Misconfig', 'Secret'
    $shown = foreach ($group in $rows | Group-Object Case) {
        $d = $group.Group | Where-Object Variant -eq 'default'
        $m = $group.Group | Where-Object Variant -eq 'maximum'
        $d
        if ($m -and (($cols | ForEach-Object { "$($d.$_)" }) -join '|') -ne (($cols | ForEach-Object { "$($m.$_)" }) -join '|').Replace('maximum', 'default')) { $m }
    }
    $text = "PS> .\scripts\Invoke-CoverageMatrix.ps1`n" + ($shown | Format-Table $cols -AutoSize | Out-String -Width 200)
    & $svg -Text $text -Title 'Ecosystem coverage matrix (found / expected)' -OutFile (Join-Path $images 'coverage-matrix.svg')
    $matrixHtml = Get-ChildItem (Join-Path $repoRoot 'reports') -Directory -Filter 'matrix-*' | Sort-Object Name |
        Select-Object -Last 1 | ForEach-Object { Join-Path $_.FullName 'matrix.html' }
    Save-PageScreenshot $matrixHtml (Join-Path $images 'coverage-matrix.png') '1800,1064'

    # 1b. The command table printed before every Trivy call
    $text = "PS> .\scripts\Invoke-TrivyScan.ps1 -Target .\fixtures\ecosystems\node-npm-lock -Method fs -Name npm-lock`n" +
        (Get-ConsoleText { & $scan -Target (Join-Path $fixtures 'node-npm-lock') -Method fs -Name 'npm-lock' } -KeepCommand)
    & $svg -Text $text -Title 'Every Trivy call is printed as a table' -OutFile (Join-Path $images 'trivy-command.svg')

    # 2. Silent zero on a .csproj-only project
    $csproj = Join-Path $fixtures 'cs-csproj-only'
    $text = "PS> .\scripts\Invoke-TrivyScan.ps1 -Target .\fixtures\ecosystems\cs-csproj-only -Method fs -Name csproj-only`n" +
        (Get-ConsoleText { & $scan -Target $csproj -Method fs -Name 'csproj-only' })
    & $svg -Text $text -Title 'A .csproj-only project: 0 vulnerabilities means "not assessed"' -OutFile (Join-Path $images 'silent-zero.svg')

    # 3. Before / after lock-file generation
    $locked = Join-Path $tmp 'cs-csproj-only-locked'
    & (Join-Path $PSScriptRoot 'New-LockFile.ps1') -Source $csproj -Destination $locked *>$null
    & $scan -Target $locked -Method fs -Name 'csproj-only-locked' *>$null
    $before = Get-LatestReport 'csproj-only'
    $after  = Get-LatestReport 'csproj-only-locked'
    $table = & $convert -Path $before.FullName, $after.FullName |
        Select-Object @{ n = 'Report'; e = { Get-ShortName $_.Report } }, DepFiles, Vulns, CRITICAL, HIGH, MEDIUM, LOW |
        Format-Table -AutoSize | Out-String -Width 200
    $text = "PS> .\scripts\New-LockFile.ps1 -Source .\fixtures\ecosystems\cs-csproj-only`n" +
        "PS> .\scripts\Invoke-TrivyScan.ps1 -Target .\workspace\cs-csproj-only-locked -Method fs`n" +
        "PS> .\scripts\Convert-Report.ps1 -Path <before>, <after>`n$table"
    & $svg -Text $text -Title 'Generating the missing packages.lock.json' -OutFile (Join-Path $images 'lockfile-before-after.svg')

    # 4. Custom Docker Compose check
    $composeCase = Join-Path $fixtures 'iac-compose'
    & $scan -Target $composeCase -Method fs -Scanners misconfig -Name 'compose-check' *>$null
    $report = Get-Content -Raw (Get-LatestReport 'compose-check').FullName | ConvertFrom-Json
    $findings = foreach ($r in @($report.Results)) {
        foreach ($m in @($r.Misconfigurations | Where-Object { $_.Status -eq 'FAIL' -and $_.ID -eq 'CMP-0001' })) {
            '{0,-20} {1}  {2}' -f $r.Target, $m.ID, $m.Message
        }
    }
    $text = "PS> .\scripts\Invoke-TrivyScan.ps1 -Target .\fixtures\ecosystems\iac-compose -Method fs -Scanners misconfig`n" +
        "PS> # CMP-0001 findings from config/checks/compose.rego`n`n" + ($findings -join "`n")
    & $svg -Text $text -Title 'Docker Compose: custom Rego check' -OutFile (Join-Path $images 'compose-check.svg')

    # 4b. HTML report of the known-answer test (vulnerabilities, secrets, misconfigurations)
    & (Join-Path $PSScriptRoot 'Test-KnownAnswer.ps1') *>$null
    $knownAnswer = (Get-LatestReport 'known-answer').FullName -replace '\.json$', '.html'
    Save-PageScreenshot $knownAnswer (Join-Path $images 'scan-report.png') '1200,880'

    # 5. Real-world bulk summary (from the most recent Invoke-TrivyBulk.ps1 run)
    $names = 'WebGoat.NET', 'dvcsharp-api', 'eShop', 'CleanArchitecture', 'pygoat', 'Vulnerable-Flask-App',
             'full-stack-fastapi-template', 'NodeGoat', 'nodejs-goof', 'juice-shop', 'terragoat', 'kubernetes-goat'
    $latest = foreach ($n in $names) { Get-LatestReport $n }
    if ($latest) {
        $table = & $convert -Path $latest.FullName |
            Select-Object @{ n = 'Repository'; e = { Get-ShortName $_.Report } }, DepFiles, Vulns, CRITICAL, HIGH, Secrets, Misconfigs |
            Format-Table -AutoSize | Out-String -Width 200
        $text = "PS> .\scripts\Invoke-TrivyBulk.ps1 -Scanners vuln,secret,misconfig`n" +
            "PS> .\scripts\Convert-Report.ps1 -Path <latest reports>`n$table"
        & $svg -Text $text -Title 'Real repositories: C#, Python, Node/TS, IaC' -OutFile (Join-Path $images 'bulk-summary.svg')
    }
    else {
        Write-Warning 'No real-repository reports found; run Invoke-TrivyBulk.ps1 first. bulk-summary.svg not updated.'
    }
}
finally {
    Pop-Location
}
