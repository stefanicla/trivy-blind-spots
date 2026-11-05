<#
.SYNOPSIS
    Helpers shared by the lab scripts: readable Trivy command echoes and self-contained HTML pages.

.DESCRIPTION
    Dot-source it from a script in scripts/:
        . (Join-Path $PSScriptRoot 'lib\TrivyLab.ps1')
    The file stays ASCII-only so that it reads the same in any PowerShell host; box-drawing
    characters are built from their code points.
#>

$script:BoxTop    = [string][char]0x250C   # top-left corner
$script:BoxSide   = [string][char]0x2502   # vertical line
$script:BoxTee    = [string][char]0x251C   # section separator
$script:BoxBottom = [string][char]0x2514   # bottom-left corner
$script:BoxLine   = [string][char]0x2500   # horizontal line

function Get-Prop($Object, [string]$Name) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { $Object.$Name } else { $null }
}

# Shortens paths under the repository root to .\relative\path, also inside values such as
# "C:\repo\cache:/root/.cache/trivy". Other text is returned unchanged.
function Get-RepoRelativePath([string]$Text, [string]$RepoRoot) {
    if ($Text.StartsWith('@')) { return '@' + (Get-RepoRelativePath $Text.Substring(1) $RepoRoot) }   # --template @file
    if (-not $RepoRoot -or -not $Text.StartsWith($RepoRoot, [StringComparison]::OrdinalIgnoreCase)) { return $Text }
    $rest = $Text.Substring($RepoRoot.Length)
    if ($rest -and $rest[0] -notin '\', '/', ':') { return $Text }   # a sibling such as C:\repo-other
    '.' + $rest
}

# Splits arguments into labelled rows: the first bare word is the subcommand, the last one the
# target (with -HasTarget), and an option takes the next token as its value unless that token
# is another option or the target.
function ConvertTo-ArgumentRow([string[]]$Arguments, [string]$RepoRoot, [string]$Section, [switch]$HasTarget) {
    $head  = [System.Collections.Generic.List[object]]::new()
    $flags = [System.Collections.Generic.List[object]]::new()
    $last  = if ($HasTarget) { $Arguments.Count - 1 } else { $Arguments.Count }
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $a = Get-RepoRelativePath $Arguments[$i] $RepoRoot
        if ($a.StartsWith('-')) {
            $value = ''
            if ($i + 1 -lt $last -and -not $Arguments[$i + 1].StartsWith('-')) {
                $i++
                $value = Get-RepoRelativePath $Arguments[$i] $RepoRoot
            }
            $flags.Add([pscustomobject]@{ Section = $Section; Name = $a; Value = $value })
        }
        else {
            $label = if ($i -eq $last) { if ($Arguments[0] -eq 'convert') { 'input' } else { 'target' } }
                     elseif ($i -eq 0) { 'subcommand' } else { 'argument' }
            $head.Add([pscustomobject]@{ Section = $Section; Name = $label; Value = $a })
        }
    }
    @($head) + @($flags)
}

# Rows describing one Trivy invocation, native or through `docker run <options> <image> <trivy arguments>`.
function Get-TrivyCommandRow([string]$Command, [string[]]$Arguments, [string]$RepoRoot) {
    $rows = @([pscustomobject]@{ Section = 'trivy'; Name = 'executable'; Value = (Get-RepoRelativePath $Command $RepoRoot) })
    if ((Split-Path -Leaf $Command) -notmatch '^docker(\.exe)?$') {
        return $rows + (ConvertTo-ArgumentRow $Arguments $RepoRoot 'trivy' -HasTarget)
    }
    # The image is the first token after `run` that is neither a docker option nor an option value.
    $i = 1
    while ($i -lt $Arguments.Count -and $Arguments[$i].StartsWith('-')) {
        $i += if ($i + 1 -lt $Arguments.Count -and -not $Arguments[$i + 1].StartsWith('-')) { 2 } else { 1 }
    }
    $rows[0].Section = 'docker'
    $rows += ConvertTo-ArgumentRow $Arguments[0..($i - 1)] $RepoRoot 'docker'
    if ($i -lt $Arguments.Count) {
        $rows += [pscustomobject]@{ Section = 'docker'; Name = 'image'; Value = $Arguments[$i] }
    }
    if ($i + 1 -lt $Arguments.Count) {
        $rows += ConvertTo-ArgumentRow $Arguments[($i + 1)..($Arguments.Count - 1)] $RepoRoot 'trivy (in container)' -HasTarget
    }
    $rows
}

<#
    Prints a Trivy invocation as a flag / value box before it runs:
        +- Trivy: main pass ---------------
        | executable   .\tools\trivy.exe
        | subcommand   repo
        | --scanners   vuln,secret,misconfig
        +----------------------------------
    Each line is a single Write-Host call so that Update-ReadmeImages.ps1 can drop the box
    from its captures by the first character of each line.
#>
function Write-TrivyCommand([string]$Title, [string]$Command, [string[]]$Arguments, [string]$RepoRoot) {
    $rows  = @(Get-TrivyCommandRow $Command $Arguments $RepoRoot)
    $width = ($rows | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $lines = foreach ($r in $rows) { ('{0} {1}  {2}' -f $script:BoxSide, $r.Name.PadRight($width), $r.Value).TrimEnd() }
    $ruler = [math]::Min(100, [math]::Max(40, ($lines | Measure-Object -Property Length -Maximum).Maximum))

    $top = "$script:BoxTop$script:BoxLine $Title "
    Write-Host ($top + $script:BoxLine * [math]::Max(3, $ruler - $top.Length)) -ForegroundColor Cyan
    $section = $rows[0].Section
    for ($i = 0; $i -lt $rows.Count; $i++) {
        if ($rows[$i].Section -ne $section) {
            $section = $rows[$i].Section
            Write-Host "$script:BoxTee$script:BoxLine $section" -ForegroundColor DarkGray
        }
        Write-Host $lines[$i]
    }
    Write-Host ($script:BoxBottom + $script:BoxLine * ($ruler - 1)) -ForegroundColor DarkGray
}

<#
    Every report format Trivy can produce natively from a JSON report with `trivy convert`.
    Single source for Invoke-TrivyScan.ps1 -Format, Invoke-FormatShowcase.ps1 and
    docs/report-formats.md. The template entries use the official templates that
    Install-Trivy.ps1 copies to tools/contrib/. Template paths need the leading "@":
    without it Trivy treats the value as the template text itself.

    Word: yes  = renders as real tables when opened in, or pasted into, Microsoft Word
          poor = plain text that only lines up in a monospace font
          no   = machine-readable data (JSON, XML, SBOM)
    The -Format ValidateSet lists in the scripts must match the Name values below.
#>
function Get-TrivyFormatCatalog([string]$RepoRoot) {
    $tpl = { param($File) @('--format', 'template', '--template', ('@' + [IO.Path]::Combine($RepoRoot, 'tools', 'contrib', $File))) }
    @(
        [pscustomobject]@{ Name = 'json'; Extension = 'json'; Word = 'no'; Audience = 'Automation, archiving'
            Description = 'Complete Trivy report: every finding class, all packages. The source for every other format.'
            Arguments = @('--format', 'json') }
        [pscustomobject]@{ Name = 'table'; Extension = 'table.txt'; Word = 'poor'; Audience = 'People at a console'
            Description = 'Summary table per target, then one detailed table per finding class.'
            Arguments = @('--format', 'table', '--scanners', 'vuln,secret,misconfig,license') }
        [pscustomobject]@{ Name = 'table-summary'; Extension = 'summary.txt'; Word = 'poor'; Audience = 'People at a console'
            Description = 'Only the summary table: finding counts per target and class, no finding details.'
            Arguments = @('--format', 'table', '--table-mode', 'summary', '--scanners', 'vuln,secret,misconfig,license') }
        [pscustomobject]@{ Name = 'sarif'; Extension = 'sarif'; Word = 'no'; Audience = 'GitHub code scanning, IDEs'
            Description = 'SARIF 2.1.0: one rule and one result per finding, with file locations.'
            Arguments = @('--format', 'sarif') }
        [pscustomobject]@{ Name = 'cyclonedx'; Extension = 'cdx.json'; Word = 'no'; Audience = 'SBOM / VEX tooling'
            Description = 'CycloneDX SBOM: component inventory plus a vulnerabilities section. No secrets or misconfigurations.'
            Arguments = @('--format', 'cyclonedx') }
        [pscustomobject]@{ Name = 'spdx'; Extension = 'spdx'; Word = 'no'; Audience = 'SBOM / licence tooling'
            Description = 'SPDX 2.3 SBOM, tag-value text: package inventory. Vulnerabilities appear only as advisory links on each package (no severity, no fixed version).'
            Arguments = @('--format', 'spdx') }
        [pscustomobject]@{ Name = 'spdx-json'; Extension = 'spdx.json'; Word = 'no'; Audience = 'SBOM / licence tooling'
            Description = 'SPDX 2.3 SBOM, JSON: as spdx, in JSON.'
            Arguments = @('--format', 'spdx-json') }
        [pscustomobject]@{ Name = 'github'; Extension = 'github.json'; Word = 'no'; Audience = 'GitHub dependency graph'
            Description = 'GitHub dependency snapshot: manifests and the packages they resolve to. No findings at all.'
            Arguments = @('--format', 'github') }
        [pscustomobject]@{ Name = 'cosign-vuln'; Extension = 'cosign-vuln.json'; Word = 'no'; Audience = 'Signed attestations (cosign attest)'
            Description = 'Cosign vulnerability attestation predicate; it wraps the complete Trivy JSON report.'
            Arguments = @('--format', 'cosign-vuln') }
        [pscustomobject]@{ Name = 'html'; Extension = 'trivy.html'; Word = 'yes'; Audience = 'People; Word documents'
            Description = 'Official html.tpl: HTML tables of vulnerabilities and misconfigurations, one section per file headed by its type (not its name). No secrets.'
            Arguments = (& $tpl 'html.tpl') }
        [pscustomobject]@{ Name = 'junit'; Extension = 'junit.xml'; Word = 'no'; Audience = 'CI test reports (Jenkins, GitLab, Azure DevOps)'
            Description = 'Official junit.tpl: each finding (vulnerability, misconfiguration, secret, licence) is a failed test case.'
            Arguments = (& $tpl 'junit.tpl') }
        [pscustomobject]@{ Name = 'gitlab'; Extension = 'gitlab.json'; Word = 'no'; Audience = 'GitLab dependency / container scanning'
            Description = 'Official gitlab.tpl: GitLab security report schema. Vulnerabilities only.'
            Arguments = (& $tpl 'gitlab.tpl') }
        [pscustomobject]@{ Name = 'gitlab-codequality'; Extension = 'codequality.json'; Word = 'no'; Audience = 'GitLab Code Quality widget'
            Description = 'Official gitlab-codequality.tpl: Code Climate issues for vulnerabilities, misconfigurations and secrets.'
            Arguments = (& $tpl 'gitlab-codequality.tpl') }
        [pscustomobject]@{ Name = 'asff'; Extension = 'asff.json'; Word = 'no'; Audience = 'AWS Security Hub'
            Description = 'Official asff.tpl: AWS Security Finding Format for vulnerabilities, misconfigurations and secrets. Reads AWS_REGION and AWS_ACCOUNT_ID from the environment (empty when unset).'
            Arguments = (& $tpl 'asff.tpl') }
    )
}

function ConvertTo-HtmlText($Text) { [System.Net.WebUtility]::HtmlEncode([string]$Text) }

$script:SeverityOrder = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; UNKNOWN = 4 }

function Get-SeverityHtml([string]$Severity) {
    $s = if ($script:SeverityOrder.ContainsKey("$Severity")) { $Severity } else { 'UNKNOWN' }
    "<span class=""sev sev-$s"">$(ConvertTo-HtmlText $Severity)</span>"
}

# The same rows as Write-TrivyCommand, as an HTML table.
function ConvertTo-CommandHtml([string]$Command, [string[]]$Arguments, [string]$RepoRoot) {
    $sb = [System.Text.StringBuilder]::new('<table class="cmd"><tbody>')
    $section = $null
    foreach ($r in Get-TrivyCommandRow $Command $Arguments $RepoRoot) {
        if ($section -and $r.Section -ne $section) {
            [void]$sb.Append("<tr><th colspan=""2"">$(ConvertTo-HtmlText $r.Section)</th></tr>")
        }
        $section = $r.Section
        [void]$sb.Append("<tr><td class=""mono"">$(ConvertTo-HtmlText $r.Name)</td><td class=""mono"">$(ConvertTo-HtmlText $r.Value)</td></tr>")
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

# A complete, self-contained HTML page (inline CSS, no scripts, light and dark themes).
function ConvertTo-HtmlPage([string]$Title, [string]$Body) {
    $css = @'
:root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --border:#d1d9e0; --panel:#f6f8fa; --link:#0969da;
  --crit:#a40e26; --high:#bc4c00; --med:#9a6700; --low:#1a7f37; --unk:#59636e;
  --ok-bg:#dafbe1; --ok-fg:#116329; --part-bg:#fff8c5; --part-fg:#7d4e00; --miss-bg:#ffebe9; --miss-fg:#a40e26; --na-fg:#818b98; --diff:#8250df; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --border:#3d444d; --panel:#151b23; --link:#4493f8;
    --crit:#f85149; --high:#db6d28; --med:#d29922; --low:#3fb950; --unk:#9198a1;
    --ok-bg:#12261e; --ok-fg:#3fb950; --part-bg:#272115; --part-fg:#d29922; --miss-bg:#2d1214; --miss-fg:#f85149; --na-fg:#656c76; --diff:#ab7df8; }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1800px; padding: 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
h1 { font-size: 22px; margin: 4px 0 12px; } h2 { font-size: 18px; margin: 24px 0 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
a { color: var(--link); }
.muted { color: var(--muted); }
.mono, code { font-family: Consolas, "Cascadia Mono", Menlo, monospace; font-size: 13px; }
.wrap { overflow-x: auto; }
.nowrap { white-space: nowrap; }
table { border-collapse: collapse; margin: 8px 0 16px; }
th, td { border: 1px solid var(--border); padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: var(--panel); }
td.num, th.num { text-align: right; }
table.meta th { width: 160px; }
table.cmd td:first-child { white-space: nowrap; }
.sev { display: inline-block; min-width: 72px; padding: 0 6px; border-radius: 4px; font-size: 12px; font-weight: 600; text-align: center; color: var(--bg); }
.sev-CRITICAL { background: var(--crit); } .sev-HIGH { background: var(--high); } .sev-MEDIUM { background: var(--med); }
.sev-LOW { background: var(--low); } .sev-UNKNOWN { background: var(--unk); }
.cards { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.card { border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; min-width: 110px; background: var(--panel); }
.card .n { font-size: 22px; font-weight: 600; } .card .l { color: var(--muted); font-size: 12px; }
.card.CRITICAL .n { color: var(--crit); } .card.HIGH .n { color: var(--high); } .card.MEDIUM .n { color: var(--med); }
.card.LOW .n { color: var(--low); } .card.warn { border-color: var(--miss-fg); }
.banner { border: 1px solid var(--part-fg); background: var(--part-bg); color: var(--part-fg); padding: 8px 12px; border-radius: 6px; margin: 12px 0; }
details { border: 1px solid var(--border); border-radius: 6px; padding: 4px 12px; margin: 8px 0; }
summary { cursor: pointer; font-weight: 600; padding: 2px 0; }
summary .sev { min-width: 0; margin-left: 4px; }
.ok { background: var(--ok-bg); color: var(--ok-fg); } .part { background: var(--part-bg); color: var(--part-fg); }
.miss { background: var(--miss-bg); color: var(--miss-fg); font-weight: 600; } .na { color: var(--na-fg); text-align: center; }
tr.group th { background: var(--bg); font-size: 15px; padding-top: 14px; border-left: 0; border-right: 0; }
tr.diff td:first-child { box-shadow: inset 4px 0 0 var(--diff); }
.diffmark { color: var(--diff); font-weight: 600; }
pre { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; overflow-x: auto;
  font-family: Consolas, "Cascadia Mono", Menlo, monospace; font-size: 12px; line-height: 1.4; }
'@
    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
$css
</style>
</head>
<body>
$Body
</body>
</html>
"@
}
