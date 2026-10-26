<#
.SYNOPSIS
    Renders captured console text as an SVG "terminal window" for the documentation.

.DESCRIPTION
    Before rendering, the text is sanitised so that no local details are published:
      - the repository root becomes "."
      - any Windows user profile path (C:\Users\<name>, including 8.3 short names) becomes "~"
      - ANSI escape sequences are removed
      - localised PowerShell warning prefixes are normalised to "WARNING:"
    Lines starting with "PS> " are drawn as prompts, lines starting with "WARNING:" in amber.

.EXAMPLE
    .\scripts\New-TerminalSvg.ps1 -Text (Get-Content capture.txt -Raw) -Title 'Coverage matrix' -OutFile docs\images\matrix.svg
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Text,

    [Parameter(Mandatory)]
    [string]$OutFile,

    [string]$Title = 'PowerShell',

    # Longer lines are word-wrapped (continuation lines are indented), like a terminal window.
    [int]$WrapAt = 110
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
# .NET file APIs resolve relative paths against the process directory, not the PowerShell location.
$OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)

# --- Sanitise
$clean = $Text -replace "`e\[[0-9;?]*[A-Za-z]", ''
foreach ($root in @($repoRoot, ($repoRoot -replace '\\', '/'))) {
    $clean = $clean.Replace($root, '.')
}
$clean = $clean -replace '(?i)[A-Z]:[\\/]Users[\\/][^\\/\s"'']+', '~'
$clean = $clean -replace '(?m)^(AVVISO|WARNUNG|AVERTISSEMENT|ADVERTENCIA):', 'WARNING:'
$lines = @(($clean -replace "`r", '').TrimEnd() -split "`n")
while ($lines.Count -and -not $lines[0].Trim()) { $lines = @($lines | Select-Object -Skip 1) }

# Colour class per source line; wrapped continuation lines keep it and are indented.
$lines = @(foreach ($line in $lines) {
    $class = if ($line -like 'PS> *') { 'prompt' }
             elseif ($line -like 'WARNING:*') { 'warn' }
             elseif ($line -match '^\s*-{3,}[\s-]*$') { 'dim' }
             else { 'out' }
    $indent = ''
    while ($line.Length -gt $WrapAt) {
        $cut = $line.LastIndexOf(' ', $WrapAt)
        if ($cut -le $indent.Length) { $cut = $WrapAt }
        [pscustomobject]@{ Text = $line.Substring(0, $cut).TrimEnd(); Class = $class }
        $indent = '    '
        $line = $indent + $line.Substring($cut).TrimStart()
    }
    [pscustomobject]@{ Text = $line; Class = $class }
})

# --- Layout
$fontSize   = 13
$charWidth  = 7.85          # approximate advance of common monospace fonts at 13 px
$lineHeight = 18
$padX       = 16
$titleBar   = 30
$maxChars   = [Math]::Max(40, ($lines | ForEach-Object { $_.Text.Length } | Measure-Object -Maximum).Maximum)
$width      = [int][Math]::Ceiling($maxChars * $charWidth + 2 * $padX)
$height     = $titleBar + 14 + $lines.Count * $lineHeight + 12

function ConvertTo-XmlText([string]$s) {
    [Security.SecurityElement]::Escape($s)
}

$sb = [Text.StringBuilder]::new()
[void]$sb.AppendLine("<svg xmlns=`"http://www.w3.org/2000/svg`" width=`"$width`" height=`"$height`" viewBox=`"0 0 $width $height`" role=`"img`" aria-label=`"$(ConvertTo-XmlText $Title)`">")
[void]$sb.AppendLine('  <style>')
[void]$sb.AppendLine("    text { font-family: ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace; font-size: ${fontSize}px; white-space: pre; }")
[void]$sb.AppendLine('    .out { fill: #e6edf3; } .prompt { fill: #7ee787; } .warn { fill: #e3b341; } .dim { fill: #8b949e; } .title { fill: #8b949e; font-size: 12px; }')
[void]$sb.AppendLine('  </style>')
[void]$sb.AppendLine("  <rect width=`"$width`" height=`"$height`" rx=`"8`" fill=`"#0d1117`" stroke=`"#30363d`"/>")
[void]$sb.AppendLine("  <rect width=`"$width`" height=`"$titleBar`" rx=`"8`" fill=`"#161b22`"/>")
[void]$sb.AppendLine("  <rect y=`"$($titleBar - 8)`" width=`"$width`" height=`"8`" fill=`"#161b22`"/>")
[void]$sb.AppendLine('  <circle cx="18" cy="15" r="6" fill="#ff5f56"/><circle cx="38" cy="15" r="6" fill="#ffbd2e"/><circle cx="58" cy="15" r="6" fill="#27c93f"/>')
[void]$sb.AppendLine("  <text class=`"title`" x=`"$([int]($width / 2))`" y=`"19`" text-anchor=`"middle`">$(ConvertTo-XmlText $Title)</text>")

$y = $titleBar + 14 + $fontSize
foreach ($line in $lines) {
    [void]$sb.AppendLine("  <text class=`"$($line.Class)`" x=`"$padX`" y=`"$y`" xml:space=`"preserve`">$(ConvertTo-XmlText $line.Text)</text>")
    $y += $lineHeight
}
[void]$sb.AppendLine('</svg>')

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
[IO.File]::WriteAllText($OutFile, $sb.ToString())
Write-Host "Wrote $OutFile ($($lines.Count) lines, ${width}x${height})"
