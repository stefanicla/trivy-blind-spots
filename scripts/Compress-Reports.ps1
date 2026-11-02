<#
.SYNOPSIS
    Moves everything currently in reports/ into a zip archive in reports/archive/.

.DESCRIPTION
    Archives all reports, matrix and image-capture folders (everything except .gitkeep and
    archive/) into reports/archive/reports-<UTC stamp>.zip, checks that the archive holds
    every file, and only then deletes the originals. Use it to start a clean round of scans
    while keeping the earlier results.

    reports/ is git-ignored, so the archives stay local. Coverage-matrix folders contain
    copies of fixtures with an injected fake token; keep the archives out of Git as well.

.EXAMPLE
    .\scripts\Compress-Reports.ps1 -WhatIf

.EXAMPLE
    .\scripts\Compress-Reports.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ReportsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'reports')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$ReportsPath = (Resolve-Path $ReportsPath).Path
$archiveDir  = Join-Path $ReportsPath 'archive'
$items = @(Get-ChildItem $ReportsPath -Force | Where-Object { $_.Name -notin '.gitkeep', 'archive' })
if (-not $items) {
    Write-Host "Nothing to archive in $ReportsPath."
    return
}
$files = @($items | ForEach-Object { if ($_.PSIsContainer) { Get-ChildItem $_.FullName -Recurse -File -Force } else { $_ } })
$zip   = Join-Path $archiveDir ('reports-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '.zip')

if (-not $PSCmdlet.ShouldProcess($ReportsPath, "Archive $($files.Count) files into $zip and delete the originals")) { return }

New-Item -ItemType Directory -Force -Path $archiveDir | Out-Null
Compress-Archive -Path $items.FullName -DestinationPath $zip -CompressionLevel Optimal

# Directory entries have an empty Name; count files only.
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try { $entries = @($archive.Entries | Where-Object { $_.Name }).Count }
finally { $archive.Dispose() }
if ($entries -ne $files.Count) {
    throw "The archive holds $entries files but $($files.Count) were expected. Originals kept; check $zip."
}

$items | Remove-Item -Recurse -Force
Write-Host ("Archived {0} files ({1:N1} MB) to {2}" -f $files.Count, ((Get-Item $zip).Length / 1MB), $zip)
