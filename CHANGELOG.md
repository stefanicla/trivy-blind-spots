# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Human-readable HTML report for every scan (`ConvertTo-HtmlReport.ps1`, run by
  `Invoke-TrivyScan.ps1`): metadata and command, counts by severity, a "not assessed"
  warning, and findings grouped by file. Secret values are never copied into the page.
- `matrix.html` for the coverage matrix: variants side by side, grouped by ecosystem,
  colour-coded cells.
- `bulk-<UTC>.html` batch summary from `Invoke-TrivyBulk.ps1`, linking each scan's report.
- `Compress-Reports.ps1` archives the contents of `reports/` into a zip.

### Changed

- Every Trivy invocation is printed as a flag / value table with repository-relative
  paths, including the coverage-matrix passes and `trivy convert`.

### Fixed

- `Invoke-TrivyScan.ps1` no longer fails when the Docker Compose pass finds no files to
  check (for example, a project with only `package.json`).

## [0.1.0] - 2026-10-26

First public release of the Trivy repository-scanning lab.

### Added

- Pinned, checksum-verified Trivy 0.76.1 installer (`Install-Trivy.ps1`), and a container
  image pinned by digest.
- Single-target scans of local paths, remote URLs (branch, tag, commit), filesystems,
  SBOMs, and containerised or client/server modes (`Invoke-TrivyScan.ps1`). Each scan
  writes a JSON report, a metadata sidecar and optional converted formats.
- Bulk scanning from a targets file or a GitHub organisation (`Invoke-TrivyBulk.ps1`).
- Report summaries with a `DepFiles` guard against "silent zero" results
  (`Convert-Report.ps1`).
- Ecosystem coverage matrix for C#/.NET, Python, JavaScript/TypeScript, Dockerfile,
  Docker Compose, Kubernetes, Helm and Terraform (`New-EcosystemFixtures.ps1`,
  `Invoke-CoverageMatrix.ps1`).
- Lock-file generation in hardened containers for projects that do not commit lock files
  (`New-LockFile.ps1`).
- Custom Rego check for Docker Compose (`config/checks/compose.rego`), run as a separate
  pass so that Kubernetes findings are kept.
- `file-patterns` so that pip requirements files with non-standard names are analysed.
- Known-answer test (`Test-KnownAnswer.ps1`) and generated terminal screenshots
  (`Update-ReadmeImages.ps1`, `New-TerminalSvg.ps1`).
- Documentation: methods, test plan and results.
- CI: PSScriptAnalyzer, gitleaks, Trivy self-scan with SARIF upload, and a known-answer
  smoke test. Dependabot for GitHub Actions.

[0.1.0]: https://github.com/stefanicla/trivy-blind-spots/releases/tag/v0.1.0
