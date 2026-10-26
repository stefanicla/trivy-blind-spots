# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
