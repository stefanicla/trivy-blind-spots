# Security policy

## Reporting a vulnerability

Please report security issues **privately**, using GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for a security problem.

Expect an acknowledgement within a week. As this is a personal lab project, fixes are
made on a best-effort basis.

## Supported versions

Only the latest commit on `main` is supported.

## Scope

In scope:

- the PowerShell scripts in `scripts/`;
- the configuration in `config/` (Trivy settings, suppressions, custom Rego checks);
- the CI workflow in `.github/workflows/`;
- the supply-chain pinning described below (for example, a pinned digest or checksum that
  does not match the official release).

Out of scope, by design:

- **`fixtures/`** deliberately contains vulnerable package versions, misconfigured
  Dockerfiles, Compose files, Kubernetes manifests and Terraform, so that the scanners
  have known findings to detect. These are test data, not vulnerabilities in this project.
  Fake secrets are generated at runtime and are never valid.
- **Third-party repositories** scanned by the lab (listed in `targets/targets.txt`).
  Report their issues to their maintainers.
- Vulnerabilities in Trivy, gitleaks or other upstream tools. Report those upstream.

## Supply-chain pinning policy

This lab was built shortly after the March 2026 supply-chain compromise of Trivy
releases (CVE-2026-33634). Therefore:

- the Trivy binary is pinned to an exact version and verified against a hard-coded
  SHA-256 (`scripts/Install-Trivy.ps1`);
- every container image is pinned by digest;
- every GitHub Action is pinned by full commit SHA, and Dependabot proposes updates.

Never install Trivy v0.69.4, v0.69.5 or v0.69.6.

## Handling untrusted code

Repositories cloned or scanned by the lab are untrusted. Trivy only parses files.
`scripts/New-LockFile.ps1` runs package managers in hardened, throw-away containers; note
that `dotnet restore` evaluates MSBuild project files, which can execute code. See the
README for details.
