# Results

Run on 26 October 2026 with Trivy 0.76.1 (vulnerability DB of 2026-10-26 07:15 UTC) on
Windows 11. Scope: **C#/.NET, Python, JavaScript/TypeScript (Node), Terraform, Dockerfile,
Docker Compose, Kubernetes/Helm.** Java is out of scope.

Raw reports are in `reports/` (git-ignored). Re-create them with:

```powershell
.\scripts\Invoke-CoverageMatrix.ps1                          # ecosystem coverage (E16)
.\scripts\Invoke-TrivyBulk.ps1 -Scanners vuln,secret,misconfig   # real repositories (E17)
```

## Executive summary

1. **Trivy is a good fit, provided each project commits a lock file.** With a lock file,
   every vulnerable package was found in all three language ecosystems, both direct and
   transitive. Every ingestion method gave the same results on the same commit: local
   path, remote URL (any branch, tag or commit), filesystem, SBOM, Docker, and
   client/server.
2. **Without a lock file Trivy reports "0 vulnerabilities" silently.** That is the main
   risk. It affects:
   - **C#**: `.csproj` `PackageReference` is **not read at all**. This is the default for
     most .NET projects. Both deliberately vulnerable C# applications came back "clean".
   - **Python**: `pyproject.toml` without a lock file, and `requirements.txt` with ranges
     (`>=`, `~=`).
   - **Node**: `package.json` without a lock file. OWASP Juice Shop came back "clean".

   The scripts now warn about this (`DepFiles` = 0), and `New-LockFile.ps1` generates the
   missing lock files on a copy. Results: WebGoat.NET 0 → 8 and dvcsharp-api 0 → 32
   vulnerabilities, mostly transitive; 0 → 121 for the Python/Node fixtures.
3. **Partial coverage by design:**
   - C# `Directory.Packages.props` and `packages.config`, and plain pinned
     `requirements.txt`, give **direct dependencies only**.
   - Dev dependencies are excluded by default.
4. **IaC coverage is strong:** Dockerfile (any naming), Kubernetes, Helm and Terraform.
   **Docker Compose has no built-in checks.** A custom Rego check, added here, closes the
   gap.
5. **Two Trivy pitfalls found and worked around in config:**
   - **pip**: only files named exactly `requirements.txt` are read; fixed with
     `file-patterns`.
   - **Kubernetes**: enabling the generic `yaml` scanner together with custom checks
     silently drops all Kubernetes findings; fixed with a separate Compose pass.
6. **Secrets in Git history are not detected**, and neither are plain-text passwords
   without a recognisable token format. Use gitleaks for history.

## Ecosystem coverage matrix (E16)

Fixtures: `fixtures/ecosystems/<case>/`, each with the same known-vulnerable packages and
an `expected.txt`.
- **default**: shared config.
- **maximum**: adds `--include-dev-deps --detection-priority comprehensive`.

Cells show expected findings detected / expected.

### C# / .NET

| Dependency declaration | Files read | Packages seen | Direct | Transitive | Verdict |
|---|---|---|---|---|---|
| `.csproj` `PackageReference` only | **0** | 0 | **0/4** | **0/1** | **Not assessed, silently** |
| `.csproj` + `packages.lock.json` | 1 | 47 | 4/4 | 1/1 | Full |
| Central Package Management (`Directory.Packages.props`) | 1 | 4 | 4/4 | **0/1** | Direct only |
| CPM + `packages.lock.json` | 2 | 51 | 4/4 | 1/1 | Full |
| `packages.config` (legacy) | 1 | 4 | 4/4 | **0/1** | Direct only |

### Python

| Dependency declaration | Files read | Packages seen | Direct | Transitive | Verdict |
|---|---|---|---|---|---|
| `requirements.txt`, exact `==` pins | 1 | 4 | 4/4 | **0/1** | Direct only |
| `requirements.txt`, ranges (`>=`, `~=`) | **0** | 0 | **0/4** | 0/1 | **Not assessed, silently** |
| … same with `--detection-priority comprehensive` | 1 | 4 | 4/4 | 0/1 | Minimum version assumed, so possible false positives |
| `requirements.txt` compiled with all transitive pins (`uv pip compile`, `pip-compile`) | 1 | 14 | 4/4 | 1/1 | Full |
| `requirements/base.txt`, `requirements-dev.txt`, `requirements_prod.txt` | 3 | 4 | 4/4 | — | Full **only with the `file-patterns` in `config/trivy.yaml`**; 0 files read without them |
| `pyproject.toml` only | **0** | 0 | **0/4** | 0/1 | **Not assessed, silently** |
| `uv.lock` | 1 | 15 | 4/4 | 1/1 | Full |
| `poetry.lock` | 1 | 14 | 4/4 | 1/1 | Full |
| `Pipfile.lock` | 1 | 14 | 4/4 | 1/1 | Full |

### JavaScript / TypeScript

| Dependency declaration | Files read | Packages (default / with dev) | Direct | Transitive | Dev (default / with dev) | Verdict |
|---|---|---|---|---|---|---|
| `package.json` only | **0** | 0 | **0/4** | **0/2** | 0/1 | **Not assessed, silently** |
| npm `package-lock.json` | 1 | 54 / 78 | 4/4 | 2/2 | 0/1 → 1/1 | Full |
| Yarn classic `yarn.lock` | 1 | 74 / 81 | 4/4 | 2/2 | 0/1 → 1/1 | Full; transitive deps of dev deps are counted as production |
| Yarn Berry `yarn.lock` | 1 | 57 / 81 | 4/4 | 2/2 | 0/1 → 1/1 | Full |
| pnpm `pnpm-lock.yaml` (v9) | 1 | 56 / 80 | 4/4 | 2/2 | 0/1 → 1/1 | Full |
| Bun `bun.lock` | 1 | 53 / 77 | 4/4 | 2/2 | 0/1 → 1/1 | Full |

TypeScript projects use the same package managers, so the same results apply.

### Infrastructure as code

| Case | Detected | Failed checks | Notes |
|---|---|---|---|
| `Dockerfile`, `Containerfile`, `Dockerfile.prod`, `api.Dockerfile`, `web.dockerfile` | 5/5 | 5 each | Any of these names works |
| Kubernetes `Deployment` | 1/1 | 22 (5 high) | Privileged, host network, hostPath, root, … |
| Helm chart | 1/1 | 18 (3 high) | Templates are rendered before checking |
| Terraform (AWS + Azure) | 1/1 | 20 (2 critical) | Public S3 ACL, SSH from 0.0.0.0/0, Azure storage without HTTPS / old TLS |
| Docker Compose | **0/2 built-in** → 2/2 with `config/checks/compose.rego` | 3 and 7 | Privileged, host namespaces, Docker socket, `cap_add`, root user, `:latest`, hard-coded credentials |
| Secret in Compose `environment:` | 1/1 GitHub token | — | The fake token is injected at runtime by `Invoke-CoverageMatrix.ps1`; the committed fixture only holds a placeholder. A plain `POSTGRES_PASSWORD` is **not** a secret finding; the custom Compose check flags it instead |

## Real-world repositories (E17)

`Invoke-TrivyBulk.ps1 -Scanners vuln,secret,misconfig` over `targets/targets.txt`:

| Repository | Stack | DepFiles | Vulns | Critical | High | Secrets | Misconfigs | Comment |
|---|---|---|---|---|---|---|---|---|
| tobyash86/WebGoat.NET | C# | **0** | **0** | 0 | 0 | 0 | 4 | `.csproj` only, so not assessed; **8 vulns** with a generated lock file (E18) |
| appsecco/dvcsharp-api | C# | **0** | **0** | 0 | 0 | 9 | 3 | `.csproj` only, so not assessed; **32 vulns** with a generated lock file (E18) |
| dotnet/eShop | C# | 1 | 0 | 0 | 0 | 0 | 0 | CPM: direct dependencies only |
| jasontaylordev/CleanArchitecture | C#, TS | 3 | 0 | 0 | 0 | 0 | 0 | CPM + 2 npm lock files |
| adeyosemanputra/pygoat | Python | 24 | 568 | 27 | 173 | 4 | 57 | 24 `requirements.txt`; 25 Dockerfiles + Compose |
| we45/Vulnerable-Flask-App | Python | 1 | 81 | 7 | 32 | 0 | 2 | |
| fastapi/full-stack-fastapi-template | Python, TS | 2 | 19 | 1 | 12 | 0 | 8 | `uv.lock` + `bun.lock`; Dockerfiles + Compose |
| OWASP/NodeGoat | Node | 1 | 92 | 12 | 47 | 1 | 1 | |
| snyk-labs/nodejs-goof | Node | 1 | 243 | 37 | 107 | 0 | 3 | |
| juice-shop/juice-shop | TS | **0** | **0** | 0 | 0 | 5 | 95 | `package-lock=false`, so not assessed; 66 vulns with a generated lock |
| bridgecrewio/terragoat | Terraform | 1 | 20 | 0 | 15 | 2 | 253 | `packages/` skipped (out-of-scope samples) |
| madhuakula/kubernetes-goat | K8s, Helm | 6 | 159 | 6 | 73 | 0 | 373 | 16 Kubernetes, 1 Helm, 14 Dockerfile results |

## Mitigation for missing lock files (E18)

`scripts/New-LockFile.ps1` copies a repository and generates lock files in pinned
containers. It disables npm scripts and Python source builds.

| Fixture | Before | After |
|---|---|---|
| C# `.csproj` only | 0 files, 0 vulns | 1 file, 11 vulns (1 critical, 5 high), including transitive `Azure.Identity` |
| Python `pyproject.toml` only + `requirements.txt` with ranges, Node `package.json` only | 0 files, 0 vulns | 121 vulns (7 critical, 48 high) |
| Juice Shop (`package.json`) | 0 | 66 (9 critical) |
| **tobyash86/WebGoat.NET** (`net8.0`, 12 direct packages) | 0 files, 0 vulns | 235 packages, **8 vulns (1 critical, 6 high)**; 6 of 8 in transitive packages |
| **appsecco/dvcsharp-api** (`netcoreapp2.0`, 8 direct packages) | 0 files, 0 vulns | 289 packages, **32 vulns (2 critical, 18 high)**; 27 of 32 in transitive packages |

**C# on third-party code (authorised by the repository owner, 26 October 2026).** `dotnet restore`
evaluates MSBuild project files, which can execute code. Before running, both project
files were reviewed: no custom targets, `Exec` tasks or imports, and no
`Directory.Build.props/targets` or `nuget.config`. Restore ran in a container with no
capabilities, no privilege escalation, resource limits, only the copy mounted, and no
credentials.

**Most C# risk is transitive** (33 of 40 findings across the two repositories). Scanning
`Directory.Packages.props` alone would miss it as well. The organisational fix is to set
`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in a shared
`Directory.Build.props` and commit `packages.lock.json`.

## Trivy pitfalls found

| Pitfall | Effect | Workaround (in this repo) |
|---|---|---|
| pip analyser matches only `requirements.txt` | `requirements-dev.txt`, `requirements/base.txt`, … silently ignored | `scan.file-patterns` in `config/trivy.yaml` |
| `yaml` misconfig scanner + custom checks | Kubernetes manifests reclassified as plain YAML; **all** Kubernetes findings lost | Compose checks run as a separate pass, merged into the same report |
| Scan cache key ignores `--offline-scan` | Results depend on previous runs | `trivy clean --scan-cache` before comparisons |
| `trivy sbom` rejects the `secret` scanner | Shared config breaks SBOM scans | Script defaults to `vuln` for `sbom` |
| Telemetry on by default | Usage data sent to Aqua | Disabled in `config/trivy.yaml` |

## Method experiments (E00–E15)

| ID | Result | Key observation |
|---|---|---|
| E00 | Pass | 0.76.1 installed, SHA-256 verified; image digest identical on Docker Hub and GHCR |
| E01 | Pass | Fixture: 63 vulns (8 C / 22 H), 1 secret, 12 misconfigurations; 19.7 s including the DB download |
| E02 | Pass | Clean re-scan from cache: 1.0 s. A dirty tree is not served from cache (`repo` = `fs` = 76) |
| E03 / E04 | Pass | Remote URL and manual shallow clone + `fs` give identical results (124) |
| E05 | Pass | `--branch`, `--tag`, `--commit` work. NodeGoat `v1.3` = 0 (no lock file) vs HEAD = 92 |
| E06 | Pass | Each scanner adds only its own finding class |
| E07 | Pass | Severity, `--ignore-unfixed`, `--skip-dirs` and suppressions behave as documented. **Expired suppressions are not applied**; `--show-suppressed` records the statement and source file |
| E08 | Pass | table, SARIF 2.1.0, CycloneDX 1.7, SPDX, GitHub formats valid; `--exit-code 1` gates |
| E09 | Pass | SBOM round-trip = direct scan (0 differences on 3 targets) |
| E10 | Pass | Docker = native. The first run is slow (image, DB and checks download) |
| E11 | Pass | Server mode: clients keep no DB; a wrong token is rejected |
| E12 | Pass | Offline with a pre-fetched DB works for local targets |
| E13 | Pass | Bulk scan: failures are logged and the batch continues |
| E14 | Skipped | No private repository supplied |
| E15 | Gaps confirmed | History-only secret missed by Trivy, found by gitleaks v8.30.1 |

(E01–E13 originally also covered Java/PHP targets; the Java-specific findings, Maven
Central rate limiting and network-dependent POM resolution, are no longer relevant.)

## Recommendations for your stack

1. **Make lock files mandatory**, and fail any assessment where `DepFiles` = 0:
   - **C#**: `RestorePackagesWithLockFile=true` in `Directory.Build.props`; commit
     `packages.lock.json`. This also adds transitive coverage to CPM projects.
   - **Python**: commit `uv.lock` / `poetry.lock`, or compile `requirements*.txt` with
     full pins.
   - **Node/TS**: always commit the lock file; never set `package-lock=false`.
2. **Always scan with `-Scanners vuln,secret,misconfig`**, so you get Dockerfile, Compose,
   Kubernetes, Helm and Terraform checks in the same pass.
3. Decide on **dev dependencies**: excluded by default. Add `--include-dev-deps` if build
   tooling is in scope (supply-chain risk).
4. Add **gitleaks** for secrets in Git history.
5. Use `New-LockFile.ps1` only as a stop-gap, and report its results as "assessed with a
   generated lock file". For third-party C# code, review the project files first
   (`*.csproj`, `Directory.Build.*`, `nuget.config`) for custom targets, because restore
   evaluates them.

## Open items

- E14: private repository with `GITHUB_TOKEN`, when one is available.
- Optional: `trivy image` on built images, for OS packages and the dependencies actually
  shipped.
