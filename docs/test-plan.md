# Test plan

## Objective

Determine whether Trivy is fit for vulnerability assessment of whole repositories, which
ingestion method suits which situation, and what Trivy does **not** detect.

## Scope

In scope: C#/.NET, Python, JavaScript/TypeScript (Node), Terraform, Dockerfile, Docker
Compose, Kubernetes/Helm. Out of scope: Java (and with it Maven resolution), PHP.

## Environment

- Windows 11, PowerShell 7, Git 2.55, Docker Desktop 29.8
- Trivy 0.76.1 (pinned, checksum-verified), image `aquasec/trivy:0.76.1@sha256:790fd66d...c06c`
- Vulnerability DB date recorded per run in `reports/*.meta.json`

## Targets

| Target | Ecosystem(s) | Why |
|---|---|---|
| `workspace/fixture-local` (`New-Fixture.ps1`) | pip, npm, Dockerfile, Terraform | Known-answer test: seeded CVEs, a live secret, a history-only secret, misconfigurations |
| `fixtures/ecosystems/<case>` (`New-EcosystemFixtures.ps1`) | C#, Python, Node, IaC | Every way of declaring dependencies / infrastructure, with expected findings |
| `aquasecurity/trivy-ci-test` | mixed | Trivy's own smoke-test repository; several branches (method tests only) |
| `tobyash86/WebGoat.NET`, `appsecco/dvcsharp-api` | C# | Vulnerable apps with `.csproj` only |
| `dotnet/eShop`, `jasontaylordev/CleanArchitecture` | C#, TS | Real-world Central Package Management |
| `adeyosemanputra/pygoat`, `we45/Vulnerable-Flask-App` | Python | `requirements.txt`, Dockerfiles, Compose |
| `fastapi/full-stack-fastapi-template` | Python, TS | `uv.lock`, `bun.lock`, Compose |
| `OWASP/NodeGoat`, `snyk-labs/nodejs-goof` | Node | npm lock files; NodeGoat has tags without a lock file |
| `juice-shop/juice-shop` | TS | No lock file by design; large |
| `bridgecrewio/terragoat` | Terraform | Misconfigurations |
| `madhuakula/kubernetes-goat` | Kubernetes, Helm | Misconfigurations |

## Experiments

| ID | Method | Experiment | Success criterion |
|---|---|---|---|
| E00 | — | Install pinned Trivy, verify checksum, first DB download | Version = pin; checksum matches |
| E01 | M1 | `repo` on clean fixture with vuln, secret, misconfig | Every seeded package, the live secret and the misconfigurations are reported |
| E02 | M1/M3 | Re-scan clean (cache); add an uncommitted dependency; `repo` vs `fs` | Cache speeds up clean re-scan; dirty tree is not served from cache |
| E03 | M2 | Remote URL, default branch (`trivy-ci-test`) | Report produced |
| E04 | M4 | Shallow clone + `fs` on the same repo | Findings identical to E03 |
| E05 | M2 | `--branch`, `--tag`, `--commit` | Results reflect the selected ref |
| E06 | M2 | Scanner toggles `vuln` → `+secret` → `+misconfig` → `+license` | Each scanner adds its own finding class only |
| E07 | M2 | `--severity`, `--ignore-unfixed`, `--skip-dirs`, ignore file (valid and expired entries), `--show-suppressed` | Counts drop as predicted; expired suppressions do not apply; suppressions are auditable |
| E08 | M3 | Output formats via `trivy convert`; `--dependency-tree`; `--exit-code 1` | Valid files; gating returns 1 |
| E09 | M5 | CycloneDX SBOM then `trivy sbom` vs direct `fs` | Identical finding sets |
| E10 | M6 | `docker-repo` and `docker-fs` | Same counts as native runs |
| E11 | M7 | Server + two clients | Clients do not download the DB |
| E12 | M9 | Offline scan with pre-fetched DB | Succeeds; record what is lost |
| E13 | M8 | Bulk scan of `targets.txt` | One report per target; failures non-fatal |
| E14 | M2 | Private repo with `GITHUB_TOKEN` | Skipped unless a private repo is supplied |
| E15 | — | Gap analysis: history-only secret, missing lock file, OS packages | Gaps documented |
| E16 | M3 | Ecosystem coverage matrix (`Invoke-CoverageMatrix.ps1`): C# (csproj, packages.lock.json, CPM, packages.config), Python (requirements variants, pyproject, uv, Poetry, Pipenv), Node (npm, yarn v1/Berry, pnpm, bun), IaC (Dockerfile names, Compose, Kubernetes, Helm, Terraform); default vs `--include-dev-deps --detection-priority comprehensive` | Every supported format detects direct and transitive findings; unsupported formats are identified |
| E17 | M8 | Bulk scan of real C#, Python, Node/TS and IaC repositories | One report per target; silent-zero cases identified |
| E18 | — | `New-LockFile.ps1` on lock-less fixtures | Findings appear after lock generation |

## Metrics per run

Wall time, DB date, findings by severity, finding class (vulnerability, secret,
misconfiguration, licence), suppressed count, exit code. All captured automatically in
the JSON report and `.meta.json` sidecar; summarise with `Convert-Report.ps1 -Markdown`.

## Re-running

```powershell
.\tools\trivy.exe clean --scan-cache --cache-dir .\cache   # comparable runs
.\scripts\Test-KnownAnswer.ps1                              # E01 / E15 as PASS/FAIL checks (also run in CI)
.\scripts\Invoke-CoverageMatrix.ps1                         # E16 (fixtures are committed)
.\scripts\Invoke-TrivyBulk.ps1 -Scanners vuln,secret,misconfig   # E17
```

`New-EcosystemFixtures.ps1` re-creates `fixtures/ecosystems` with fresh dependency
resolutions (Docker and network required). Run it only when you deliberately want new
transitive versions.
