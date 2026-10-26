# Ingestion methods

How a repository can be handed to Trivy (0.76.1) for assessment, with trade-offs. The
statements marked **(verified)** were confirmed by the experiments in
[results.md](results.md); the rest come from the Trivy documentation.

## Summary

| # | Method | Use it when | Avoid it when |
|---|---|---|---|
| M1 | `trivy repo <local path>` | You already have a checkout | — |
| M2 | `trivy repo <url>` | Ad hoc scans of remote repos, specific branch/tag/commit | The host needs auth Trivy cannot use (SSH keys, SSO) |
| M3 | `trivy fs <path>` | Uncommitted work, non-Git folders, vendored code | — |
| M4 | Manual `git clone` + M3 | You need control over auth, submodules, sparse checkout, LFS | A quick one-off scan |
| M5 | SBOM (`fs --format cyclonedx` then `trivy sbom`) | Re-assessing later without the source; exchanging inventories | You need secrets/misconfig results (SBOM carries packages only) |
| M6 | Container image (`docker run aquasec/trivy@sha256:...`) | No host install; CI runners; isolation | Very high scan volumes (container start-up overhead) |
| M7 | Client/server (`trivy server` + `--server`) | Many scanners sharing one DB | Single-user use |
| M8 | Bulk (targets file or `gh repo list <org>`) | Organisation-wide sweeps | — |
| M9 | Offline / air-gapped | No internet at scan time | — |
| M10 | CI (`trivy-action`, SARIF upload) | Continuous gating on pull requests | — (documented only) |

## M1 – local Git folder

```powershell
.\scripts\Invoke-TrivyScan.ps1 -Target C:\src\my-repo -Scanners vuln,secret,misconfig
```

- Scan results are cached by commit hash; a clean re-scan takes about 1 s **(verified)**.
- With uncommitted changes the cache is bypassed, so new findings appear immediately
  **(verified)**.
- `--branch` / `--tag` / `--commit` are for remote URLs; check out the ref locally instead.

## M2 – remote URL

```powershell
.\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/OWASP/NodeGoat -Tag v1.3
.\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/org/repo -Branch develop
.\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/org/repo -Commit 055a8a2...
```

- Trivy clones into a temporary directory and removes it afterwards.
- Results are identical to M4 on the same commit **(verified)**.
- Private repositories: `GITHUB_TOKEN` or `GITLAB_TOKEN` in the environment.

## M3 – filesystem

```powershell
.\scripts\Invoke-TrivyScan.ps1 -Target C:\src\my-repo -Method fs
```

Same scanners and analysers as `repo`, no Git awareness. Good for folders that are not
Git repositories (exports, tarballs, vendored dependencies) and for pre-commit checks.

## M4 – manual clone, then filesystem

```powershell
git clone --depth 1 --filter=blob:none https://host/org/repo workspace\repo
.\scripts\Invoke-TrivyScan.ps1 -Target .\workspace\repo -Method fs
```

The fall-back for anything Trivy cannot clone itself (SSH-only hosts, Azure DevOps with
SSO, Gerrit, submodules, Git LFS). Keep clones under `workspace/`.

## M5 – SBOM round-trip

```powershell
.\tools\trivy.exe fs --format cyclonedx --output repo.cdx.json C:\src\my-repo
.\scripts\Invoke-TrivyScan.ps1 -Target .\repo.cdx.json -Method sbom
```

- Findings equal a direct scan **(verified on three targets)**.
- Lets you store the inventory and re-assess it against tomorrow's DB without the source.
- `trivy sbom` supports only the `vuln` and `license` scanners.
- `--format cyclonedx` / `spdx-json` on `fs`/`repo` produces an **inventory only** unless
  `--scanners vuln` is given. Converting an existing JSON report with `trivy convert`
  does keep vulnerabilities.

## M6 – container

```powershell
.\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/org/repo -Method docker-repo
.\scripts\Invoke-TrivyScan.ps1 -Target C:\src\my-repo -Method docker-fs
```

The target is mounted read-only at `/src`; the DB is kept in `cache/docker` so it is not
re-downloaded each time. Always pin by digest.

## M7 – client/server

```powershell
.\tools\trivy.exe server --listen localhost:4954 --cache-dir .\cache\server
.\scripts\Invoke-TrivyScan.ps1 -Target https://github.com/org/repo -Server http://localhost:4954
```

The client still clones and analyses the repository locally; only the vulnerability
matching happens on the server, which owns the DB. Use `--token` on both sides in any
shared deployment.

## M8 – bulk

```powershell
.\scripts\Invoke-TrivyBulk.ps1                                    # targets/targets.txt
.\scripts\Invoke-TrivyBulk.ps1 -GitHubOrg my-org -Limit 50       # every repo in an org
```

Failures are logged and skipped. Combine with `-Server` (M7) for large sweeps.

## M9 – offline / air-gapped

```powershell
# On a connected machine
.\tools\trivy.exe fs --download-db-only --cache-dir .\cache
# Copy cache\ to the isolated machine, then:
.\scripts\Invoke-TrivyScan.ps1 -Target C:\src\my-repo -Offline
```

`-Offline` adds `--skip-db-update --skip-java-db-update --skip-check-update --offline-scan`.
Alternatively, point `--db-repository` at an internal OCI mirror of `trivy-db`. For the
ecosystems in scope (NuGet, pip/uv/Poetry, npm/yarn/pnpm/bun) no network is needed at
scan time, so offline results equal online ones **(verified)**.

## Missing lock files

```powershell
.\scripts\New-LockFile.ps1 -Source .\workspace\some-repo          # -> workspace\some-repo-locked
.\scripts\Invoke-TrivyScan.ps1 -Target .\workspace\some-repo-locked -Method fs
```

Generates `packages.lock.json` (C#), `uv.lock` / compiled requirements (Python) and
`package-lock.json` (Node) on a copy, in pinned containers. npm scripts and Python source
builds are disabled, but `dotnet restore` evaluates MSBuild files, which can run code, so
use it only on code you are entitled to assess. Review `*.csproj`, `Directory.Build.*` and
`nuget.config` for custom targets or `Exec` tasks first. Containers run with all
capabilities dropped, `no-new-privileges` and resource limits. Resolved versions are
today's, not necessarily what is deployed.

## M10 – CI (documentation only)

Use `aquasecurity/trivy-action` **>= v0.35.0**, pinned by commit SHA, with
`scan-type: repo` or `fs`, `format: sarif`, and upload with
`github/codeql-action/upload-sarif`. Use `--exit-code 1 --severity CRITICAL,HIGH` to gate.
Pin the Trivy version inside the action as well.

## What Trivy reads, per ecosystem in scope

All verified by the coverage matrix (`Invoke-CoverageMatrix.ps1`, see [results.md](results.md)).

| Ecosystem | Full coverage (direct + transitive) | Direct only | **Not read (silent 0)** |
|---|---|---|---|
| C# / .NET | `packages.lock.json` | `Directory.Packages.props`, `packages.config` | `.csproj` `PackageReference` |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, fully compiled `requirements*.txt` | `requirements*.txt` with `==` pins | `pyproject.toml` alone; `requirements.txt` with ranges (unless `--detection-priority comprehensive`) |
| JS / TS | `package-lock.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml`, `bun.lock` | — | `package.json` alone; `bun.lockb` |
| Dockerfile | `Dockerfile`, `Containerfile`, `Dockerfile.*`, `*.Dockerfile`, `*.dockerfile` | | Base-image OS packages (use `trivy image`) |
| Kubernetes / Helm | Manifests (`apiVersion` + `kind`), Helm charts (rendered) | | Kustomize (not listed in Trivy's coverage docs; not tested) |
| Terraform | `*.tf`, `*.tf.json`, `*.tfvars`, plan JSON | | |
| Docker Compose | Only via the custom check `config/checks/compose.rego` | | **No built-in checks** |

Dev dependencies (npm/yarn/pnpm/bun `devDependencies`, Poetry/uv dev groups) are excluded
by default; add `--include-dev-deps` to include them.

## Limitations

| Limitation | Consequence | Mitigation |
|---|---|---|
| Needs **lock files** for most ecosystems | **0 vulnerabilities, silently**, for C# `.csproj`, Python `pyproject.toml`, Node `package.json` **(verified: WebGoat.NET, dvcsharp-api, Juice Shop)** | `Invoke-TrivyScan.ps1` warns and `Convert-Report.ps1` shows `DepFiles` = 0; `New-LockFile.ps1` generates lock files on a copy; best: commit lock files |
| pip analyser matches only `requirements.txt` | `requirements-dev.txt`, `requirements/base.txt`, … ignored **(verified)** | `scan.file-patterns` in `config/trivy.yaml` (already configured) |
| No Docker Compose checks | Privileged services, Docker socket mounts, etc. not reported **(verified)** | Custom Rego check `config/checks/compose.rego`, run as a separate pass by the scripts |
| `yaml` misconfig scanner + custom checks | Kubernetes manifests become plain YAML: **all Kubernetes findings lost** **(verified)** | Never enable `yaml` in the main pass; the scripts run Compose separately |
| Secret scanning reads the **working tree only** and matches known token formats | Deleted-but-committed secrets and plain passwords are missed **(verified)** | gitleaks over the full history **(verified)**; the Compose check flags credential-like environment variables |
| No OS-package CVEs in `repo`/`fs` | Base-image vulnerabilities are not assessed | Build and `trivy image` the result |
| Scan cache key ignores `--offline-scan` | Results can depend on previous runs **(verified)** | `trivy clean --scan-cache` before comparative runs |
| No reachability analysis | Every vulnerable dependency is reported, used or not | Triage with VEX / `trivyignore.yaml` statements |
| Misconfig and licence scanners off by default | Under-reporting if not enabled | `-Scanners vuln,secret,misconfig` (add `license` if needed) |
