<#
.SYNOPSIS
    Builds the ecosystem coverage fixtures for C#, Python and JavaScript/TypeScript.

.DESCRIPTION
    Creates fixtures/ecosystems/<case>/ for every way a project in these ecosystems can
    declare its dependencies, each with the same known-vulnerable packages. Lock files are
    produced by the real package managers inside pinned containers, so they match what
    real projects commit. Each case has an expected.txt ("<package> <direct|transitive|dev>")
    used by Invoke-CoverageMatrix.ps1.

    The generated files are committed, so the matrix can be re-run without Docker.
    Re-generate only when you want fresh resolutions (transitive versions may change).

    Requires Docker and network access (NuGet, PyPI and npm registries).

.EXAMPLE
    .\scripts\New-EcosystemFixtures.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'fixtures\ecosystems')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Images = @{
    dotnet = 'mcr.microsoft.com/dotnet/sdk:8.0@sha256:ff39a765f04619c8d146796fc09b38499ae5984f4a2a4c3a0a57d0022855daee'
    python = 'python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
    node   = 'node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914'
    bun    = 'oven/bun:1@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d'
}

function Write-Case([string]$Case, [hashtable]$Files, [string[]]$Expected) {
    $dir = Join-Path $Path $Case
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($name in $Files.Keys) {
        $file = Join-Path $dir $name
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $file) | Out-Null
        # LF endings and no BOM, as the package managers would write them.
        [IO.File]::WriteAllText($file, ($Files[$name].Trim() -replace "`r`n", "`n") + "`n")
    }
    [IO.File]::WriteAllText((Join-Path $dir 'expected.txt'), (($Expected -join "`n") + "`n"))
}

function Invoke-InContainer([string]$Image, [string]$Case, [string]$Script) {
    $dir = Join-Path $Path $Case
    Write-Host "  [$Case] $Script"
    docker run --rm -v "${dir}:/w" -w /w -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 -e DOTNET_CLI_TELEMETRY_OPTOUT=1 `
        -e DOTNET_NOLOGO=1 -e PIP_DISABLE_PIP_VERSION_CHECK=1 $Image sh -c $Script
    if ($LASTEXITCODE -ne 0) { throw "Lock generation failed for $Case (exit code $LASTEXITCODE)" }
}

if (Test-Path $Path) { Remove-Item -Recurse -Force $Path }
New-Item -ItemType Directory -Path $Path | Out-Null

# ---------------------------------------------------------------- C# / NuGet
# Newtonsoft.Json 12.0.1        GHSA-5crp-9r3c-p9vr (fixed 13.0.1)
# System.Text.Encodings.Web 4.7.1  CVE-2021-26701 (fixed 4.7.2)
# System.Data.SqlClient 4.8.0   CVE-2022-41064, CVE-2024-0056 (fixed 4.8.6)
# Microsoft.Data.SqlClient 5.1.0 CVE-2024-0056; brings Azure.Identity 1.7.0 (CVE-2023-36414) transitively
$csExpected = 'Newtonsoft.Json direct', 'System.Text.Encodings.Web direct', 'System.Data.SqlClient direct', 'Microsoft.Data.SqlClient direct', 'Azure.Identity transitive'
$csRefs = @'
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="System.Text.Encodings.Web" Version="4.7.1" />
    <PackageReference Include="System.Data.SqlClient" Version="4.8.0" />
    <PackageReference Include="Microsoft.Data.SqlClient" Version="5.1.0" />
'@
$csRefsNoVersion = $csRefs -replace ' Version="[^"]+"', ''
$cpmProps = @'
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageVersion Include="System.Text.Encodings.Web" Version="4.7.1" />
    <PackageVersion Include="System.Data.SqlClient" Version="4.8.0" />
    <PackageVersion Include="Microsoft.Data.SqlClient" Version="5.1.0" />
  </ItemGroup>
</Project>
'@
function Get-CsprojContent([string]$Refs, [switch]$LockFile) {
    $lock = if ($LockFile) { "`n    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" } else { '' }
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <NuGetAudit>false</NuGetAudit>
    <NoWarn>NU1605</NoWarn>$lock
  </PropertyGroup>
  <ItemGroup>
$Refs
  </ItemGroup>
</Project>
"@
}

Write-Host 'C# fixtures'
Write-Case 'cs-csproj-only' @{ 'App.csproj' = (Get-CsprojContent $csRefs) } $csExpected
Write-Case 'cs-packages-lock' @{ 'App.csproj' = (Get-CsprojContent $csRefs -LockFile) } $csExpected
Write-Case 'cs-cpm-props' @{ 'App.csproj' = (Get-CsprojContent $csRefsNoVersion); 'Directory.Packages.props' = $cpmProps } $csExpected
Write-Case 'cs-cpm-lock' @{ 'App.csproj' = (Get-CsprojContent $csRefsNoVersion -LockFile); 'Directory.Packages.props' = $cpmProps } $csExpected
Write-Case 'cs-packages-config' @{ 'packages.config' = @'
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.1" targetFramework="net48" />
  <package id="System.Text.Encodings.Web" version="4.7.1" targetFramework="net48" />
  <package id="System.Data.SqlClient" version="4.8.0" targetFramework="net48" />
  <package id="Microsoft.Data.SqlClient" version="5.1.0" targetFramework="net48" />
</packages>
'@ } $csExpected

foreach ($case in 'cs-packages-lock', 'cs-cpm-lock') {
    Invoke-InContainer $Images.dotnet $case 'dotnet restore --use-lock-file >/dev/null && rm -rf obj bin && ls'
}

# ---------------------------------------------------------------- Python
# Django 2.2.0, Jinja2 2.10, requests 2.19.0, Flask 0.12.2 (all with published CVEs).
# requests 2.19.0 pins urllib3 < 1.24, so a vulnerable urllib3 arrives transitively.
$pyExpected = 'Django direct', 'Jinja2 direct', 'requests direct', 'Flask direct', 'urllib3 transitive'
$pyPinned = "Django==2.2.0`nJinja2==2.10`nrequests==2.19.0`nFlask==0.12.2"
$pyDeps = '"Django==2.2.0", "Jinja2==2.10", "requests==2.19.0", "Flask==0.12.2"'
$pyproject = @"
[project]
name = "fixture"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [$pyDeps]
"@

Write-Host 'Python fixtures'
Write-Case 'py-requirements-pinned' @{ 'requirements.txt' = $pyPinned } $pyExpected
# Trivy reads only files named exactly requirements.txt unless file-patterns are configured.
Write-Case 'py-requirements-names' @{
    'requirements/base.txt' = "Django==2.2.0`nrequests==2.19.0"
    'requirements-dev.txt'  = 'Jinja2==2.10'
    'requirements_prod.txt' = 'Flask==0.12.2'
} ($pyExpected | Where-Object { $_ -notlike 'urllib3*' })
Write-Case 'py-requirements-ranges' @{ 'requirements.txt' = "Django>=2.2.0,<3`nJinja2~=2.10`nrequests>=2.19.0`nFlask>=0.12.2" } $pyExpected
Write-Case 'py-requirements-compiled' @{ 'requirements.in' = $pyPinned } $pyExpected
Write-Case 'py-pyproject-only' @{ 'pyproject.toml' = $pyproject } $pyExpected
Write-Case 'py-poetry-lock' @{ 'pyproject.toml' = $pyproject } $pyExpected
Write-Case 'py-uv-lock' @{ 'pyproject.toml' = $pyproject } $pyExpected
Write-Case 'py-pipenv-lock' @{ 'Pipfile' = @'
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
django = "==2.2.0"
jinja2 = "==2.10"
requests = "==2.19.0"
flask = "==0.12.2"

[requires]
python_version = "3.12"
'@ } $pyExpected

$pyTools = 'pip install -q uv poetry pipenv && uv --version && poetry --version && pipenv --version'
Invoke-InContainer $Images.python 'py-requirements-compiled' "pip install -q uv && uv pip compile -q --python-version 3.12 requirements.in -o requirements.txt"
Invoke-InContainer $Images.python 'py-poetry-lock' "$pyTools >/dev/null && poetry lock -q && ls"
Invoke-InContainer $Images.python 'py-uv-lock' 'pip install -q uv && uv lock -q && ls'
Invoke-InContainer $Images.python 'py-pipenv-lock' 'pip install -q pipenv && PIPENV_VENV_IN_PROJECT=0 pipenv lock >/dev/null 2>&1 && ls'

# ---------------------------------------------------------------- JavaScript / TypeScript
# lodash 4.17.15, minimist 1.2.0, axios 0.21.0 (direct); express 4.17.1 brings vulnerable
# qs and path-to-regexp transitively; handlebars 4.0.11 is a vulnerable devDependency.
$nodeExpected = 'lodash direct', 'minimist direct', 'axios direct', 'express direct', 'qs transitive', 'path-to-regexp transitive', 'handlebars dev'
$packageJson = @'
{
  "name": "fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "axios": "0.21.0",
    "express": "4.17.1",
    "lodash": "4.17.15",
    "minimist": "1.2.0"
  },
  "devDependencies": {
    "handlebars": "4.0.11"
  }
}
'@

Write-Host 'JavaScript/TypeScript fixtures'
foreach ($case in 'node-package-json-only', 'node-npm-lock', 'node-yarn-classic', 'node-yarn-berry', 'node-pnpm-lock', 'node-bun-lock') {
    Write-Case $case @{ 'package.json' = $packageJson } $nodeExpected
}
Invoke-InContainer $Images.node 'node-npm-lock' 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null && ls'
Invoke-InContainer $Images.node 'node-yarn-classic' 'corepack yarn@1.22.22 install --ignore-scripts --non-interactive >/dev/null && rm -rf node_modules && ls'
Invoke-InContainer $Images.node 'node-yarn-berry' 'corepack yarn@4.9.2 install --mode=update-lockfile >/dev/null && rm -rf .yarn node_modules .pnp.* && ls'
Invoke-InContainer $Images.node 'node-pnpm-lock' 'corepack pnpm@10.12.1 install --lockfile-only --ignore-scripts >/dev/null && ls'
Invoke-InContainer $Images.bun 'node-bun-lock' 'bun install --lockfile-only --ignore-scripts >/dev/null && ls'

# ---------------------------------------------------------------- Infrastructure as code
# For IaC, expected.txt lists "<file> misconfig" (at least one failed check on that file)
# or "<file> secret" (at least one secret found in that file).
# Token-shaped strings are never committed: Invoke-CoverageMatrix.ps1 replaces this
# placeholder with a freshly generated, invalid token in a temporary copy before scanning.
$fakePat = '__FAKE_GITHUB_TOKEN__'
$badDockerfile = @'
FROM node:latest
ADD . /app
RUN apt-get update && apt-get install -y curl
CMD ["node", "/app/server.js"]
'@

Write-Host 'IaC fixtures'
Write-Case 'iac-dockerfile-names' @{
    'Dockerfile'           = $badDockerfile
    'Containerfile'        = $badDockerfile
    'Dockerfile.prod'      = $badDockerfile
    'api.Dockerfile'       = $badDockerfile
    'web.dockerfile'       = $badDockerfile
} 'Dockerfile misconfig', 'Containerfile misconfig', 'Dockerfile.prod misconfig', 'api.Dockerfile misconfig', 'web.dockerfile misconfig'

Write-Case 'iac-compose' @{
    'docker-compose.yml' = @"
services:
  web:
    image: nginx:latest
    privileged: true
    network_mode: host
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      POSTGRES_PASSWORD: SuperSecret123!
      GITHUB_TOKEN: $fakePat
"@
    'compose.yaml' = @'
services:
  db:
    image: postgres:latest
    privileged: true
    cap_add: [ALL]
'@
} 'docker-compose.yml misconfig', 'compose.yaml misconfig', 'docker-compose.yml secret'

Write-Case 'iac-kubernetes' @{
    'deployment.yaml' = @'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - {name: host, mountPath: /host}
      volumes:
        - name: host
          hostPath: {path: /}
'@
} 'deployment.yaml misconfig'

Write-Case 'iac-helm' @{
    'chart/Chart.yaml' = "apiVersion: v2`nname: web`nversion: 0.1.0"
    'chart/values.yaml' = "image: nginx:latest`nprivileged: true"
    'chart/templates/deployment.yaml' = @'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: {{ .Values.image }}
          securityContext:
            privileged: {{ .Values.privileged }}
'@
} 'chart/templates/deployment.yaml misconfig'

Write-Case 'iac-terraform' @{
    'main.tf' = @'
resource "aws_s3_bucket" "data" {
  bucket = "fixture-public-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read-write"
}

resource "aws_security_group" "ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_storage_account" "data" {
  name                      = "fixturestorage"
  resource_group_name       = "rg"
  location                  = "westeurope"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  https_traffic_only_enabled = false
  min_tls_version           = "TLS1_0"
}
'@
} 'main.tf misconfig'

Write-Host "`nFixtures written to $Path"
Get-ChildItem $Path -Directory | ForEach-Object { '{0,-28} {1}' -f $_.Name, ((Get-ChildItem $_.FullName -File -Name | Where-Object { $_ -ne 'expected.txt' }) -join ', ') }
