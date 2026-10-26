<#
.SYNOPSIS
    Creates a local Git repository with known, seeded findings (known-answer test).

.DESCRIPTION
    workspace/fixture-local is (re)built with:
      - requirements.txt   old Python packages with published CVEs (Django, PyYAML, requests, Jinja2)
      - package-lock.json  old npm package (lodash 4.17.15) with published CVEs
      - Dockerfile         misconfigurations (runs as root, latest tag, no HEALTHCHECK)
      - main.tf            Terraform misconfiguration (public S3 bucket ACL)
      - config/settings.py a fake GitHub token in the working tree (secret scanner)
      - Git history only   a fake AWS-style key committed, then deleted (E15: history gap)

    The fake credentials are generated at runtime, so they never appear in this script
    and cannot trip secret scanners on the PoC repository itself. They are not valid.

.EXAMPLE
    .\scripts\New-Fixture.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'workspace\fixture-local')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RandomString([string]$Alphabet, [int]$Length) {
    -join (1..$Length | ForEach-Object { $Alphabet[(Get-Random -Maximum $Alphabet.Length)] })
}

function Invoke-Git {
    & git -C $Path -c user.name='Fixture' -c user.email='fixture@example.invalid' -c commit.gpgsign=false -c core.autocrlf=false @args
    if ($LASTEXITCODE -ne 0) { throw "git $args failed" }
}

if (Test-Path $Path) { Remove-Item -Recurse -Force $Path }
New-Item -ItemType Directory -Path (Join-Path $Path 'config') | Out-Null
Invoke-Git init -q -b main

$alnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
$upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

# Commit 1: a secret that is later removed, so it survives only in Git history.
$awsKeyId = 'AKIA' + (Get-RandomString $upper 16)
$awsSecret = Get-RandomString ($alnum + '/+') 40
Set-Content -Encoding utf8 (Join-Path $Path 'config\aws.env') @"
AWS_ACCESS_KEY_ID=$awsKeyId
AWS_SECRET_ACCESS_KEY=$awsSecret
"@
Invoke-Git add -A
Invoke-Git commit -q -m 'Add AWS credentials (fixture: history-only secret)'

Remove-Item (Join-Path $Path 'config\aws.env')
Invoke-Git add -A
Invoke-Git commit -q -m 'Remove AWS credentials'

# Commit 3: the current tree with vulnerable dependencies, misconfigurations and a live secret.
Set-Content -Encoding utf8 (Join-Path $Path 'requirements.txt') @'
Django==2.2.0
PyYAML==5.3
requests==2.19.0
Jinja2==2.10
'@

Set-Content -Encoding utf8 (Join-Path $Path 'package.json') @'
{
  "name": "fixture-local",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  }
}
'@

Set-Content -Encoding utf8 (Join-Path $Path 'package-lock.json') @'
{
  "name": "fixture-local",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture-local",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
      "integrity": "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A=="
    }
  }
}
'@

Set-Content -Encoding utf8 (Join-Path $Path 'Dockerfile') @'
FROM python:latest
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/main.py"]
'@

Set-Content -Encoding utf8 (Join-Path $Path 'main.tf') @'
resource "aws_s3_bucket" "data" {
  bucket = "fixture-public-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read-write"
}
'@

$ghToken = 'ghp_' + (Get-RandomString $alnum 36)
Set-Content -Encoding utf8 (Join-Path $Path 'config\settings.py') @"
DEBUG = True
GITHUB_TOKEN = "$ghToken"
"@

Invoke-Git add -A
Invoke-Git commit -q -m 'Add application files'
Invoke-Git tag v1.0.0

Write-Host "Fixture created at $Path"
Invoke-Git log --oneline
