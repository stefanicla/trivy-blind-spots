# Trivy report formats

Which reports can Trivy produce **natively**, what does each one contain, and which one
can go into a **Word document**? This page answers both questions with measurements
(experiment E19). It also explains how to reproduce every format by hand.

All formats come from **one scan**. Trivy writes a JSON report, and `trivy convert` turns
that JSON into any other format in about a second, without scanning again. So every format
below is a different view of the same findings.

## Contents

- [Quick start](#quick-start)
- [The formats at a glance](#the-formats-at-a-glance)
- [Which format for a Word document?](#which-format-for-a-word-document)
- [Testing each format by hand](#testing-each-format-by-hand)
- [Pitfalls](#pitfalls)
- [Not covered](#not-covered)

## Quick start

From the repository root, in PowerShell 7:

```powershell
.\scripts\Install-Trivy.ps1                  # Trivy 0.76.1 + official templates in tools\contrib
.\scripts\Invoke-FormatShowcase.ps1 -Open    # one fixture scan, every format, overview page in the browser
```

The output is a self-contained folder, `reports\formats-<UTC>\`:

| File | Content |
|---|---|
| `index.html` | Overview: what each format contains. Each format then has its own section with the exact command, a ready-to-paste command line and the first 30 lines of the file |
| `scan.json`, `scan.meta.json` | The JSON scan report every format was converted from, and its metadata |
| `report.<ext>` | One file per format (extensions in the table below) |

To share the results, zip the folder. Useful variations:

```powershell
.\scripts\Invoke-FormatShowcase.ps1 -Format html,table     # only some formats (reuses the last scan)
.\scripts\Invoke-FormatShowcase.ps1 -Rescan                 # scan the fixture again first
.\scripts\Invoke-FormatShowcase.ps1 -FromJson .\reports\<real-repo>.json -Format html   # a real repository
.\scripts\Invoke-TrivyScan.ps1 -Target C:\src\my-repo -Scanners vuln,secret,misconfig -Format all   # during a normal scan
```

## The formats at a glance

Measured on 2026-11-05 with Trivy 0.76.1 on the known-answer fixture
(`workspace\fixture-local`). The JSON baseline has 62 vulnerabilities, 1 secret,
12 misconfigurations and 5 packages; the fixture has no licence findings. Each cell shows
how many of the baseline findings appear in the file. These counts come from a presence
check on identifiers (CVE ID, secret rule or title, check ID, package name + version);
open the files to see the detail.

| `-Format` | File | For | Vulns | Secrets | Misconfigs | Packages | Word |
|---|---|---|---|---|---|---|---|
| `json` | `report.json` | Automation, archiving | 62/62 | 1/1 | 12/12 | 5/5 | No |
| `table` | `report.table.txt` | People at a console | 62/62 | 1/1 | 12/12 | 5/5 | Poor |
| `table-summary` | `report.summary.txt` | People at a console: counts only | — | — | — | — | Poor |
| `sarif` | `report.sarif` | GitHub code scanning, IDEs | 62/62 | 1/1 | 12/12 | 5/5 | No |
| `cyclonedx` | `report.cdx.json` | SBOM / VEX tooling | 62/62 | **0/1** | **0/12** | 5/5 | No |
| `spdx` | `report.spdx` | SBOM / licence tooling | 61/62 ¹ | **0/1** | **0/12** | 5/5 | No |
| `spdx-json` | `report.spdx.json` | SBOM / licence tooling | 61/62 ¹ | **0/1** | **0/12** | 5/5 | No |
| `github` | `report.github.json` | GitHub dependency graph | **0/62** | **0/1** | **0/12** | 5/5 | No |
| `cosign-vuln` | `report.cosign-vuln.json` | Signed attestations | 62/62 | 1/1 | 12/12 | 5/5 | No |
| `html` | `report.trivy.html` | People, Word documents | 62/62 | **0/1** | 12/12 | 5/5 | **Yes** |
| `junit` | `report.junit.xml` | CI test reports | 62/62 | 1/1 | 12/12 | 5/5 | No |
| `gitlab` | `report.gitlab.json` | GitLab security dashboard | 62/62 | **0/1** | **0/12** | 5/5 | No |
| `gitlab-codequality` | `report.codequality.json` | GitLab Code Quality | 62/62 | 1/1 | 12/12 | 5/5 | No |
| `asff` | `report.asff.json` | AWS Security Hub | 62/62 | 1/1 | 12/12 | 5/5 | No |

¹ SPDX does not have a vulnerability section. A CVE shows up only as an
`ExternalRef: SECURITY advisory` link on the affected package, with no severity and no
fixed version. One CVE had no such link.

What this means:

- **Complete formats** (everything in the JSON): `json`, `table`, `sarif`, `cosign-vuln`,
  `junit`, `gitlab-codequality`, `asff`.
- **SBOMs** (`cyclonedx`, `spdx`, `spdx-json`) and the **GitHub dependency snapshot**
  (`github`) are package inventories. They do not carry secrets or misconfigurations.
  `github` carries no findings at all.
- **`html`** and **`gitlab`** drop secrets without warning; `gitlab` also drops
  misconfigurations. If one of these formats is the only report someone reads, a leaked
  credential stays invisible to them.

## Which format for a Word document?

**Short answer: `html` (the official `html.tpl` template). It is the only native format
that becomes real Word tables.** It has three limits:
- it **does not include secrets**;
- it **does not show which file** a finding is in, only the file type;
- it is **long**: 17 A4 pages on the fixture, mostly because of reference links.

| Format | In Word | Why |
|---|---|---|
| `html` | **Yes** | Word opens HTML directly; the result is real, editable tables |
| `table`, `table-summary` | Poor | Plain text drawn with box characters. It lines up only in a monospace font (Consolas) and wraps on A4 portrait |
| All the others | No | Machine-readable data (JSON, XML, SBOM) |
| Markdown, CSV | Not native | Only with a custom template |

### What we measured (Word 365, A4 portrait)

- The table **fits the page width**: Word sizes it automatically.
- **17 pages** for 62 vulnerabilities and 12 misconfigurations.
- **1811 reference links**, about 24 per vulnerability. In a browser, the page's
  JavaScript shows only the first 3 links of each row. Word does not run JavaScript, so it
  shows all of them, and that is most of the length.
- **No secrets**: the template has no secrets section.
- **No file names**: each section is headed by the file type (`npm`, `pip`, `dockerfile`,
  `terraform`). When there are two Terraform files, nothing tells their findings apart.
  The package name usually identifies a vulnerability; for a misconfiguration, add the
  file by hand or take it from `report.table.txt`.

### Option A: open the HTML file in Word

1. In File Explorer, right-click `reports\formats-<UTC>\report.trivy.html` and choose
   **Open with → Word** (or, in Word, **File → Open** and pick the file).
2. **File → Save As → Word Document (.docx)**.
3. To make it shorter, delete the *Links* column: click in the column, then
   **Table Layout → Delete → Delete Columns**.
4. If you need more room: **Layout → Orientation → Landscape**.

### Option B: copy from the browser and paste into Word

1. Open `report.trivy.html` in Edge or Chrome.
2. Press **Ctrl+A**, then **Ctrl+C**, then paste into a Word document with **Ctrl+V**.
3. Check how many links each row has. The browser normally copies only what is visible,
   so you should get at most 3 links per row, but this has not been measured yet.

### Option C: the summary table, for counts only

`report.summary.txt` holds only the finding counts per file and class. Paste it into
Word, select it and set the font to **Consolas, 8 pt**; it then lines up. Nothing else
needs to be changed.

### Secrets in a Word document

No native format puts secrets into Word tables. If secrets must be in the document, take
them from `report.table.txt`: its *Secrets* section lists the file, line and rule, and
Trivy masks the secret value. Alternatively, use the lab's own HTML page,
`reports\<name>_<method>_<UTC>.html`. It is not a native Trivy format, and it has not been
tested in Word.

## Testing each format by hand

First, point two variables at the newest showcase folder:

```powershell
$dir  = (Get-ChildItem .\reports -Directory -Filter 'formats-*' | Sort-Object Name | Select-Object -Last 1).FullName
$scan = "$dir\scan.json"
```

Each section below then gives one command to paste. It writes a `manual.*` file next to
the showcase's own `report.*` file, so you can compare the two. `index.html` has the same
commands with the paths already filled in.

For the checks, these are findings the fixture is known to contain:

| Class | Example to search for |
|---|---|
| Vulnerability | `CVE-2019-14234` (Django 2.2.0); `CVE-2020-8203` (lodash 4.17.15) |
| Secret | `github-pat` / "GitHub Personal Access Token" in `config/settings.py`, line 2 |
| Misconfiguration | `DS-0002` "Image user should not be 'root'" (Dockerfile); `AWS-0086` (main.tf) |

### json

```powershell
.\tools\trivy.exe convert --format json --output "$dir\manual.json" $scan
```

- **Open with:** VS Code or any editor.
- **Check:** `Results[]` has one entry per file. `Vulnerabilities`, `Secrets`,
  `Misconfigurations` and `Packages` are all present.
- **Word:** no.

### table

```powershell
.\tools\trivy.exe convert --format table --scanners vuln,secret,misconfig,license --output "$dir\manual.table.txt" $scan
```

- **Open with:** an editor with a monospace font, or print it in the console with
  `Get-Content "$dir\manual.table.txt"`.
- **Check:** first a *Report Summary* table with counts per file, then a detailed table per
  file. The secret appears with its value masked (`****`).
- **Word:** poor (see [Option C](#option-c-the-summary-table-for-counts-only)).

### table-summary

```powershell
.\tools\trivy.exe convert --format table --table-mode summary --scanners vuln,secret,misconfig,license --output "$dir\manual.summary.txt" $scan
```

- **Check:** only the summary: 6 + 56 vulnerabilities, 1 secret, 3 + 9 misconfigurations.
  A `-` means the class was not scanned for that file, and `0` means it was scanned and
  is clean.
- **Word:** poor, but short enough to paste in Consolas.

### sarif

```powershell
.\tools\trivy.exe convert --format sarif --output "$dir\manual.sarif" $scan
```

- **Open with:** VS Code with the *SARIF Viewer* extension, or upload it to GitHub code
  scanning.
- **Check:** `"version": "2.1.0"`. `runs[0].results` has 75 results, one per finding
  (62 + 1 + 12), each with file and line. The CVEs, `github-pat` and `DS-0002` are all
  present.
- **Word:** no.

### cyclonedx

```powershell
.\tools\trivy.exe convert --format cyclonedx --output "$dir\manual.cdx.json" $scan
```

- **Open with:** an editor, or an SBOM tool such as Dependency-Track.
- **Check:** `specVersion` is `1.7`. `components` lists the 5 packages (`library`) and the
  2 manifests (`application`). `vulnerabilities` lists the 62 CVEs. There is no secret
  and no misconfiguration.
- **Note:** Trivy prints `"--format cyclonedx" disables security scanning`. With
  `convert` this message is misleading: the vulnerabilities already in the JSON are
  carried over.
- **Word:** no.

### spdx and spdx-json

```powershell
.\tools\trivy.exe convert --format spdx --output "$dir\manual.spdx" $scan
.\tools\trivy.exe convert --format spdx-json --output "$dir\manual.spdx.json" $scan
```

- **Open with:** an editor.
- **Check:** `SPDXVersion: SPDX-2.3` (`spdxVersion` in JSON). Each package has licence
  fields (`NOASSERTION` for this fixture) and `ExternalRef: SECURITY advisory` links, and
  those links are the only trace of vulnerabilities.
- **Word:** no.

### github

```powershell
.\tools\trivy.exe convert --format github --output "$dir\manual.github.json" $scan
```

- **Open with:** an editor. On GitHub, it goes to the dependency submission API.
- **Check:** `manifests` contains `package-lock.json` and `requirements.txt` and their
  packages. There are no findings at all.
- **Word:** no.

### cosign-vuln

```powershell
.\tools\trivy.exe convert --format cosign-vuln --output "$dir\manual.cosign-vuln.json" $scan
```

- **Open with:** an editor. It is meant for `cosign attest --type vuln`.
- **Check:** `scanner.result` is the complete Trivy JSON report, so every class is there.
- **Word:** no.

### html (official template)

```powershell
.\tools\trivy.exe convert --format template --template '@.\tools\contrib\html.tpl' --output "$dir\manual.trivy.html" $scan
```

- **Open with:** a browser, or Word (see [above](#which-format-for-a-word-document)).
- **Check:** one section per scanned file. Each has vulnerabilities (package, ID,
  severity, installed and fixed version, links), then misconfigurations (type, ID, check,
  severity, message). Each section is headed **only by its type** (`npm`, `pip`,
  `dockerfile`, `terraform`), **not by the file name**. The secret's file
  (`config/settings.py`) gets an empty header with *No Vulnerabilities found* and *No
  Misconfigurations found*, and the secret itself is missing.
- **Word:** yes.

### junit (official template)

```powershell
.\tools\trivy.exe convert --format template --template '@.\tools\contrib\junit.tpl' --output "$dir\manual.junit.xml" $scan
```

- **Open with:** an editor, or as a test report in Jenkins, GitLab or Azure DevOps.
- **Check:** one `<testsuite>` per file and class. Each finding is a `<testcase>` with a
  `<failure>`. The secret has its own test suite.
- **Word:** no.

### gitlab (official template)

```powershell
.\tools\trivy.exe convert --format template --template '@.\tools\contrib\gitlab.tpl' --output "$dir\manual.gitlab.json" $scan
```

- **Open with:** an editor. In GitLab, it is used as `artifacts:reports:container_scanning`
  or `dependency_scanning`.
- **Check:** `vulnerabilities[]` holds the 62 CVEs. Neither the secret nor the
  misconfigurations are there.
- **Word:** no.

### gitlab-codequality (official template)

```powershell
.\tools\trivy.exe convert --format template --template '@.\tools\contrib\gitlab-codequality.tpl' --output "$dir\manual.codequality.json" $scan
```

- **Open with:** an editor. In GitLab, it is used as `artifacts:reports:codequality`.
- **Check:** a JSON array of 75 issues: vulnerabilities, misconfigurations and the secret.
- **Word:** no.

### asff (official template)

```powershell
$env:AWS_REGION = 'eu-south-1'; $env:AWS_ACCOUNT_ID = '123456789012'   # optional, example values
.\tools\trivy.exe convert --format template --template '@.\tools\contrib\asff.tpl' --output "$dir\manual.asff.json" $scan
```

- **Open with:** an editor. It is meant for `aws securityhub batch-import-findings`.
- **Check:** `Findings[]` has 75 entries: the vulnerabilities, the misconfigurations and
  the secret ("Trivy found a secret in config/settings.py: GitHub Personal Access Token").
  Without the
  two variables, `ProductArn`, `AwsAccountId` and `Region` are empty.
- **Word:** no.

## Pitfalls

- **`--template` needs the `@`.** `--template '@path\file.tpl'` reads the file.
  `--template path\file.tpl` treats the text as the template itself and writes only the
  path into the report: a 22-byte "HTML" file, and exit code 0. In PowerShell, quote the
  argument, because a bare `@` means splatting.
- **Formats can drop findings without warning.** `html`, `gitlab`, the SBOMs and `github`
  leave out whole classes and still exit with code 0. Choose the format by who reads it,
  and keep the JSON as the reference.
- **The `INFO … disables security scanning` message** from `convert` to an SBOM format is
  misleading: `convert` never scans.
- **`--scanners` on `convert`** only decides which columns the summary table shows. It
  does not filter findings.
- **The templates are installed by `Install-Trivy.ps1`** from the same checksum-verified
  release archive as `trivy.exe`, so they cannot be swapped silently. Do not download
  templates from `main`.

## Not covered

- **`--compliance` reports** (CIS, NSA, …) apply to `trivy image`, `trivy k8s` and cloud
  scans, not to repository or filesystem scans.
- **Markdown and CSV** are not native. They can be produced with a custom template
  (`--format template --template @my.tpl`), and the lab has none.
- **The lab's HTML page** (`ConvertTo-HtmlReport.ps1`, written by every scan) is not a
  Trivy format. Unlike `html.tpl`, it includes secrets.
