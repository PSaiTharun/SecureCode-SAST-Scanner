# SecureCode SAST Scanner

A self-contained Python 3.10+ static application security testing (SAST) CLI. **No third-party packages.**

| Languages | How they are analysed |
|---|---|
| **Python** | Real **AST parsing + source-to-sink taint analysis** (interprocedural, sanitizer- and guard-aware) |
| JavaScript/TypeScript, Java, PHP, Go | Regex engine with per-file **variable taint tracking** and language-specific sinks/sanitizers |

Outputs: terminal table, JSON, HTML, and **SARIF 2.1.0** (GitHub code scanning, Jenkins, IDEs). Supports baselines, inline suppressions, severity/confidence filters and CI exit codes.

## Detection rules

| ID | CWE | Detection |
|---|---|---|
| SC001 | CWE-89 | SQL injection |
| SC002 | CWE-78 | OS command injection |
| SC003 | CWE-79 | Cross-site scripting |
| SC004 | CWE-798 | Hard-coded credentials / tokens / private keys (evidence is redacted) |
| SC005 | CWE-95 | Dynamic code evaluation (`eval`, `exec`, `new Function`) |
| SC006 | CWE-22 | Path traversal / file inclusion |
| SC007 | CWE-327 | Weak hashes (MD5, SHA-1) |
| SC008 | CWE-502 | Insecure deserialization (`pickle`, `yaml.load`, `unserialize`, `ObjectInputStream`) |
| SC009 | CWE-295 | TLS / signature verification disabled |
| SC010 | CWE-918 | Server-side request forgery |
| SC011 | CWE-601 | Open redirect |
| SC012 | CWE-489 | Insecure configuration (debug mode, `0.0.0.0`, CSRF off, wildcard CORS) |
| SC013 | CWE-338 | Predictable randomness for tokens/passwords |
| SC014 | CWE-1336 | Server-side template injection |

`py sast.py rules` prints this table. Each finding has severity, **confidence** (High = untrusted source proven to reach the sink; Medium = dynamic data or a function parameter reaches the sink; Low = risky API, no evidence), evidence, explanation, remediation and, where known, the **source → sink flow**.

---

## 1. Run it (Windows + PyCharm)

1. Install **Python 3.10+** from python.org (tick *Add python.exe to PATH*). Check: `py --version`
2. Extract the ZIP, then in PyCharm: **File → Open →** the `securecode-sast-scanner` folder. Pick any Python 3.10+ interpreter (no packages to install).
3. Open **Terminal** in PyCharm (PowerShell) and run:

```powershell
py -m unittest discover -s tests -v                              # 31 tests should pass
py sast.py scan samples\vulnerable                               # many findings, exit code 1
py sast.py scan samples\fixed                                    # 0 findings, exit code 0
py sast.py scan samples --format html  --output reports\sample.html
py sast.py scan samples --format sarif --output reports\sample.sarif
```

Open `reports\sample.html` in a browser. On Linux/macOS use `python3` instead of `py` and `/` in paths.

**Scan your own code**

```powershell
py sast.py scan C:\path\to\project --format html --output reports\my-report.html
py sast.py scan . --severity high,critical --min-confidence medium
py sast.py scan . --exclude tests,docs            # added to the default exclusions
```

**Useful options**

| Option | Meaning |
|---|---|
| `--format table\|json\|html\|sarif`, `--output FILE` | report type / destination |
| `--severity high,critical` | only show these severities |
| `--min-confidence medium` | hide low-confidence findings |
| `--fail-on high` | exit 1 only for findings at/above this severity (`none` = never) |
| `--exit-zero` | report only, never fail the build |
| `--write-baseline baseline.json` / `--baseline baseline.json` | accept today's findings, show only **new** ones later |

**Exit codes:** `0` clean (or below `--fail-on`), `1` findings, `2` scan/argument error.

**Suppressing a reviewed finding** (own line or the comment line directly above):
`# sast:ignore SC001 -- reason` or `// sast:ignore SC001, SC002 -- reason` (`all` suppresses every rule).

---

## 2. Upload to GitHub (manual, step by step)

**One-time setup**
1. Create a free account at <https://github.com>.
2. Install **Git for Windows** from <https://git-scm.com/download/win> (accept the defaults), then reopen PyCharm. Check: `git --version`
3. On GitHub click **+ → New repository**. Name it `securecode-sast-scanner`, choose Public (or Private), and **leave "Add a README / .gitignore / license" unticked**. Click *Create repository* and copy the HTTPS URL, e.g. `https://github.com/<your-username>/securecode-sast-scanner.git`.

**Push the project** (PyCharm Terminal, inside the project folder)

```powershell
git init
git config user.name  "Your Name"
git config user.email "you@example.com"      # use the e-mail on your GitHub account
git add .
git status                                   # reports/ and __pycache__ must NOT be listed
git commit -m "SecureCode SAST scanner: AST taint analysis, SARIF, CI"
git branch -M main
git remote add origin https://github.com/<your-username>/securecode-sast-scanner.git
git push -u origin main
```

A browser window opens the first time to sign in (Git Credential Manager). If you are asked for a password in the terminal, use a **Personal Access Token** (GitHub → Settings → Developer settings → Personal access tokens → *Fine-grained*, repository access = this repo, permission *Contents: Read and write*).

**Without the terminal:** PyCharm menu **Git → Create Git Repository…**, then **Git → Commit…** (select all files), then **Git → Push…** and *Define remote* with the URL above. Or on GitHub use **Add file → Upload files** and drag the folder contents in (limit: 100 files per upload).

**After the first push**
- The **Actions** tab runs `.github/workflows/sast.yml` (tests on Python 3.10-3.13, scan, SARIF upload).
- Findings appear under **Security → Code scanning** (public repos, or private repos with GitHub Advanced Security).
- Later changes: `git add . ; git commit -m "message" ; git push`.

> `samples/vulnerable` contains **intentionally insecure demo code** with obviously fake credentials. Keep the README note that it is for training only.

---

## 3. Jenkins

`Jenkinsfile` (declarative, Windows + Linux agents) runs the tests, then the scan, and archives `reports/sast-report.html` and `reports/sast.sarif`. Findings at HIGH or above make the build **UNSTABLE** (change to `FAILURE` to block). Full setup walk-through: [docs/JENKINS.md](docs/JENKINS.md).

## 4. Test it on real open-source projects

```powershell
py scripts\scan_oss.py                 # clones DVWA, NodeGoat, pygoat, WebGoat, govwa and scans each
py scripts\scan_oss.py DVWA pygoat     # or choose
```

Reports land in `reports\`. Results from our own run and the triage method are in [docs/OSS_RESULTS.md](docs/OSS_RESULTS.md).

## 5. More documentation

- [docs/FILE_GUIDE.md](docs/FILE_GUIDE.md) - what every file is and what was changed
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - how the engine works and how to add a rule
- [docs/MANUAL_TEST_PLAN.md](docs/MANUAL_TEST_PLAN.md) - manual verification & triage checklist
- [docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md) - how to present the project

## Limitations (read this)

This is an educational scanner, not a replacement for commercial SAST. Python has real taint analysis; **JS/Java/PHP/Go use line-oriented matching with simple variable tracking** (no cross-function flow, no object-field tracking, no framework models), so expect false positives and missed bugs there. Python files that do not parse (e.g. Python 2) fall back to the regex engine. Always validate findings manually and never use it as the only release gate.
