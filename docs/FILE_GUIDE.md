# File guide: what each file is and what was done

Legend: **Original** = existed in the first prototype (regex-only, about 190 lines). **Rewritten** = same file, new content. **New** = added.

## Entry point
| File | Status | What it does / what was done |
|---|---|---|
| `sast.py` | Rewritten | Command-line interface. Original had one `scan` command with table/JSON/HTML output. Now: `scan` and `rules` commands; `sarif` format; `--min-confidence`, `--fail-on`, `--exit-zero`, `--baseline`, `--write-baseline`, `--no-default-excludes`; exit codes 0/1/2; safe console output on Windows. |

## The scanner package (`scanner/`)
| File | Status | What it does / what was done |
|---|---|---|
| `__init__.py` | Rewritten | Holds the version number (`2.0.0`) shown in reports and SARIF. |
| `models.py` | New | The `Finding` data class (rule, severity, confidence, file, line, evidence, explanation, fix, source-to-sink trace, fingerprint). Shared by every analyzer and reporter. |
| `rules.py` | Rewritten | Original held a tiny helper for 6 regex rules. Now it is the **rule catalogue**: id, name, CWE, OWASP category, severity, description and remediation for all 14 rules (SC001-SC014), plus `make_finding()`. One place to change wording or severity. |
| `engine.py` | Rewritten | Original: walked files, ran 6 regexes per line. Now: walks the tree efficiently and skips excluded folders (fixing a bug where a project inside a folder named `build`/`dist` was ignored); sends `.py` files to the Python analyzer and everything else to the regex engine; falls back to regex if a Python file will not parse; applies `sast:ignore` suppressions (several rule ids, comment on the line above); removes duplicate findings; creates stable fingerprints for baselines. |
| `python_analyzer.py` | New | **Python AST + taint analysis.** Parses code into a syntax tree, marks untrusted sources (`request.args`, `input()`, ...), follows them through variables, concatenation, f-strings and function calls, and reports when they reach a dangerous sink (SQL, shell, `eval`, file paths, HTTP requests, redirects, deserialization, templates). Understands sanitizers per vulnerability type, validation checks (allow-lists, `isdigit`, path containment), and function summaries so a value passed through a helper is still traced. Also detects weak hashes, disabled TLS verification, debug mode, weak randomness and hard-coded secrets. |
| `regex_engine.py` | New | **JS/TS, Java, PHP, Go analysis** (and fallback for unparsable Python). Original had 6 flat regexes. Now each language has its own sources, sinks and sanitizers, tracks which variables hold untrusted data, understands things like Go `exec.Command` only being risky with `sh -c`, and skips safe parameterized queries. |
| `secret_rules.py` | New | Hard-coded secret logic: secret-like names, known token formats (AWS, GitHub, Slack, Google, Stripe, private keys), filters for placeholders/URLs/config names, entropy check, and **redaction** so reports never print the real secret. |
| `reporting.py` | Rewritten | Original: table, JSON, basic HTML. Now: table with source-to-sink flow lines; JSON with fingerprints; a styled self-contained HTML report (light/dark); and **SARIF 2.1.0** (rules, levels, security-severity, code flows) for GitHub code scanning and IDEs. |

## Tests
| File | Status | What it does / what was done |
|---|---|---|
| `tests/test_scanner.py` | Rewritten | Original had 3 tests. Now 31: your 3 originals, sample ground-truth (vulnerable files must be detected, fixed files must give zero), Python taint cases, per-language cases, secret handling, engine behaviour (exclusions, suppression, fingerprints), report structure (JSON/SARIF) and CLI exit codes/baselines. Run with `py -m unittest discover -s tests -v`. |

## Samples (`samples/`)
| File | Status | What it does / what was done |
|---|---|---|
| `samples/vulnerable/python_app.py, app.js, Example.java, app.php, main.go` | Original | Your intentionally insecure examples, unchanged. |
| `samples/vulnerable/flask_app.py` | New | A Flask app with multi-step and cross-function flaws: SQL injection, XSS, command injection through a helper, SSRF, open redirect, unsafe pickle, debug mode. Shows the taint engine. |
| `samples/fixed/*` | Original | Your safer versions, unchanged. |
| `samples/fixed/flask_app.py` | New | The safe version of the Flask app (int conversion, parameterized query, `html.escape`, allow-list, `shlex.quote`, JSON). Must produce zero findings. |

## Automation and scripts
| File | Status | What it does / what was done |
|---|---|---|
| `Jenkinsfile` | New | Jenkins pipeline: run tests, run the scan (HTML + SARIF), archive reports, mark build unstable on HIGH+ findings. Works on Windows and Linux agents. |
| `.github/workflows/sast.yml` | New | GitHub Actions: tests on Python 3.10-3.13, scan, upload SARIF to code scanning, fail on HIGH+. |
| `scripts/scan_oss.py` | New | Clones DVWA, NodeGoat, pygoat, WebGoat and govwa, scans each, writes HTML and SARIF reports and prints a summary table. |

## Documentation and housekeeping
| File | Status | What it does / what was done |
|---|---|---|
| `README.md` | Rewritten | Features, rule table, how to run in PyCharm, all options, **manual GitHub upload steps**, Jenkins, OSS testing, limitations. |
| `docs/ARCHITECTURE.md` | Rewritten | How the engine works, taint analysis design, how to add a rule, limits and roadmap. |
| `docs/JENKINS.md` | Rewritten | Step-by-step Jenkins job setup, gate behaviour, baselines. |
| `docs/MANUAL_TEST_PLAN.md` | Rewritten | Manual verification commands, expected results, triage template. |
| `docs/OSS_RESULTS.md` | New | Results from scanning five real open-source projects, what was checked by hand, and the false-positive patterns that were found and fixed. |
| `docs/INTERVIEW_GUIDE.md` | Rewritten | How to explain the project and answer common questions. |
| `docs/FILE_GUIDE.md` | New | This file. |
| `requirements.txt` | Original | Still no third-party packages. |
| `.gitignore` | Rewritten | Ignores caches, IDE folders, generated reports and cloned test projects (keeps `reports/.gitkeep`). |
| `reports/.gitkeep` | New | Keeps the empty `reports/` folder in Git. |

## What was done overall, in order
1. Read your prototype: six line-by-line regex rules, three tests, basic reports.
2. Added a rule catalogue, a data model and a better engine (accurate exclusions, suppression, fingerprints).
3. Added real Python AST taint analysis.
4. Rebuilt the JS/Java/PHP/Go analysis with variable tracking, per-language sinks and sanitizers.
5. Added SARIF, baselines, confidence filtering and CI exit codes.
6. Wrote the samples, 31 tests, Jenkins and GitHub pipelines, and the documentation.
7. Scanned five real open-source projects, fixed the false positives found, and re-ran the tests.
