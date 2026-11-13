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



## 1. Test it on real open-source projects

```powershell
py scripts\scan_oss.py                 # clones DVWA, NodeGoat, pygoat, WebGoat, govwa and scans each
py scripts\scan_oss.py DVWA pygoat     # or choose
```

Reports land in `reports\`. Results from our own run and the triage method are in [docs/OSS_RESULTS.md](docs/OSS_RESULTS.md).

This is an educational scanner, not a replacement for commercial SAST. Python has real taint analysis; **JS/Java/PHP/Go use line-oriented matching with simple variable tracking** (no cross-function flow, no object-field tracking, no framework models), so expect false positives and missed bugs there. Python files that do not parse (e.g. Python 2) fall back to the regex engine. Always validate findings manually and never use it as the only release gate.
