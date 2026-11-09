# Results on real open-source projects

Command: `py scripts\scan_oss.py` (scanner v2.0.0, default exclusions, shallow clones, Python 3.13).
These are **deliberately vulnerable** training applications, so many findings are expected true positives.

| Project | Language | Files | Findings | Time | Severity mix |
|---|---|---|---|---|---|
| DVWA | PHP | 179 | 105 | 0.4 s | 9 critical, 61 high, 35 medium |
| NodeGoat | JavaScript | 48 | 13 | 0.1 s | 12 high, 1 medium |
| pygoat | Python/Django | 118 | 79 | 0.2 s | 1 critical, 47 high, 26 medium, 5 low |
| WebGoat | Java | 583 | 134 | 2.4 s | 128 high, 6 medium |
| govwa | Go | 23 | 6 | 0.1 s | 2 high, 4 medium |

(Counts change as the upstream repositories change.)

## What was manually checked
Triage was done on **samples of findings per rule, not every finding** - treat the table as a starting point, not a precision score.

**Confirmed true positives (examples):** WebGoat `SqlInjectionLesson5a/6a/10`, `SqlInjectionChallenge`, `JWTHeaderKIDEndpoint` (SQL built by concatenating request data); pygoat Flask labs with `app.run(host="0.0.0.0", debug=True)` and hard-coded `app.secret_key`; DVWA command execution, file inclusion and weak MD5 password handling; NodeGoat hard-coded cookie secret and `eval` of request data.

**False-positive patterns found by this exercise and fixed in the scanner** (each led to a rule change):
- `file_get_contents('php://input')` reported as path traversal/SSRF -> `php://` streams are sources, not paths.
- SSRF reported when only the *path* of a URL was user-controlled -> SSRF now requires user control of the URL start.
- `MD5('x')` inside an SQL seed string reported as weak hashing -> matches inside string literals are ignored for API-only rules.
- PEM header inside `.replace("-----BEGIN ...", "")` reported as a private key; `*_LINK`/`*_PAGE` constants reported as passwords.
- Credentials in nested dictionaries were reported on the wrong line.

**Remaining known noise:** demo/seed passwords in fixtures and tests (true hard-coded credentials, but harmless - exclude `test`/`artifacts` dirs or baseline them); Java `args[0]` treated as an untrusted source; JS/PHP/Java/Go detection is single-file and line-based, so real flows split across functions or files are missed.

## Reproduce and triage
1. `py scripts\scan_oss.py DVWA` then open `reports\DVWA.html`.
2. For each finding fill the triage template in `docs/MANUAL_TEST_PLAN.md`.
3. Turn every false positive into a test in `tests/test_scanner.py`, fix the rule, re-run, record the change here.
