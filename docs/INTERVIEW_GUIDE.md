# Interview explanation

"I built a multi-language SAST scanner in Python. For Python it parses the AST and runs a source-to-sink **taint analysis**: sources like `request.args` create taint, assignments/concatenation/f-strings propagate it, context-specific sanitizers (`shlex.quote` for command injection, `html.escape` for XSS) and validation guards (allow-lists, `isdigit`, path-containment checks) remove it, and sinks like `cursor.execute` or `os.system` report with a source-to-sink trace. It builds function summaries so a tainted value passed through a helper is still caught. For JavaScript, Java, PHP and Go it uses regex rules with per-file variable tracking and language-specific sinks. It covers 14 CWE-mapped rules, redacts secrets in reports, supports inline suppressions and **baselines** (stable fingerprints), emits **SARIF 2.1.0** for GitHub code scanning, and has Jenkins and GitHub Actions pipelines. I validated it on DVWA, NodeGoat, pygoat, WebGoat and govwa, triaged samples of findings and turned every false-positive pattern into a rule fix plus a regression test (31 unit tests)."

**Is it production-ready?** No. Python has real taint analysis; the other languages are heuristic and single-file.

**How do you triage?** Trace untrusted input to the sink, check sanitization/parameterization/validation, assess reachability and impact, mark true/false positive, fix, retest.

**How would you improve it?** tree-sitter ASTs for the other languages, cross-file call graph, framework/ORM models, YAML rule packs, autofix suggestions, precision/recall benchmarks (OWASP Benchmark).

**Why confidence levels?** High = proven source reaches sink; Medium = dynamic data or an unvalidated parameter reaches it; Low = risky API only. It lets teams gate CI on high-confidence findings and review the rest.
