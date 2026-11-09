# Architecture

```
sast.py                     CLI: arguments, filters, baseline, exit codes
scanner/
  engine.py                 file discovery, analyzer dispatch, suppressions, fingerprints
  python_analyzer.py        Python: ast parsing + taint analysis (+ syntactic checks)
  regex_engine.py           JS/TS, Java, PHP, Go (and unparsable Python): regex + taint-lite
  rules.py                  rule catalogue (id, CWE, severity, text) - single source of truth
  secret_rules.py           credential names/formats, placeholder filters, redaction
  models.py                 Finding dataclass
  reporting.py              table, JSON, HTML, SARIF 2.1.0
```

## Execution flow
1. `sast.py scan` builds a `Scanner` with the exclusions and walks the tree (`os.walk`, pruning excluded dirs; exclusions match paths *relative to the scan root*).
2. Each supported file goes to an analyzer: `.py` -> `PythonAnalyzer` (falls back to `RegexAnalyzer` on `SyntaxError`), everything else -> `RegexAnalyzer`.
3. Findings are post-processed: `sast:ignore` suppressions, de-duplication per (rule, line) keeping the highest confidence, and a **fingerprint** (hash of rule + file + normalised code, *not* the line number) so baselines survive refactors.
4. CLI filters (severity, confidence, baseline), then a reporter writes the result and the exit code is derived from `--fail-on`.

## Python taint analysis (python_analyzer.py)
- **Sources** (`request.args`, `input()`, `sys.argv`...) create taint with `src=True` -> *High* confidence. **Function parameters** create taint with `params={i}` -> *Medium* (callers may pass untrusted data).
- Taint flows through assignment, `+`, `%`, f-strings, containers, unknown calls and string methods.
- **Sanitizers are context-specific**: a `Taint` remembers which rule ids it is already safe for (`html.escape` -> SC003 only, `shlex.quote` -> SC002 only). `int()`, `len()`, `uuid.UUID()` clear everything.
- **Validation guards** are understood: `if x not in ALLOWED: raise`, `x.isdigit()`, `re.fullmatch`, `base not in path.parents`.
- **Interprocedural summaries**: for each function we record which parameters reach which sinks and what the return value derives from; calls like `helper(request.args["c"])` are reported at the call site with the full trace. Summaries are iterated until stable.
- Strings, comments and docstrings can no longer cause matches because we work on the AST.

## Regex engine (regex_engine.py)
Per language: a *profile* (sources, sanitizers, "dynamic string" pattern, assignment patterns) and a list of `Spec` sinks. Modes: `dyn` (needs dynamic data or tainted var), `taint` (needs source/tainted var), `eval` (argument must not be a literal), `always` (API itself is the problem). Statements are cut at `;` so one statement never leaks into the next. SSRF requires the *start* of the URL to be user-controlled.

## Adding a rule
1. Add `RuleMeta("SC0xx", ...)` in `rules.py`.
2. Python: add a sink to `check_sinks()` (taint) or `_check_call()` (syntactic). Other languages: add a `Spec(...)` to `SPECS`.
3. Add a vulnerable and a fixed example under `samples/` and a test in `tests/test_scanner.py`.

## Known limits / roadmap
- No AST for JS/Java/PHP/Go yet (next step: tree-sitter), no cross-file flow, no framework/ORM models, no `@PathVariable`-style parameter sources.
- Python guards are name-based and flow-insensitive across loops; sanitizer lists are curated, not exhaustive.
- Ideas: cross-file call graph, tree-sitter parsers, rule packs in YAML, autofix hints.
