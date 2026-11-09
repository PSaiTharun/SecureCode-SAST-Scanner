# Manual test plan

```powershell
py -m unittest discover -s tests -v                       # all tests pass
py sast.py scan samples\vulnerable                        # exit code 1, findings in every language
py sast.py scan samples\fixed                             # exit code 0, no findings
py sast.py scan samples --format sarif --output reports\s.sarif
py sast.py scan samples\vulnerable --write-baseline reports\b.json
py sast.py scan samples\vulnerable --baseline reports\b.json     # exit code 0 (all baselined)
py scripts\scan_oss.py DVWA NodeGoat pygoat
```

## Checks
| Check | Expected |
|---|---|
| Fixed samples | 0 findings |
| `flask_app.py` (vulnerable) | SC001, SC002 (incl. call-site flow through `run_ping`), SC003, SC008, SC010, SC011, SC012 with a *Flow:* line |
| Add `# sast:ignore SC002 -- reviewed` above a finding | finding disappears; summary shows `suppressed: 1` |
| Secrets | evidence shows `***REDACTED***`, never the real value |
| SARIF | opens in VS Code *SARIF Viewer* extension / uploads to GitHub code scanning |

## Triage template (record for every finding on a real project)
`file:line | rule | TRUE POSITIVE / FALSE POSITIVE / NEEDS INVESTIGATION | is untrusted input reachable? | sanitizer/validation present? | impact | fix | retest evidence`
