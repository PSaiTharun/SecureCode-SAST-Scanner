# Jenkins setup

**Prerequisites:** Jenkins with the *Pipeline* and *Git* plugins, Python 3.10+ on the agent (`py` launcher on Windows, `python`/`python3` on Linux).

1. Push the project to GitHub (README section 2).
2. Jenkins -> **New Item** -> **Pipeline** -> name `securecode-sast`.
3. *Pipeline* section: **Pipeline script from SCM** -> Git -> repository URL -> branch `*/main` -> Script Path `Jenkinsfile`. (For a private repo add credentials.)
4. **Build Now**. Stages: *Tests* -> *SAST scan*. Artifacts `reports/sast-report.html` and `reports/sast.sarif` are archived on the build page.
5. Optional: install **Warnings Next Generation** and un-comment the `recordIssues tool: sarif(...)` line in `post {}` to see findings inside Jenkins.
6. Optional trigger: *Build Triggers* -> **GitHub hook trigger for GITScm polling** + a webhook (`http://<jenkins>/github-webhook/`) on the repo.

**Gate behaviour:** the scan runs with `--fail-on high`; findings at HIGH/CRITICAL mark the build UNSTABLE. Change `buildResult: 'UNSTABLE'` to `'FAILURE'` to block merges. Use a **baseline** so legacy findings do not block new work:

```
python sast.py scan . --write-baseline baseline.json     # once, commit baseline.json
python sast.py scan . --baseline baseline.json --fail-on high
```

`samples/` and `tests/` are excluded because they are intentionally vulnerable. Tune rules and review false positives before using results as a hard gate.
