"""Clone well-known vulnerable-by-design projects and scan them with SecureCode SAST.

    py scripts/scan_oss.py                 (Windows)      python3 scripts/scan_oss.py   (Linux/macOS)
    py scripts/scan_oss.py DVWA NodeGoat   (only some)

Needs `git` and internet access. Clones go to ./oss-targets (git-ignored); reports to ./reports.
"""
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scanner import reporting  # noqa: E402
from scanner.engine import DEFAULT_EXCLUDES, Scanner  # noqa: E402

TARGETS = {
    "DVWA": "https://github.com/digininja/DVWA.git",                 # PHP
    "NodeGoat": "https://github.com/OWASP/NodeGoat.git",            # Node.js
    "pygoat": "https://github.com/adeyosemanputra/pygoat.git",      # Python / Django
    "WebGoat": "https://github.com/WebGoat/WebGoat.git",            # Java
    "govwa": "https://github.com/0c34/govwa.git",                   # Go
}


def main(names):
    names = names or list(TARGETS)
    dest = ROOT / "oss-targets"
    dest.mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    print(f"{'project':<10} {'files':>6} {'findings':>9} {'seconds':>8}  severity mix")
    for name in names:
        if name not in TARGETS:
            print(f"unknown target {name}; choose from {', '.join(TARGETS)}")
            continue
        repo = dest / name
        if not repo.exists():
            subprocess.run(["git", "clone", "--depth", "1", "-q", TARGETS[name], str(repo)], check=True)
        start = time.time()
        scanner = Scanner(set(DEFAULT_EXCLUDES))
        findings, scanned, skipped = scanner.scan(repo)
        took = time.time() - start
        reporting.write_html(findings, scanned, skipped, ROOT / "reports" / f"{name}.html")
        reporting.write_sarif(findings, scanned, skipped, ROOT / "reports" / f"{name}.sarif")
        print(f"{name:<10} {scanned:>6} {len(findings):>9} {took:>8.2f}  {reporting.summary_counts(findings)}")
    print("Reports written to reports/ - open the .html files and TRIAGE the findings (true / false positive).")


if __name__ == "__main__":
    main(sys.argv[1:])
