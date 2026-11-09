"""SecureCode SAST Scanner - command line interface.

Examples
    python sast.py scan samples
    python sast.py scan . --format html --output reports/report.html
    python sast.py scan . --format sarif --output reports/results.sarif --fail-on high
    python sast.py scan . --baseline baseline.json          # only show NEW findings
    python sast.py rules                                     # list every rule

Exit codes: 0 = clean (or below --fail-on)   1 = findings at/above --fail-on   2 = scan/argument error
"""
import argparse
import json
import sys
from pathlib import Path

from scanner import __version__
from scanner.engine import DEFAULT_EXCLUDES, Scanner
from scanner.models import CONFIDENCE_ORDER, SEVERITY_ORDER
from scanner.rules import META


def _csv(value):
    return [x.strip() for x in value.split(",") if x.strip()]


def build_parser():
    p = argparse.ArgumentParser(prog="sast.py", description="SecureCode multi-language SAST scanner")
    p.add_argument("--version", action="version", version=f"SecureCode SAST Scanner {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("target", help="file or directory to scan")
    s.add_argument("--format", choices=["table", "json", "html", "sarif"], default="table")
    s.add_argument("--output", "-o", help="output file (required for html; json/sarif print to stdout without it)")
    s.add_argument("--severity", default="low,medium,high,critical", help="comma list of severities to show")
    s.add_argument("--min-confidence", choices=["low", "medium", "high"], default="low",
                   help="hide findings below this confidence (default: show all)")
    s.add_argument("--exclude", default="", help="extra comma-separated dir/file names or globs to skip "
                   "(added to the defaults: " + ",".join(DEFAULT_EXCLUDES[:7]) + ",...)")
    s.add_argument("--no-default-excludes", action="store_true", help="do not apply the default exclusions")
    s.add_argument("--max-size-kb", type=int, default=1024, help="skip files larger than this (default 1024)")
    s.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="low",
                   help="exit 1 when a finding at/above this severity remains (default: low = any finding)")
    s.add_argument("--exit-zero", action="store_true", help="always exit 0 (report-only mode)")
    s.add_argument("--baseline", help="JSON baseline: findings already listed in it are hidden")
    s.add_argument("--write-baseline", help="write all current findings to this baseline file and exit 0")

    sub.add_parser("rules", help="list the detection rules")
    return p


def cmd_rules():
    print(f"{'ID':<6} {'Sev':<9} {'CWE':<9} Name")
    for r in META.values():
        print(f"{r.rule_id:<6} {r.severity:<9} {r.cwe:<9} {r.name}")
    return 0


def cmd_scan(a, parser):
    if a.format == "html" and not a.output:
        parser.error("--output is required for html")
    excludes = set() if a.no_default_excludes else set(DEFAULT_EXCLUDES)
    excludes |= set(_csv(a.exclude))
    scanner = Scanner(excludes, a.max_size_kb * 1024)
    findings, scanned, skipped = scanner.scan(Path(a.target))

    allowed = {x.lower() for x in _csv(a.severity)}
    min_conf = CONFIDENCE_ORDER[a.min_confidence]
    findings = [f for f in findings
                if f.severity.lower() in allowed and CONFIDENCE_ORDER[f.confidence.lower()] >= min_conf]

    if a.write_baseline:
        data = {"tool": "SecureCode SAST Scanner", "version": __version__,
                "fingerprints": sorted({f.fingerprint for f in findings})}
        Path(a.write_baseline).parent.mkdir(parents=True, exist_ok=True)
        Path(a.write_baseline).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Baseline with {len(data['fingerprints'])} findings written: {a.write_baseline}")
        return 0

    baselined = 0
    if a.baseline:
        try:
            known = set(json.loads(Path(a.baseline).read_text(encoding="utf-8")).get("fingerprints", []))
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot read baseline {a.baseline}: {exc}")
        kept = [f for f in findings if f.fingerprint not in known]
        baselined = len(findings) - len(kept)
        findings = kept

    from scanner import reporting as rep
    notes = []
    if scanner.suppressed:
        notes.append(f"suppressed: {scanner.suppressed}")
    if baselined:
        notes.append(f"baselined: {baselined}")
    if scanner.fallbacks:
        notes.append(f"regex-fallback files: {scanner.fallbacks}")
    extra = ", ".join(notes)

    if a.format == "table":
        print(rep.render_table(findings, scanned, skipped, extra))
    else:
        text = {"json": rep.json_text, "html": rep.html_text, "sarif": rep.sarif_text}[a.format](findings, scanned, skipped)
        if a.output:
            out = Path(a.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"Report written: {a.output}  ({len(findings)} findings: {rep.summary_counts(findings)}"
                  + (f"; {extra}" if extra else "") + ")")
        else:
            print(text)
    for err in scanner.errors:
        print(f"warning: could not analyse {err}", file=sys.stderr)

    if a.exit_zero or a.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[a.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity.lower()] >= threshold for f in findings) else 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")      # evidence may contain characters the console can't show
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    a = parser.parse_args(argv)
    try:
        return cmd_rules() if a.cmd == "rules" else cmd_scan(a, parser)
    except (OSError, ValueError) as exc:
        print("Scan error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
