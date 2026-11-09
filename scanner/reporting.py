"""Output formats: terminal table, JSON, self-contained HTML and SARIF 2.1.0."""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from . import __version__
from .models import CONFIDENCE_ORDER, SEVERITY_ORDER
from .rules import META

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "SecureCode SAST Scanner"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
RANK = {"high": 90.0, "medium": 60.0, "low": 30.0}


def _sorted(fs):
    return sorted(fs, key=lambda f: (-SEVERITY_ORDER[f.severity.lower()],
                                     -CONFIDENCE_ORDER[f.confidence.lower()], f.file, f.line))


def summary_counts(fs) -> str:
    c = Counter(f.severity.lower() for f in fs)
    return ", ".join(f"{c[s]} {s}" for s in ("critical", "high", "medium", "low") if c[s]) or "none"


def _write(out, text):
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------- table
def render_table(fs, scanned, skipped, extra=""):
    out = [f"SecureCode SAST | scanned: {scanned} | skipped: {skipped} | findings: {len(fs)} ({summary_counts(fs)})"
           + (f" | {extra}" if extra else ""), "-" * 88]
    for f in _sorted(fs):
        out += [f"[{f.severity.upper()}] {f.rule_id} {f.title} ({f.cwe})",
                f"  {f.file}:{f.line} | confidence: {f.confidence}",
                f"  Evidence: {f.evidence}",
                f"  Why: {f.detail or f.description}"]
        if len(f.trace) > 1:
            out.append("  Flow: " + "  ->  ".join(f"L{ln} {msg}" for ln, msg in f.trace))
        out += [f"  Fix: {f.remediation}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------- json
def json_text(fs, scanned, skipped):
    return json.dumps({
        "tool": TOOL_NAME, "version": __version__, "files_scanned": scanned, "files_skipped": skipped,
        "finding_count": len(fs), "findings": [f.to_dict() for f in _sorted(fs)],
    }, indent=2)


def write_json(fs, scanned, skipped, out):
    _write(out, json_text(fs, scanned, skipped))


# ---------------------------------------------------------------------------- html
_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#5b6675;--line:#dfe3e8;
--critical:#8b1a1a;--high:#c0392b;--medium:#c77c0e;--low:#2c6fbb}
@media(prefers-color-scheme:dark){:root{--bg:#10151c;--card:#1a212b;--ink:#e6eaf0;--mute:#9aa5b4;--line:#2b3441}}
*{box-sizing:border-box}body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px}.sub{color:var(--mute);margin-bottom:20px}
.tiles{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px}
.tile b{display:block;font-size:22px}.card{background:var(--card);border:1px solid var(--line);
border-left:5px solid var(--low);border-radius:8px;padding:12px 16px;margin-bottom:12px}
.card.critical{border-left-color:var(--critical)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}.badge{display:inline-block;color:#fff;border-radius:4px;
padding:1px 8px;font-size:12px;font-weight:600;margin-right:8px;background:var(--low)}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}.badge.medium{background:var(--medium)}
.meta{color:var(--mute);font-size:13px;margin:4px 0}code,pre{font:12.5px/1.45 ui-monospace,Consolas,monospace}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow:auto;margin:8px 0}
details{margin-top:6px}summary{cursor:pointer;color:var(--mute)}.fix{margin-top:6px}
"""


def html_text(fs, scanned, skipped):
    e = html.escape
    c = Counter(f.severity.lower() for f in fs)
    tiles = "".join(f'<div class="tile"><b>{c[s]}</b>{s}</div>' for s in ("critical", "high", "medium", "low"))
    cards = []
    for f in _sorted(fs):
        sev = f.severity.lower()
        flow = ""
        if len(f.trace) > 1:
            flow = "<details><summary>Data flow (source → sink)</summary><pre>" + e(
                "\n".join(f"line {ln}: {msg}" for ln, msg in f.trace)) + "</pre></details>"
        cards.append(
            f'<div class="card {sev}"><span class="badge {sev}">{e(f.severity)}</span>'
            f'<b>{e(f.rule_id)} {e(f.title)}</b> <span class="meta">({e(f.cwe)})</span>'
            f'<div class="meta">{e(f.file)}:{f.line} &middot; confidence {e(f.confidence)}</div>'
            f'<pre>{e(f.evidence)}</pre><div>{e(f.detail or f.description)}</div>{flow}'
            f'<div class="fix"><b>Fix:</b> {e(f.remediation)}</div></div>')
    body = "".join(cards) or "<p>No findings.</p>"
    return (f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>SAST report</title><style>{_CSS}</style><main><h1>SecureCode SAST Report</h1>"
            f'<div class="sub">Scanner v{__version__} &middot; scanned {scanned} files &middot; skipped {skipped} '
            f"&middot; {len(fs)} findings</div><div class=\"tiles\">{tiles}</div>{body}"
            f'<p class="meta">Heuristic results: validate each finding manually before acting on it.</p></main></html>')


def write_html(fs, scanned, skipped, out):
    _write(out, html_text(fs, scanned, skipped))


# ---------------------------------------------------------------------------- sarif
def _location(uri, line, end_line=None, message=None, snippet=None):
    region = {"startLine": max(1, line)}
    if end_line and end_line >= line:
        region["endLine"] = end_line
    if snippet:
        region["snippet"] = {"text": snippet}
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": region}}
    if message:
        loc["message"] = {"text": message}
    return loc


def sarif_dict(fs, scanned, skipped):
    rule_ids = list(META)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    rules = []
    for rid in rule_ids:
        m = META[rid]
        num = m.cwe.split("-")[-1]
        rules.append({
            "id": rid,
            "name": "".join(w.capitalize() for w in m.name.replace("/", " ").split()),
            "shortDescription": {"text": m.name},
            "fullDescription": {"text": m.description},
            "help": {"text": f"{m.description}\n\nRemediation: {m.remediation}",
                     "markdown": f"{m.description}\n\n**Remediation:** {m.remediation}"},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
            "defaultConfiguration": {"level": SARIF_LEVEL[m.severity.lower()]},
            "properties": {"tags": ["security", f"external/cwe/cwe-{num}", m.owasp],
                           "security-severity": SECURITY_SEVERITY[m.severity.lower()]},
        })
    results = []
    for f in _sorted(fs):
        sev = f.severity.lower()
        result = {
            "ruleId": f.rule_id, "ruleIndex": index[f.rule_id], "level": SARIF_LEVEL[sev],
            "rank": RANK[f.confidence.lower()],
            "message": {"text": f"{f.title}: {f.detail or f.description}"},
            "locations": [_location(f.file, f.line, f.end_line, snippet=f.evidence)],
            "partialFingerprints": {"sastFingerprint/v1": f.fingerprint},
            "properties": {"confidence": f.confidence.lower(), "security-severity": SECURITY_SEVERITY[sev],
                           "cwe": f.cwe},
        }
        if len(f.trace) > 1:
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": _location(f.file, ln, message=msg)} for ln, msg in f.trace]}]}]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "semanticVersion": __version__, "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True}],
            "properties": {"filesScanned": scanned, "filesSkipped": skipped},
        }],
    }


def sarif_text(fs, scanned, skipped):
    return json.dumps(sarif_dict(fs, scanned, skipped), indent=2)


def write_sarif(fs, scanned, skipped, out):
    _write(out, sarif_text(fs, scanned, skipped))
