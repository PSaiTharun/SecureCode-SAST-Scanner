"""Scan engine: file discovery, analyzer dispatch, suppressions and baseline fingerprints."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from pathlib import Path
from typing import List, Tuple

from . import secret_rules as sec
from .models import CONFIDENCE_ORDER, Finding
from .python_analyzer import PythonAnalyzer
from .regex_engine import LANG_BY_EXT, RegexAnalyzer
from .rules import make_finding

EXT = set(LANG_BY_EXT)
DEFAULT_EXCLUDES = (
    ".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", "*.min.js", "*.bundle.js", "*.d.ts",
)
IGNORE_MARKER = re.compile(r"sast:ignore", re.I)
IGNORE_IDS = re.compile(r"SC\d{3}|all", re.I)
COMMENT_START = ("#", "//", "/*", "*", "<!--")


def parse_ignores(lines: List[str]):
    """Map line number -> set of suppressed rule ids.

    ``# sast:ignore SC001, SC002 -- reason`` applies to its own line; when the comment is
    alone on a line it also applies to the next line.  ``all`` suppresses every rule.
    """
    out = {}
    for no, raw in enumerate(lines, 1):
        m = IGNORE_MARKER.search(raw)
        if not m:
            continue
        tail = raw[m.end():].split("--", 1)[0]
        ids = {i.upper() if i.lower() != "all" else "ALL" for i in IGNORE_IDS.findall(tail)}
        if not ids:
            continue
        out.setdefault(no, set()).update(ids)
        if raw.strip().startswith(COMMENT_START):
            out.setdefault(no + 1, set()).update(ids)
    return out


class Scanner:
    def __init__(self, excluded_dirs=None, max_file_bytes=1048576):
        self.excluded = set(excluded_dirs or ())
        self.max_file_bytes = max_file_bytes
        self.suppressed = 0
        self.fallbacks = 0          # Python files that failed to parse and used the regex fallback
        self.errors: List[str] = []

    # ---- discovery ------------------------------------------------------------------
    def _excluded(self, name: str, rel: str) -> bool:
        return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in self.excluded)

    def _iter_files(self, target: Path, base: Path):
        if target.is_file():
            yield target
            return
        for root, dirs, files in os.walk(target, followlinks=False):
            # Exclusions are matched against paths *relative to the scan root*, so a project that
            # happens to live inside a folder called "build" or "dist" is still scanned.
            rel_root = Path(root).relative_to(base).as_posix()
            prefix = "" if rel_root == "." else rel_root + "/"
            dirs[:] = sorted(d for d in dirs if not self._excluded(d, prefix + d))
            for f in sorted(files):
                if not self._excluded(f, prefix + f):
                    yield Path(root) / f

    # ---- scanning -------------------------------------------------------------------
    def scan(self, target) -> Tuple[List[Finding], int, int]:
        target = Path(target).resolve()
        if not target.exists():
            raise ValueError(f"Target does not exist: {target}")
        base = target if target.is_dir() else target.parent
        findings: List[Finding] = []
        scanned = skipped = 0
        self.suppressed = self.fallbacks = 0
        self.errors = []
        for path in self._iter_files(target, base):
            if path.suffix.lower() not in EXT:
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    skipped += 1
                    continue
                text = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                skipped += 1
                continue
            scanned += 1
            rel = path.relative_to(base).as_posix()
            try:
                findings.extend(self._scan_text(text, rel, LANG_BY_EXT[path.suffix.lower()]))
            except Exception as exc:                      # never let one odd file stop the scan
                self.errors.append(f"{rel}: {type(exc).__name__}: {exc}")
                skipped += 1
        findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
        self._fingerprint(findings)
        return findings, scanned, skipped

    def _scan_text(self, text: str, rel: str, lang: str) -> List[Finding]:
        if lang == "py":
            try:
                found = PythonAnalyzer(text, rel).run()
                found.extend(self._format_secrets(text, rel))
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self.fallbacks += 1
                found = RegexAnalyzer(text, rel, "py").run()
        else:
            found = RegexAnalyzer(text, rel, lang).run()
        return self._postprocess(found, text)

    @staticmethod
    def _format_secrets(text: str, rel: str) -> List[Finding]:
        out = []
        for no, line in enumerate(text.splitlines(), 1):
            for label, value in sec.format_hits(line):
                out.append(make_finding("SC004", rel, no, sec.redact(line.strip(), value)[:220], "High",
                                        detail=f"Looks like a {label} committed to source.",
                                        trace=[(no, f"{label} in source")]))
        return out

    def _postprocess(self, found: List[Finding], text: str) -> List[Finding]:
        ignores = parse_ignores(text.splitlines())
        best = {}
        for f in found:
            ids = set()
            for ln in range(f.line, max(f.line, f.end_line) + 1):
                ids |= ignores.get(ln, set())
            if f.rule_id in ids or "ALL" in ids:
                self.suppressed += 1
                continue
            key = (f.rule_id, f.line)
            old = best.get(key)
            if old is None or CONFIDENCE_ORDER[f.confidence.lower()] > CONFIDENCE_ORDER[old.confidence.lower()]:
                best[key] = f
        return list(best.values())

    @staticmethod
    def _fingerprint(findings: List[Finding]):
        """Stable ids that survive line-number changes (used by --baseline)."""
        seen = {}
        for f in findings:
            norm = re.sub(r"\s+", " ", f.evidence.strip())
            key = (f.rule_id, f.file, norm)
            seen[key] = seen.get(key, 0) + 1
            raw = f"{f.rule_id}|{f.file}|{norm}|{seen[key]}"
            f.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
