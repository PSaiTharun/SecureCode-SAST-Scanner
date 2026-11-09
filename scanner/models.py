"""Shared data model: what a finding looks like and how severities compare."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    rule_id: str
    title: str
    cwe: str
    severity: str          # Low | Medium | High | Critical
    confidence: str        # Low | Medium | High
    file: str              # path relative to the scan root, '/' separators
    line: int
    evidence: str          # the offending source line (secrets are redacted)
    description: str       # generic explanation of the weakness
    remediation: str
    end_line: int = 0      # last line of the statement (0 = same as line)
    detail: str = ""       # specific explanation for this finding
    trace: list = field(default_factory=list)   # [(line, message), ...] source -> sink
    fingerprint: str = ""  # stable id used for baselines (set by the engine)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["trace"] = [{"line": ln, "message": msg} for ln, msg in self.trace]
        return data
