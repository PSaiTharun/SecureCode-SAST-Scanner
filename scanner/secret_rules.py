"""Hard-coded secret detection shared by the Python and regex analyzers.

Three signals are used:
  1. a secret-looking *name* assigned a string literal (``db_password = "..."``),
  2. well-known token *formats* (AWS keys, GitHub tokens, private key blocks, ...),
  3. filters that drop placeholders, URLs, env-var names and UI text.

Evidence lines are redacted so reports never leak the secret they report.
"""
from __future__ import annotations

import math
import re

NAME_RE = re.compile(
    r"(?:pass(?:word|wd|phrase)|(?:^|[_\-])pass(?:$|[_\-])|pwd|secret|api[_-]?key|apikey|"
    r"access[_-]?(?:key|token)|auth[_-]?token|private[_-]?key|client[_-]?secret|token(?!iz)|credential)",
    re.I,
)
# names such as password_field, token_url, secret_name, TOKEN_TYPE are configuration, not secrets
NAME_SKIP_RE = re.compile(
    r"(?:url|uri|path|file|name|field|label|type|prompt|hint|env|header|id|expir\w*|"
    r"length|min|max|regex|pattern|help|text|msg|message|error|placeholder|param|arg|"
    r"required|policy|endpoint|route|class|prefix|suffix|link|page|title|key_len\w*)$",
    re.I,
)
PLACEHOLDER_RE = re.compile(
    r"^(?:change[_-]?me|changeit|your[_-].*|example.*|sample.*|dummy.*|xxx+|\*+|<.*>|"
    r"\$\{.*\}|\{\{.*\}\}|%\(.*\)s|%s|todo|none|null|undefined|password|secret|test|testing|"
    r"token|string|redacted|\.\.\.|\$[a-z_]+)$",
    re.I,
)
FORMAT_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
]
# `name = "value"`, `name: "value"`, `name := "value"`, `'name' => 'value'` (not ==, !=, <=, >=)
ASSIGN_RE = re.compile(
    r"""(?P<name>[A-Za-z_][\w.\-]*)["']?\s*(?:=>|:=|(?<![=!<>])=(?!=)|:)\s*["'](?P<val>[^"'\n]*)["']"""
)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def is_secret_name(name: str) -> bool:
    last = re.split(r"[.\[\]]", name)[-1]
    return bool(NAME_RE.search(last)) and not NAME_SKIP_RE.search(last)


def classify(name: str, value: str):
    """Return 'High', 'Medium' or None for a (name, literal value) pair."""
    if not is_secret_name(name):
        return None
    if len(value) < 6 or re.search(r"\s", value):
        return None
    if PLACEHOLDER_RE.match(value):
        return None
    if value.lower().startswith(("http://", "https://", "/", "./", "file:")):
        return None
    if re.fullmatch(r"[A-Z][A-Z_]+", value):          # looks like an env-var / constant name
        return None
    if len(value) >= 12 and entropy(value) >= 3.0:
        return "High"
    return "Medium"


def redact(line: str, value: str) -> str:
    """Hide most of the secret in an evidence line."""
    if value and value in line:
        keep = value[:2] if len(value) > 8 else ""
        line = line.replace(value, f"{keep}***REDACTED***")
    return line


def format_hits(line: str):
    """Yield (label, matched_text) for well-known token formats found in ``line``."""
    # a PEM header that is merely compared/stripped (``.replace("-----BEGIN PRIVATE KEY-----", "")``) is not a key
    handling = re.search(r"\.(?:replace|contains|startsWith|endsWith|indexOf|equals|split)\s*\(|startswith\(|\bin\s+", line)
    for label, pattern in FORMAT_PATTERNS:
        if label == "Private key block" and handling:
            continue
        for m in pattern.finditer(line):
            yield label, m.group(0)


def assignment_hits(line: str):
    """Yield (name, value, confidence) for secret-looking literal assignments in ``line``."""
    for m in ASSIGN_RE.finditer(line):
        conf = classify(m.group("name"), m.group("val"))
        if conf:
            yield m.group("name"), m.group("val"), conf
