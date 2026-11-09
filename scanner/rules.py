"""Rule catalogue: one place that defines every rule's metadata.

The analyzers (python_analyzer.py, regex_engine.py) decide *where* a rule fires;
this file defines *what* the rule is called, how severe it is and how to fix it.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding

A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"
A07 = "A07:2021 Identification and Authentication Failures"
A08 = "A08:2021 Software and Data Integrity Failures"
A10 = "A10:2021 Server-Side Request Forgery"


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    cwe: str
    severity: str
    owasp: str
    description: str
    remediation: str


_RULES = [
    RuleMeta("SC001", "Possible SQL injection", "CWE-89", "High", A03,
             "A SQL statement is built from dynamic data using concatenation or formatting.",
             "Use parameterized queries/prepared statements; never format input into SQL."),
    RuleMeta("SC002", "Possible OS command injection", "CWE-78", "Critical", A03,
             "A process or shell command is built from dynamic data.",
             "Avoid shell command strings; use argument arrays and strict allowlists."),
    RuleMeta("SC003", "Possible cross-site scripting", "CWE-79", "High", A03,
             "Dynamic data is written into an HTML response or DOM sink without output encoding.",
             "Prefer auto-escaping templates / textContent; contextually encode untrusted data."),
    RuleMeta("SC004", "Possible hardcoded credential", "CWE-798", "High", A07,
             "A credential, token or private key appears to be stored in source code.",
             "Remove secrets from source; use a secret manager/environment config and rotate exposed values."),
    RuleMeta("SC005", "Dynamic code evaluation", "CWE-95", "High", A03,
             "Dynamic evaluation executes code represented as data.",
             "Avoid eval/exec; use explicit parsing (JSON, ast.literal_eval) or a safe expression library."),
    RuleMeta("SC006", "Possible path traversal / file inclusion", "CWE-22", "High", A01,
             "A file path (or included file) is derived from dynamic data and may escape the intended directory.",
             "Normalize paths, verify resolved containment under a fixed base, and allowlist permitted files."),
    RuleMeta("SC007", "Weak hash algorithm", "CWE-327", "Medium", A02,
             "MD5/SHA-1 are broken for security purposes (passwords, signatures, integrity).",
             "Use SHA-256 or better for integrity; use bcrypt/scrypt/argon2 for passwords."),
    RuleMeta("SC008", "Insecure deserialization", "CWE-502", "High", A08,
             "Deserializing untrusted data with a format that can instantiate arbitrary objects can lead to code execution.",
             "Use data-only formats (JSON); use yaml.safe_load; never unpickle/unserialize untrusted data."),
    RuleMeta("SC009", "Certificate or signature verification disabled", "CWE-295", "High", A02,
             "TLS certificate/hostname or token signature verification is turned off.",
             "Keep verification enabled; pin or add a CA bundle instead of disabling checks."),
    RuleMeta("SC010", "Possible server-side request forgery", "CWE-918", "High", A10,
             "The server makes an outbound request to a destination controlled by the user.",
             "Allowlist destination hosts, block private/link-local addresses and disable redirects."),
    RuleMeta("SC011", "Possible open redirect", "CWE-601", "Medium", A01,
             "The application redirects to a user-controlled URL.",
             "Redirect only to relative paths or an allowlist of hosts."),
    RuleMeta("SC012", "Insecure configuration", "CWE-489", "Medium", A05,
             "Debug mode, permissive binding or disabled protections expose the application.",
             "Disable debug features outside local development and bind/permit only what is required."),
    RuleMeta("SC013", "Insecure randomness for a security value", "CWE-338", "Medium", A02,
             "A predictable PRNG is used for a token, password, salt, nonce or similar value.",
             "Use secrets (Python), crypto.randomBytes (Node), SecureRandom (Java), crypto/rand (Go), random_bytes (PHP)."),
    RuleMeta("SC014", "Possible server-side template injection", "CWE-1336", "High", A03,
             "Untrusted input is used as a template, allowing code execution inside the template engine.",
             "Pass user data as template variables; never use it as the template source."),
]

META = {r.rule_id: r for r in _RULES}


def make_finding(rule_id, file, line, evidence, confidence, detail="",
                 trace=None, end_line=None, severity=None) -> Finding:
    """Build a Finding using the catalogue metadata for ``rule_id``."""
    meta = META[rule_id]
    return Finding(
        rule_id=rule_id, title=meta.name, cwe=meta.cwe,
        severity=severity or meta.severity, confidence=confidence,
        file=file, line=line, evidence=evidence,
        description=meta.description, remediation=meta.remediation,
        end_line=end_line or line, detail=detail, trace=list(trace or []),
    )
