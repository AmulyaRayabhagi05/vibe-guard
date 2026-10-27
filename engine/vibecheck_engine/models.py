"""Shared data types. Every scanner returns Finding objects; the extension receives them as dicts."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
# Points removed from the 100-point security score per open finding.
SEVERITY_WEIGHT = {"critical": 15, "high": 8, "medium": 4, "low": 1, "info": 0}

# Categories drive the tag shown in the UI.
CATEGORIES = ("app", "secret", "ai", "a11y", "web", "dependency")


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: str
    category: str
    path: str  # workspace-relative, forward slashes; a URL for website findings
    start_line: int = 0
    end_line: int = 0
    cwe: str = ""
    owasp: str = ""
    wcag: str = ""  # e.g. "1.1.1 Non-text Content (A)"
    source: str = ""  # opengrep | trufflehog | axe | web | osv
    snippet: str = ""
    fixable: bool = True
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "medium"
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        # Stable across rescans as long as the rule, file and flagged text stay the same,
        # so accepted-risk decisions and audit entries survive line shifts.
        key = f"{self.rule_id}|{self.path}|{self.snippet.strip() or self.start_line}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def security_score(findings: list[Finding]) -> int:
    lost = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.category != "a11y")
    return max(0, 100 - lost)


def a11y_score(findings: list[Finding]) -> int:
    lost = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.category == "a11y")
    return max(0, 100 - lost)
