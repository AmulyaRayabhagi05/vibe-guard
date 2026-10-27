"""Merge scanner output: dedupe overlaps, drop accepted risks, order by severity."""
from __future__ import annotations

from .models import SEVERITIES, Finding

# When Opengrep and TruffleHog flag the same line for the same thing, keep the more specific one.
_PREFER = {"trufflehog": 0, "opengrep": 1, "axe": 2, "web": 3, "osv": 4}


def merge(findings: list[Finding], statuses: dict[str, str] | None = None) -> list[Finding]:
    statuses = statuses or {}
    by_loc: dict[tuple, Finding] = {}
    out: list[Finding] = []
    for f in findings:
        if statuses.get(f.id) in ("accepted", "ignored"):
            continue
        if f.category == "secret" and f.start_line:
            key = (f.path, f.start_line, "secret")
            prev = by_loc.get(key)
            if prev is not None:
                if _PREFER.get(f.source, 9) < _PREFER.get(prev.source, 9):
                    out.remove(prev)
                    by_loc[key] = f
                    out.append(f)
                continue
            by_loc[key] = f
        out.append(f)
    seen: set[str] = set()
    unique = []
    for f in out:
        if f.id not in seen:
            seen.add(f.id)
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITIES.index(f.severity), f.category == "a11y", f.path, f.start_line))
    return unique
