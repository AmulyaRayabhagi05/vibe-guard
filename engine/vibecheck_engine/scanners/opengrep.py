"""Run Opengrep with VibeCheck's rules and turn results into Findings."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .. import tools
from ..config import IGNORE_DIRS, RULES_DIR
from ..models import Finding

SEVERITY_FALLBACK = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _rel(path: str, root: Path) -> str:
    p = Path(path)
    try:
        p = p.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    return p.as_posix()


def scan(target: str | Path, files: list[str] | None = None, rules: Path = RULES_DIR, timeout: int = 600) -> tuple[list[Finding], list[str]]:
    """Scan a folder (or just `files` inside it). Returns findings and any scanner errors."""
    exe = tools.find("opengrep")
    if not exe:
        return [], ["Opengrep is not installed. Run 'VibeCheck: Set up' to download it."]
    root = Path(target)
    cmd = [
        str(exe), "scan", "--config", str(rules), "--json", "--quiet",
        "--disable-version-check", "--no-rewrite-rule-ids", "--timeout", "10",
    ]
    for d in IGNORE_DIRS:
        cmd += ["--exclude", d]
    # Our own rule fixtures are deliberately vulnerable; skip them when scanning this repo.
    cmd += ["--exclude", "rules/*/*.ts", "--exclude", "rules/*/*.tsx", "--exclude", "rules/*/*.py"]
    cmd += files or ["."]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], [f"Opengrep failed: {proc.stderr.strip()[:500]}"]
    errors = [e.get("message", str(e))[:300] for e in data.get("errors", []) if e.get("level") == "error"]
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        findings.append(
            Finding(
                rule_id=r["check_id"],
                title=meta.get("title", r["check_id"]),
                message=" ".join(extra.get("message", "").split()),
                severity=meta.get("severity") or SEVERITY_FALLBACK.get(extra.get("severity", ""), "medium"),
                category=meta.get("category", "app"),
                path=_rel(r["path"], root),
                start_line=r["start"]["line"],
                end_line=r["end"]["line"],
                cwe=meta.get("cwe", ""),
                owasp=meta.get("owasp", ""),
                wcag=meta.get("wcag", ""),
                source="opengrep",
                snippet=extra.get("lines", "")[:2000],
                fixable=meta.get("fixable", True),
            )
        )
    return findings, errors
