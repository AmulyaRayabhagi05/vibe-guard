"""Check a patch before anyone sees it: it parses, the issue is gone, and nothing new appeared."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from ..context import language_for, parse_ok
from ..models import Finding
from ..scanners import opengrep, trufflehog


def _scan_copy(rel_path: str, content: str) -> list[Finding]:
    tmp = Path(tempfile.mkdtemp(prefix="vibecheck-validate-"))
    try:
        dest = tmp / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        found, _ = opengrep.scan(tmp, [rel_path])
        secrets, _ = trufflehog.scan_filesystem(tmp)
        return found + secrets
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def validate(finding: Finding, original: str, patched: str, test_command: str | None = None, cwd: str | None = None) -> dict:
    lang = language_for(finding.path)
    checks = []

    syntax = parse_ok(patched, lang)
    checks.append({"name": "parses", "ok": syntax is not False, "detail": "tree-sitter" if syntax is not None else "not checked for this file type"})

    before = Counter(f.rule_id for f in _scan_copy(finding.path, original))
    after_findings = _scan_copy(finding.path, patched)
    after = Counter(f.rule_id for f in after_findings)
    resolved = after[finding.rule_id] < max(before[finding.rule_id], 1) or finding.rule_id not in after
    checks.append({"name": "finding resolved", "ok": resolved, "detail": finding.rule_id})

    new = sorted(r for r in after if after[r] > before.get(r, 0) and r != finding.rule_id)
    checks.append({"name": "no new findings", "ok": not new, "detail": ", ".join(new) or "0 new"})

    if test_command:
        try:
            proc = subprocess.run(test_command, shell=True, cwd=cwd, capture_output=True, text=True, timeout=600)
            checks.append({"name": "tests pass", "ok": proc.returncode == 0, "detail": (proc.stdout + proc.stderr)[-400:]})
        except subprocess.TimeoutExpired:
            checks.append({"name": "tests pass", "ok": False, "detail": "timed out after 10 minutes"})

    return {"ok": all(c["ok"] for c in checks), "checks": checks}
