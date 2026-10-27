"""Workspace scan: Opengrep + TruffleHog in parallel, merged, stored and audited."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import tools
from .models import Finding, a11y_score, security_score
from .scanners import opengrep, trufflehog
from .store import Store
from .tools import OPENGREP_VERSION, TRUFFLEHOG_VERSION
from .triage import merge

RULES_VERSION = "0.1.0"


def run_scanners(target: Path, files: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    with ThreadPoolExecutor(max_workers=2) as pool:
        og = pool.submit(opengrep.scan, target, files)
        # TruffleHog is cheap on whole folders; for a single-file rescan we still scan the folder
        # only when no file list is given, to keep on-save scans fast.
        th = pool.submit(trufflehog.scan_filesystem, target) if not files else None
        findings, errors = og.result()
        if th is not None:
            f2, e2 = th.result()
            findings += f2
            errors += e2
    return findings, errors


def scan_workspace(workspace: str | Path, files: list[str] | None = None, store: Store | None = None) -> dict[str, Any]:
    root = Path(workspace).resolve()
    store = store or Store(root)
    t0 = time.time()
    scan_id = store.start_scan(str(root), "workspace" if not files else "files")
    raw, errors = run_scanners(root, files)
    findings = merge(raw, store.statuses())
    if files:
        # Partial scan: keep earlier findings for files we didn't rescan.
        rescanned = {Path(f).as_posix().lstrip("./") for f in files}
        previous = [store.get_finding(fid) for fid, st in store.statuses().items() if st == "open"]
        keep = [f for f in previous if f and f.path not in rescanned and f.source != "web"]
        findings = merge(findings + keep, store.statuses())
    sec, a11y = security_score(findings), a11y_score(findings)
    store.finish_scan(scan_id, findings, sec, a11y)
    store.audit(
        "scan.finished",
        {
            "target": str(root), "files": files or "all", "findings": len(findings),
            "critical": sum(f.severity == "critical" for f in findings),
            "rules_version": RULES_VERSION, "opengrep": OPENGREP_VERSION, "trufflehog": TRUFFLEHOG_VERSION,
            "seconds": round(time.time() - t0, 2),
        },
    )
    return {
        "scan_id": scan_id,
        "target": str(root),
        "findings": [f.to_dict() for f in findings],
        "security_score": sec,
        "a11y_score": a11y,
        "errors": errors,
        "seconds": round(time.time() - t0, 2),
        "tools": tools.status(),
    }
