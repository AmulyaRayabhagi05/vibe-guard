"""'Scan a link': repo or website, picked automatically."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..a11y import axe
from ..models import a11y_score, security_score
from ..store import Store
from ..triage import merge
from . import detect, ownership, repo, website


def scan_link(workspace: str | Path, link: str, a11y: bool = True) -> dict[str, Any]:
    info = detect.classify(link)
    store = Store(workspace, "links.db")
    t0 = time.time()
    scan_id = store.start_scan(info["url"], info["kind"])
    notes: list[str] = []
    if info["kind"] == "repo":
        findings, errors, meta = repo.scan_repo(info)
        notes.append("Scanned a shallow copy in a temporary folder (deleted afterwards). No repo code was run.")
    else:
        findings, errors, meta = website.scan_website(info)
        notes.append("Passive checks only: the page, its own scripts and source maps, and response headers.")
        if a11y:
            try:
                a11y_findings, a11y_meta = axe.check(info["url"])
                findings += a11y_findings
                meta["a11y"] = a11y_meta
            except Exception as e:  # missing Playwright, timeouts, blocked by the site
                errors.append(f"Accessibility check skipped: {e}")
        owner = ownership.verify(info["host"])
        meta["owner_verified"] = owner["verified"]
        if not owner["verified"]:
            meta["owner_token"] = owner["token"]
            notes.append("Owner-only checks are locked. " + owner["how"])
    findings = merge(findings)
    store.finish_scan(scan_id, findings, security_score(findings), a11y_score(findings))
    store.audit("link.scanned", {"link": info["url"], "kind": info["kind"], "findings": len(findings),
                                 "seconds": round(time.time() - t0, 1), **{k: v for k, v in meta.items() if k != "owner_token"}})
    return {
        "kind": info["kind"], "url": info["url"], "meta": meta, "notes": notes, "errors": errors,
        "findings": [f.to_dict() for f in findings],
        "security_score": security_score(findings), "a11y_score": a11y_score(findings),
        "seconds": round(time.time() - t0, 1),
    }


def check_a11y(workspace: str | Path, url: str) -> dict[str, Any]:
    """Run axe on any URL, typically the user's local dev server."""
    findings, meta = axe.check(url)
    store = Store(workspace, "links.db")
    store.audit("a11y.checked", {"url": url, "violations": len(findings)})
    return {"url": url, "findings": [f.to_dict() for f in merge(findings)], "a11y_score": a11y_score(findings), "meta": meta}
