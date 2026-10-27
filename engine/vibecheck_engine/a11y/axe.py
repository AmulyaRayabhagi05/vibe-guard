"""WCAG checks on a rendered page with axe-core (MPL-2.0) in headless Chromium (Playwright).
Works on live sites and on a local dev server (http://localhost:3000). Catches what static
rules can't: colour contrast, focus order, ARIA misuse, missing names after rendering."""
from __future__ import annotations

import hashlib
import re
import urllib.request

from ..config import BIN_DIR
from ..models import Finding

AXE_VERSION = "4.10.2"
AXE_URL = f"https://cdnjs.cloudflare.com/ajax/libs/axe-core/{AXE_VERSION}/axe.min.js"
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]
IMPACT = {"critical": "high", "serious": "high", "moderate": "medium", "minor": "low"}
LEVEL = {"wcag2a": "A", "wcag21a": "A", "wcag2aa": "AA", "wcag21aa": "AA", "wcag22aa": "AA"}


def _axe_source() -> str:
    path = BIN_DIR / f"axe-{AXE_VERSION}.min.js"
    if not path.exists():
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(AXE_URL, headers={"User-Agent": "vibecheck"})
        with urllib.request.urlopen(req, timeout=60) as r:
            path.write_bytes(r.read())
    return path.read_text(encoding="utf-8")


def _wcag(tags: list[str]) -> str:
    crit = [t for t in tags if re.fullmatch(r"wcag\d{3,4}", t)]
    level = next((LEVEL[t] for t in tags if t in LEVEL), "")
    if not crit:
        return "best practice"
    d = crit[0][4:]
    sc = f"{d[0]}.{d[1]}.{d[2:]}"
    return f"{sc} ({level})" if level else sc


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def check(url: str, timeout_ms: int = 45000) -> tuple[list[Finding], dict]:
    if not available():
        raise RuntimeError(
            "Live accessibility checks need Playwright (free): pip install \"vibecheck-engine[a11y]\" "
            "then: python -m playwright install chromium"
        )
    from playwright.sync_api import sync_playwright

    axe_js = _axe_source()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            page.add_script_tag(content=axe_js)
            result = page.evaluate("(tags) => axe.run(document, { runOnly: { type: 'tag', values: tags } })", TAGS)
            # Reflow at 320 CSS px (WCAG 1.4.10): flag horizontal scrolling.
            page.set_viewport_size({"width": 320, "height": 800})
            overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
        finally:
            browser.close()

    findings = []
    for v in result.get("violations", []):
        nodes = v.get("nodes", [])
        first = nodes[0] if nodes else {}
        findings.append(Finding(
            rule_id=f"vc-axe-{v['id']}",
            title=v.get("help", v["id"]),
            message=f"{v.get('description', '')} {len(nodes)} element(s) affected. "
                    + (first.get("failureSummary", "").replace("\n", " ")[:400]),
            severity=IMPACT.get(v.get("impact") or "", "medium"),
            category="a11y", path=url, source="axe", wcag=_wcag(v.get("tags", [])),
            snippet=(first.get("html") or "")[:500], fixable=False,
            extra={"help_url": v.get("helpUrl"), "targets": [n.get("target") for n in nodes[:10]], "count": len(nodes)},
        ))
    if overflow:
        findings.append(Finding(
            rule_id="vc-axe-reflow", title="Page scrolls sideways at 320px wide",
            message="At 320 CSS pixels (400% zoom) the page needs horizontal scrolling, which is hard for people who zoom. "
                    "Let content wrap and avoid fixed widths.",
            severity="medium", category="a11y", path=url, source="axe", wcag="1.4.10 Reflow (AA)", fixable=False,
            snippet=hashlib.sha1(url.encode()).hexdigest()[:8],
        ))
    meta = {"passes": len(result.get("passes", [])), "incomplete": len(result.get("incomplete", [])),
            "violations": len(result.get("violations", [])), "axe": AXE_VERSION}
    return findings, meta
