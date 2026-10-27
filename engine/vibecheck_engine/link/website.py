"""Passive website checks: only what a normal browser visit downloads (the page, its own
scripts and the source maps they point to) plus response headers. Safe on any public URL."""
from __future__ import annotations

import json
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

from ..models import Finding
from ..scanners import opengrep, trufflehog

UA = "Mozilla/5.0 (compatible; VibeCheck/0.1; +https://github.com/vibecheck)"
MAX_SCRIPTS = 40
MAX_BYTES = 5_000_000


class _Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self.html_lang = None
        self.generator = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "html":
            self.html_lang = a.get("lang")
        elif tag == "meta" and (a.get("name") or "").lower() == "generator":
            self.generator = a.get("content") or ""


def _fetch(url: str, limit: int = MAX_BYTES) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            headers["_set_cookie"] = r.headers.get_all("Set-Cookie") or []
            return r.status, headers, r.read(limit)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise RuntimeError(f"Couldn't load {url}: {reason}") from e


def _web(rule: str, title: str, message: str, severity: str, url: str, snippet: str = "", **kw) -> Finding:
    return Finding(rule_id=rule, title=title, message=message, severity=severity, category=kw.pop("category", "web"),
                   path=url, source="web", snippet=snippet, fixable=False, **kw)


def _header_findings(url: str, headers: dict, set_cookies: list[str]) -> list[Finding]:
    out = []
    https = url.startswith("https://")
    if "content-security-policy" not in headers:
        out.append(_web("vc-web-no-csp", "No Content-Security-Policy header",
                        "Without a CSP, any injected script runs freely. Add a Content-Security-Policy header "
                        "(start with default-src 'self').", "medium", url, cwe="CWE-1021", owasp="A05:2021 Security Misconfiguration"))
    if https and "strict-transport-security" not in headers:
        out.append(_web("vc-web-no-hsts", "No HSTS header",
                        "Browsers may still try plain HTTP first. Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                        "low", url, cwe="CWE-319"))
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        out.append(_web("vc-web-clickjacking", "Page can be framed by other sites",
                        "Other sites can load this page in a hidden frame (clickjacking). Add "
                        "Content-Security-Policy: frame-ancestors 'self'.", "low", url, cwe="CWE-1021"))
    if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials") == "true":
        out.append(_web("vc-web-cors-wildcard", "CORS allows any site with credentials",
                        "Any website can make logged-in requests here. List your real origins.", "high", url, cwe="CWE-942"))
    if headers.get("x-powered-by"):
        out.append(_web("vc-web-powered-by", "Server reveals its framework",
                        f"X-Powered-By: {headers['x-powered-by']} tells attackers what to target. Remove the header.",
                        "low", url, snippet=headers["x-powered-by"], cwe="CWE-200"))
    for c in set_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [flag for flag, ok in (("Secure", "secure" in low or not https), ("HttpOnly", "httponly" in low),
                                        ("SameSite", "samesite" in low)) if not ok]
        if missing and re.search(r"(?i)sess|auth|token|sid|jwt", name):
            out.append(_web("vc-web-cookie-flags", f"Cookie {name} missing {', '.join(missing)}",
                            "Session cookies should be Secure, HttpOnly and SameSite so scripts and other sites can't use them.",
                            "medium", url, snippet=name, cwe="CWE-614"))
    return out


def _fingerprint(html: str, headers: dict, scripts: list[str], gen: str) -> list[str]:
    s = []
    blob = html[:200_000] + " ".join(scripts)
    for needle, label in [("/_next/", "Next.js"), ("__NUXT", "Nuxt"), ("/_app/immutable", "SvelteKit"), ("supabase.co", "Supabase"),
                          ("firebaseapp.com", "Firebase"), ("/assets/index-", "Vite"), ("wp-content", "WordPress")]:
        if needle in blob and label not in s:
            s.append(label)
    if "vercel" in headers.get("server", "").lower() or "x-vercel-id" in headers:
        s.append("Vercel")
    if "netlify" in headers.get("server", "").lower():
        s.append("Netlify")
    if gen:
        s.append(gen)
    return s


AI_ENDPOINT = re.compile(r"""["'`](/api/(?:chat|ai|completion|completions|generate|assistant|llm|ask|agent)[\w/-]*)["'`]""")


def scan_website(info: dict) -> tuple[list[Finding], list[str], dict]:
    url = info["url"]
    status, headers, body = _fetch(url)
    if status >= 400 or not body:
        raise RuntimeError(f"The site answered {status}. Check the address, or that it's publicly reachable.")
    html = body.decode("utf-8", errors="replace")
    set_cookies = headers.pop("_set_cookie", [])

    parser = _Assets()
    parser.feed(html)
    origin = urlparse(url).netloc
    # Only first-party scripts; third-party CDNs aren't the site owner's code.
    script_urls = [u for u in (urljoin(url, s) for s in parser.scripts) if urlparse(u).netloc == origin][:MAX_SCRIPTS]

    findings = _header_findings(url, headers, set_cookies)
    errors: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="vibecheck-site-"))
    maps_found = 0
    ai_endpoints: set[str] = set()
    try:
        (tmp / "index.html").write_text(html, encoding="utf-8")
        for i, su in enumerate(script_urls):
            st, _, js = _fetch(su)
            if st >= 400 or not js:
                continue
            text = js.decode("utf-8", errors="replace")
            name = f"bundle_{i}_{Path(urlparse(su).path).name or 'script.js'}"
            (tmp / "bundles" / name).parent.mkdir(exist_ok=True)
            (tmp / "bundles" / name).write_text(text, encoding="utf-8")
            ai_endpoints.update(AI_ENDPOINT.findall(text))
            m = re.search(r"//# sourceMappingURL=([^\s'\"]+\.map)\s*$", text[-500:], re.M)
            if m and not m.group(1).startswith("data:"):
                mst, _, raw = _fetch(urljoin(su, m.group(1)))
                if mst < 400 and raw:
                    maps_found += _unpack_sourcemap(raw, tmp / "sources" / f"map_{i}")
        if maps_found:
            findings.append(_web("vc-web-public-sourcemaps", "Original source code is public (source maps)",
                                 f"{maps_found} original source files can be rebuilt from public .map files. Anyone can read your "
                                 "code and comments. Disable production source maps (productionBrowserSourceMaps: false / build.sourcemap: false).",
                                 "medium", url, cwe="CWE-540"))
        # Secrets in what the browser downloads.
        secrets, e1 = trufflehog.scan_filesystem(tmp)
        for f in secrets:
            f.path = _origin_of(f.path, url, script_urls)
            f.fixable = False
            f.message = f.message.replace("written in the code", "shipped to every visitor's browser")
        # Full rule scan on any rebuilt original sources.
        code_findings, e2 = opengrep.scan(tmp / "sources") if maps_found else ([], [])
        for f in code_findings:
            f.extra["from_sourcemap"] = True
            f.fixable = False
        findings += secrets + code_findings
        errors += e1 + e2
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if parser.html_lang is None:
        findings.append(_web("vc-a11y-web-html-lang", "Page language not set", "Add lang=\"en\" (or your language) to <html>.",
                             "medium", url, category="a11y", wcag="3.1.1 Language of Page (A)"))
    meta = {
        "stack": _fingerprint(html, headers, script_urls, parser.generator),
        "scripts": len(script_urls), "source_maps": maps_found, "ai_endpoints": sorted(ai_endpoints)[:20],
        "status": status, "https": url.startswith("https://"),
    }
    return findings, errors, meta


def _unpack_sourcemap(raw: bytes, dest: Path) -> int:
    try:
        data = json.loads(raw)
    except ValueError:
        return 0
    n = 0
    for src, content in zip(data.get("sources", []), data.get("sourcesContent") or []):
        if not content or "node_modules" in src:
            continue
        clean = re.sub(r"^[a-z]+://", "", src).replace("..", "_").lstrip("/\\")
        p = dest / clean
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            n += 1
        except OSError:
            continue
    return n


def _origin_of(rel: str, page: str, scripts: list[str]) -> str:
    m = re.match(r"bundles/bundle_(\d+)_", rel)
    if m and int(m.group(1)) < len(scripts):
        return scripts[int(m.group(1))]
    return page
