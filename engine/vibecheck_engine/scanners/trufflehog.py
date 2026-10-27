"""Run TruffleHog for hardcoded secrets. Verification is off by default: checking a key would
send it to the provider's API, and VibeCheck never sends anything off the machine unasked."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from .. import tools
from ..config import IGNORE_DIRS
from ..models import Finding


def _mask(secret: str) -> str:
    s = secret.strip()
    return s[:4] + "…" + s[-2:] if len(s) > 8 else "…"


def env_name(detector: str) -> str:
    """OpenAI -> OPENAI_API_KEY, used by the quick fix and in messages."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", detector).upper().strip("_")
    return base if base.endswith(("KEY", "TOKEN", "SECRET", "URL")) else f"{base}_API_KEY"


def _finding(r: dict, path: str, line: int, extra: dict) -> Finding:
    detector = r.get("DetectorName", "Secret")
    raw = r.get("Raw", "") or ""
    verified = bool(r.get("Verified"))
    return Finding(
        rule_id=f"vc-secret-{detector.lower()}",
        title=f"Hardcoded {detector} secret",
        message=(
            f"A {detector} credential ({_mask(raw)}) is written in the code. Anyone with the repo or the "
            f"built app can use it. Move it to an environment variable ({env_name(detector)}) and rotate "
            f"the key, because it may already be exposed."
            + (" TruffleHog confirmed it is live." if verified else "")
        ),
        severity="critical",
        category="secret",
        path=path,
        start_line=line,
        end_line=line,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        source="trufflehog",
        # Only a hash-like stub of the secret is stored, never the value itself.
        snippet=f"{detector}:{_mask(raw)}",
        extra={"detector": detector, "verified": verified, "env_name": env_name(detector), **extra},
    )


def _run(args: list[str], timeout: int) -> tuple[list[dict], list[str]]:
    exe = tools.find("trufflehog")
    if not exe:
        return [], ["TruffleHog is not installed. Run 'VibeCheck: Set up' to download it."]
    proc = subprocess.run([str(exe), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    errs = [] if proc.returncode in (0, 183) else [proc.stderr.strip()[-400:]]
    return rows, errs


def scan_filesystem(target: str | Path, timeout: int = 600) -> tuple[list[Finding], list[str]]:
    root = Path(target).resolve()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as ex:
        ex.write("\n".join(rf"(^|[\\/]){re.escape(d)}([\\/]|$)" for d in IGNORE_DIRS))
        exclude = ex.name
    try:
        rows, errs = _run(
            ["filesystem", str(root), "--json", "--no-verification", "--no-update", f"--exclude-paths={exclude}"],
            timeout,
        )
    finally:
        Path(exclude).unlink(missing_ok=True)
    out = []
    for r in rows:
        fs = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        p = Path(fs.get("file", ""))
        if not p.is_absolute():
            p = root / p
        try:
            rel = p.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = p.as_posix()
        out.append(_finding(r, rel, int(fs.get("line") or 0), {}))
    return _dedupe(out), errs


def scan_git(repo: str, timeout: int = 900) -> tuple[list[Finding], list[str]]:
    """Scan full git history (a URL or a local path). Finds keys that were 'deleted' in later commits."""
    target = repo if "://" in repo else Path(repo).resolve().as_uri()
    rows, errs = _run(["git", target, "--json", "--no-verification", "--no-update"], timeout)
    out = []
    for r in rows:
        g = r.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        f = _finding(r, g.get("file", ""), int(g.get("line") or 0), {"commit": g.get("commit", "")[:12], "history": True})
        f.title += " (in git history)"
        f.rule_id += "-history"
        f.fixable = False  # history needs a key rotation, not a code edit
        f.id = f.fingerprint() + g.get("commit", "")[:4]
        out.append(f)
    return _dedupe(out), errs


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            out.append(f)
    return out
