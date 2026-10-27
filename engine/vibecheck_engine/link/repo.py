"""Scan a remote repo: shallow clone into a throwaway folder, scan code + full git history.
Nothing in the repo is ever executed."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .. import tools
from ..models import Finding
from ..scanners import opengrep, trufflehog


def _clone(info: dict, dest: Path) -> None:
    cmd = ["git", "clone", "--depth", "1", "--quiet", "--no-tags"]
    if info.get("ref"):
        cmd += ["--branch", info["ref"]]
    # Never run repo hooks or fetch LFS blobs we don't need.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    proc = subprocess.run(cmd + ["-c", "core.hooksPath=/dev/null", info["clone_url"], str(dest)],
                          capture_output=True, text=True, env=env, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(
            "Couldn't clone that repo. If it's private, sign in with git first (a free GitHub token works). "
            + proc.stderr.strip()[-300:]
        )


def _stack(root: Path) -> list[str]:
    found = []
    pj = root / "package.json"
    if pj.exists():
        try:
            deps = {**json.loads(pj.read_text(encoding="utf-8")).get("dependencies", {})}
        except ValueError:
            deps = {}
        for dep, label in [("next", "Next.js"), ("react", "React"), ("express", "Express"), ("@supabase/supabase-js", "Supabase"),
                           ("firebase", "Firebase"), ("openai", "OpenAI"), ("@anthropic-ai/sdk", "Anthropic"), ("ai", "Vercel AI SDK"),
                           ("svelte", "Svelte"), ("vue", "Vue"), ("prisma", "Prisma"), ("mongoose", "MongoDB")]:
            if dep in deps:
                found.append(label)
    req = " ".join((root / n).read_text(encoding="utf-8", errors="ignore").lower()
                   for n in ("requirements.txt", "pyproject.toml") if (root / n).exists())
    for dep, label in [("fastapi", "FastAPI"), ("flask", "Flask"), ("django", "Django"), ("openai", "OpenAI"),
                       ("anthropic", "Anthropic"), ("langchain", "LangChain")]:
        if dep in req and label not in found:
            found.append(label)
    return found


def _osv(root: Path) -> list[Finding]:
    exe = tools.find("osv-scanner")
    if not exe:
        return []
    proc = subprocess.run([str(exe), "scan", "source", "--format", "json", "-r", str(root)],
                          capture_output=True, text=True, timeout=600)
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return []
    out = []
    for res in data.get("results", []):
        src = Path(res.get("source", {}).get("path", "")).name
        for pkg in res.get("packages", []):
            name = pkg.get("package", {}).get("name", "?")
            ver = pkg.get("package", {}).get("version", "?")
            for v in pkg.get("vulnerabilities", []):
                out.append(Finding(
                    rule_id=f"vc-dep-{v.get('id', 'vuln').lower()}", title=f"Vulnerable dependency {name}@{ver}",
                    message=(v.get("summary") or v.get("details", "")[:300]) + f" Upgrade {name}.",
                    severity="high", category="dependency", path=src, source="osv",
                    snippet=f"{name}@{ver} {v.get('id')}", fixable=False,
                ))
    return out


def scan_repo(info: dict) -> tuple[list[Finding], list[str], dict]:
    tmp = Path(tempfile.mkdtemp(prefix="vibecheck-repo-"))
    try:
        _clone(info, tmp / "src")
        root = tmp / "src"
        files = sum(1 for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)
        findings, errors = opengrep.scan(root)
        secrets, e2 = trufflehog.scan_filesystem(root)
        # History: scan the remote URL so commits beyond the shallow clone are included.
        history, e3 = trufflehog.scan_git(info["clone_url"])
        findings += secrets + history + _osv(root)
        for f in findings:
            f.fixable = False  # fixes apply to a local checkout, not to someone's remote repo
            f.extra["repo"] = f"{info['owner']}/{info['repo']}"
        meta = {"files": files, "stack": _stack(root), "repo": f"{info['owner']}/{info['repo']}"}
        return findings, errors + e2 + e3, meta
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
