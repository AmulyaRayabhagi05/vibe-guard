"""Helpers shared by the dataset scripts and training/evaluate.py (stdlib only).

- talks to a local Ollama server
- runs the engine CLI scan
- cuts REGION / CONTEXT out of a file and splices a fix back in
- validates a fix by re-scanning a temp copy of the app
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENGINE_DIR = REPO / "engine"
OUT = Path(__file__).resolve().parent / "out"

# The prompt format lives in the engine so training and inference never drift.
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
from vibecheck_engine.fixer.prompt import (  # noqa: E402
    LANG_FENCE,
    SYSTEM,
    build_messages,
    build_user_prompt,
    extract_code,
)

__all__ = [
    "LANG_FENCE", "SYSTEM", "build_messages", "build_user_prompt", "extract_code",
    "OUT", "REPO", "ENGINE_DIR",
]

# Region picking, splicing and parse checks also come from the engine when it is importable, so a
# training example cuts exactly the REGION the extension would send at inference time
# (engine/vibecheck_engine/context.py: tree-sitter statement/function/JSX unit, <=80 lines).
try:
    from vibecheck_engine import context as _ectx  # noqa: E402
except ImportError:  # engine layout changed: fall back to the heuristics below
    _ectx = None

DEFAULT_OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
if not DEFAULT_OLLAMA.startswith("http"):
    DEFAULT_OLLAMA = "http://" + DEFAULT_OLLAMA

REGION_PAD = 8
CONTEXT_PAD = 40
MAX_REGION_LINES = 60

EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "tsx", ".mjs": "javascript", ".cjs": "javascript",  # .jsx -> tsx like the engine
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".html": "html", ".htm": "html",
    ".vue": "vue", ".svelte": "svelte", ".astro": "astro",
    ".php": "php", ".rb": "ruby", ".go": "go", ".java": "java",
}


# ---------------------------------------------------------------- io

def read_jsonl(path: Path):
    path = Path(path)
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # a half-written last line after a crash


def append_jsonl(path: Path, rec: dict, lock=None) -> None:
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    if lock:
        with lock:
            with Path(path).open("a", encoding="utf-8") as f:
                f.write(line)
    else:
        with Path(path).open("a", encoding="utf-8") as f:
            f.write(line)


def log(msg: str, path: Path | None = None) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    if path:
        with Path(path).open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def split_for(app_id: str) -> str:
    """90/5/5 by app id. Hash-based so the split never changes as the dataset grows."""
    bucket = int(stable_hash("split", app_id)[:8], 16) % 100
    return "train" if bucket < 90 else ("val" if bucket < 95 else "test")


# ---------------------------------------------------------------- ollama

def ollama_chat(model: str, messages: list[dict], host: str = DEFAULT_OLLAMA,
                options: dict | None = None, timeout: float = 600, fmt: str | None = None,
                retries: int = 2) -> dict:
    """POST /api/chat (non-streaming). Returns {content, seconds, prompt_tokens, completion_tokens}."""
    body = {"model": model, "messages": messages, "stream": False, "keep_alive": "30m"}
    if options:
        body["options"] = options
    if fmt:
        body["format"] = fmt
    data = json.dumps(body).encode("utf-8")
    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(host.rstrip("/") + "/api/chat", data=data,
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out = json.loads(resp.read().decode("utf-8"))
            return {
                "content": out.get("message", {}).get("content", ""),
                "seconds": round(time.time() - t0, 3),
                "prompt_tokens": out.get("prompt_eval_count", 0),
                "completion_tokens": out.get("eval_count", 0),
            }
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"ollama {model} failed: {last_err}")


# ---------------------------------------------------------------- engine scan

def run_scan(target: Path, python: str = sys.executable, timeout: float = 600) -> list[dict]:
    """`python -m vibecheck_engine scan <dir> --json` -> list of Finding dicts."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ENGINE_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    # cwd is ENGINE_DIR, so a relative --python path must be resolved against the caller's cwd first.
    if os.sep in python or "/" in python:
        python = str(Path(python).resolve())
    proc = subprocess.run(
        [python, "-m", "vibecheck_engine", "scan", str(target), "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, env=env, cwd=str(ENGINE_DIR),
    )
    data = _parse_json_blob(proc.stdout)
    if data is None:
        raise RuntimeError(f"scan failed (rc={proc.returncode}): {proc.stderr.strip()[-500:]}")
    findings = data.get("findings", []) if isinstance(data, dict) else data
    for f in findings:
        f["path"] = (f.get("path") or "").replace("\\", "/")
    return findings


def _parse_json_blob(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # tolerate log lines before the JSON document
    start = text.find("{")
    while start != -1:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
    return None


def finding_tags(f: dict) -> str:
    # same format as engine/vibecheck_engine/fixer/fix.py:_tags
    wcag = f.get("wcag")
    return ", ".join(x for x in (f.get("cwe"), f.get("owasp"), f"WCAG {wcag}" if wcag else "") if x)


def finding_key(f: dict) -> tuple[str, str]:
    # Line numbers move when a fix is spliced in, so compare by rule + file.
    return (f.get("rule_id", ""), f.get("path", ""))


def language_for(path: str) -> str:
    """Matches fix.py: the engine's language (.jsx -> tsx) or the bare suffix (html, vue, ...)."""
    suffix = Path(path).suffix.lower()
    if _ectx is not None:
        return _ectx.language_for(path) or suffix.lstrip(".")
    return EXT_LANG.get(suffix, suffix.lstrip("."))


def _engine_parser_ok(language: str) -> bool:
    try:
        return _ectx is not None and _ectx._parser(language) is not None
    except Exception:  # noqa: BLE001 - tree-sitter or a grammar package is not installed
        return False


def fence(language: str, code: str) -> str:
    return f"```{LANG_FENCE.get(language, '')}\n{code.rstrip(chr(10))}\n```"


# ---------------------------------------------------------------- region / context

_PY_DEF = re.compile(r"^(\s*)(async\s+def|def|class)\s+\w+")
_JS_FUNC = re.compile(
    r"(\bfunction\b[\s\w$]*\(|=>\s*\{?\s*$|^\s*(export\s+)?(default\s+)?(async\s+)?function\b"
    r"|^\s*(async\s+)?[\w$]+\s*\([^)]*\)\s*\{\s*$|^\s*(app|router|server)\.\w+\(|^\s*export\s+(default\s+)?(async\s+)?function"
    r"|^\s*(export\s+)?(const|let|var)\s+[\w$]+\s*=\s*(async\s*)?\()"
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _py_enclosing(lines: list[str], s: int, e: int) -> tuple[int, int] | None:
    """0-based inclusive span of the innermost def/class containing lines s..e."""
    target_indent = _indent(lines[s]) if lines[s].strip() else 10**6
    for i in range(s, -1, -1):
        m = _PY_DEF.match(lines[i])
        if not m:
            continue
        ind = len(m.group(1))
        if i != s and ind >= target_indent:
            continue
        # decorators belong to the function
        top = i
        while top > 0 and lines[top - 1].lstrip().startswith("@"):
            top -= 1
        end = i
        for j in range(i + 1, len(lines)):
            if lines[j].strip() and _indent(lines[j]) <= ind:
                break
            end = j
        while end > i and not lines[end].strip():
            end -= 1
        if end >= e:
            return top, end
        target_indent = ind
    return None


def _brace_end(lines: list[str], start: int) -> int | None:
    depth, seen = 0, False
    for j in range(start, min(len(lines), start + 400)):
        # strings/comments make this approximate; good enough to pick a block
        for ch in lines[j]:
            if ch in "{(":
                depth += 1
                seen = True
            elif ch in "})":
                depth -= 1
        if seen and depth <= 0:
            return j
    return None


def _js_enclosing(lines: list[str], s: int, e: int) -> tuple[int, int] | None:
    for i in range(s, max(-1, s - 120), -1):
        if not _JS_FUNC.search(lines[i]):
            continue
        end = _brace_end(lines, i)
        if end is not None and end >= e:
            return i, end
    return None


def extract_region(text: str, start_line: int, end_line: int, language: str,
                   pad: int = REGION_PAD, ctx_pad: int = CONTEXT_PAD, max_lines: int = MAX_REGION_LINES):
    """Return (region, context, region_start, region_end) with 1-based inclusive line numbers.

    REGION is the enclosing function when it is small enough, else finding ±pad lines.
    CONTEXT is ±ctx_pad lines around the region (includes the region itself).
    With tree-sitter installed the engine's own region picker is used instead, to match inference."""
    if _engine_parser_ok(language):
        rs, re_ = _ectx.region_lines(text, language, start_line or 1, end_line or start_line or 1)
        return _ectx.slice_lines(text, rs, re_), _ectx.context_window(text, rs, re_, ctx_pad), rs, re_
    lines = text.split("\n")
    n = len(lines)
    s = max(0, min(n - 1, (start_line or 1) - 1))
    e = max(s, min(n - 1, (end_line or start_line or 1) - 1))
    span = None
    if language == "python":
        span = _py_enclosing(lines, s, e)
    elif language in ("javascript", "typescript", "tsx", "vue", "svelte", "astro"):
        span = _js_enclosing(lines, s, e)
    if span is None or span[1] - span[0] + 1 > max_lines:
        span = (max(0, s - pad), min(n - 1, e + pad))
    rs, re_ = span
    cs, ce = max(0, rs - ctx_pad), min(n - 1, re_ + ctx_pad)
    region = "\n".join(lines[rs:re_ + 1])
    context = "\n".join(lines[cs:ce + 1])
    return region, context, rs + 1, re_ + 1


def splice(text: str, region_start: int, region_end: int, new_region: str) -> str:
    if _ectx is not None:  # re-indents when the model dropped indentation, like the extension does
        return _ectx.replace_lines(text, region_start, region_end, new_region.rstrip("\n"))
    lines = text.split("\n")
    new = new_region.rstrip("\n").split("\n")
    return "\n".join(lines[:region_start - 1] + new + lines[region_end:])


def make_messages(finding: dict, language: str, region: str, context: str,
                  region_start: int, region_end: int) -> list[dict]:
    return build_messages(
        language=language,
        path=finding.get("path", ""),
        rule_id=finding.get("rule_id", ""),
        title=finding.get("title", ""),
        message=finding.get("message", ""),
        tags=finding_tags(finding),
        start_line=region_start,
        end_line=region_end,
        region=region,
        context=context,
    )


# ---------------------------------------------------------------- validation

def syntax_ok(path: Path, language: str) -> bool | None:
    """Cheap parse check. None = no checker available for this language."""
    try:
        src = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if _engine_parser_ok(language):
        return _ectx.parse_ok(src, language)
    if language == "python":
        try:
            compile(src, str(path), "exec")
            return True
        except SyntaxError:
            return False
    if language == "javascript" and path.suffix in (".js", ".mjs", ".cjs") and shutil.which("node"):
        try:
            r = subprocess.run(["node", "--check", str(path)], capture_output=True, timeout=30)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None


def compare_findings(before: list[dict], after: list[dict], target: dict) -> dict:
    b, a = Counter(map(finding_key, before)), Counter(map(finding_key, after))
    key = finding_key(target)
    new = [f"{k[0]}@{k[1]}" for k in a if a[k] > b.get(k, 0)]
    return {"target_gone": a.get(key, 0) < b.get(key, 0), "new_findings": new}


def validate_fix(app_dir: Path, finding: dict, new_file_text: str, baseline: list[dict],
                 python: str = sys.executable, tmp_root: Path | None = None,
                 timeout: float = 600) -> dict:
    """Copy the app, write the patched file, re-scan. passed = finding gone, nothing new, parses."""
    rel = finding["path"]
    language = language_for(rel)
    tmp = Path(tempfile.mkdtemp(prefix="vc-val-", dir=str(tmp_root) if tmp_root else None))
    try:
        work = tmp / "app"
        shutil.copytree(app_dir, work, ignore=shutil.ignore_patterns("_spec.json", "node_modules", ".git"))
        target = work / rel
        target.write_text(new_file_text, encoding="utf-8", newline="")
        parses = syntax_ok(target, language)
        try:
            after = run_scan(work, python=python, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - a crashing scan is a failed validation
            return {"passed": False, "error": str(e)[:300], "parses": parses,
                    "target_gone": False, "new_findings": []}
        cmp = compare_findings(baseline, after, finding)
        passed = cmp["target_gone"] and not cmp["new_findings"] and parses is not False
        return {"passed": passed, "parses": parses, **cmp}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- rejected-fix mutations

_COMMENT = {"python": "#", "ruby": "#"}


def mutate_wrong_fix(region: str, finding: dict, language: str, seed: str = "") -> tuple[str, str]:
    """A plausible-but-wrong 'fix' for DPO rejected. Returns (code, kind).

    Kinds: comment_only (claims a fix, changes nothing), drop_lines (removes the flagged
    lines, which kills the feature), half_fix (wraps the value in a no-op helper)."""
    lines = region.split("\n")
    c = _COMMENT.get(language, "//")
    if language in ("html", "vue", "svelte", "astro") and finding.get("category") == "a11y":
        c = None
    pick = int(stable_hash("mut", seed, finding.get("rule_id", ""))[:4], 16) % 3
    indent = re.match(r"\s*", lines[0]).group(0) if lines else ""
    note = {
        "secret": "moved to config",
        "a11y": "accessible",
        "ai": "prompt is sanitized",
    }.get(finding.get("category", ""), "input validated")
    snippet = (finding.get("snippet") or "").strip()

    if pick == 1 and snippet:
        flagged = [i for i, ln in enumerate(lines) if snippet.split("\n")[0].strip() in ln]
        if flagged and len(flagged) < len(lines):
            kept = [ln for i, ln in enumerate(lines) if i not in flagged]
            return "\n".join(kept), "drop_lines"
    if pick == 2 and finding.get("category") != "a11y":
        wrapped = re.sub(r"\b(req\.(body|query|params)\.\w+|request\.(args|form|json)\b[^\s,)]*)",
                         lambda m: f"String({m.group(0)})" if language != "python" else f"str({m.group(0)})",
                         region, count=1)
        if wrapped != region:
            return wrapped, "half_fix"
    if c is None:
        return f"<!-- fixed: {note} -->\n{region}", "comment_only"
    return f"{indent}{c} fixed: {note}\n{region}", "comment_only"
