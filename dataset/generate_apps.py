"""Generate vibe-coded multi-file apps with a local Ollama model.

Each spec from prompts.py becomes dataset/out/apps/<app_id>/ with the files the model wrote.
The spec + generation metadata go to dataset/out/specs/<app_id>.json, written last, so its
presence means the app is finished (kept outside the app so the scanner never sees the prompt).
Re-running skips finished apps, so it is safe to stop and resume.

    python dataset/generate_apps.py --limit 2000 --model qwen2.5-coder:14b --workers 2
    python dataset/generate_apps.py --limit 20000 --models qwen2.5-coder:14b,deepseek-coder-v2:16b,llama3.1:8b
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath

from common import DEFAULT_OLLAMA, OUT, append_jsonl, log, ollama_chat
from prompts import sample_specs

GEN_SYSTEM = (
    "You are a fast full-stack developer helping a non-expert ship an app. Write a complete, "
    "small but working project (3-12 files): source files, package.json or requirements.txt, "
    "and any HTML/templates. Skip lock files, binary assets and long READMEs.\n"
    "Output format, strictly: for every file, one line `### FILE: <relative/path>` followed by "
    "one fenced code block with the full file content. No other prose."
)

MAX_FILES = 40
MAX_FILE_BYTES = 200_000
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}

# Keys the model invents can look real. Replace anything key-shaped that is not one of our
# fakes, keeping the prefix so secret scanners still see a secret-shaped string.
_KEYLIKE = re.compile(
    r"\b(sk-(?:proj-|ant-|or-)?|sk_live_|sk_test_|rk_live_|ghp_|gho_|github_pat_|xox[bpas]-|AKIA|AIza|gsk_|hf_)"
    r"([A-Za-z0-9_\-]{12,})"
)


def scrub_secrets(text: str) -> str:
    def repl(m: re.Match) -> str:
        if "VIBECHECK" in m.group(0).upper():
            return m.group(0)
        # same length and charset class as the original so secret rules still match the shape
        body = m.group(2)
        filler = ("VIBECHECKFAKE" + hashlib.sha256(body.encode()).hexdigest() * 2)[: len(body)]
        return m.group(1) + filler
    return _KEYLIKE.sub(repl, text)


# ---------------------------------------------------------------- parsing

_HEADER = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\*\*)?(?:FILE|File|file|Filename|filename|Path|path)\s*[:=]\s*`?([^\s`*]+)`?(?:\*\*)?\s*$"
)
_LOOSE_HEADER = re.compile(r"^\s*(?:#{1,6}\s+|\*\*|`)+\s*`?([\w.\-/\[\]()@+]+\.[A-Za-z0-9]{1,6})`?\s*(?:\*\*|`)?\s*:?\s*$")
_FENCE_OPEN = re.compile(r"^\s*(`{3,}|~{3,})\s*([^\s`]*)\s*(.*)$")
_INLINE_NAME = re.compile(r"(?:title|file|filename)\s*=\s*[\"']?([^\"'\s]+)")
_FIRST_LINE_NAME = re.compile(r"^\s*(?://|#|<!--|/\*)\s*(?:file(?:name)?\s*:\s*)?([\w.\-/\[\]()@+]+\.[A-Za-z0-9]{1,6})\s*(?:-->|\*/)?\s*$", re.I)


def _clean_path(p: str) -> str | None:
    p = p.strip().strip("`'\"*:").replace("\\", "/")
    if not p or p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    parts = [x for x in PurePosixPath(p).parts if x not in (".", "")]
    if not parts or any(x == ".." for x in parts) or "node_modules" in parts:
        return None
    if parts[-1] in SKIP_NAMES:
        return None
    if "." not in parts[-1] and parts[-1] not in ("Dockerfile", "Procfile", "Makefile", ".env", ".env.local"):
        return None
    return "/".join(parts)


def _try_json(text: str) -> dict[str, str] | None:
    t = text.strip()
    m = re.match(r"^```(?:json)?\s*\n(.*)\n```\s*$", t, re.S)
    if m:
        t = m.group(1)
    if not t.startswith("{"):
        return None
    try:
        data = json.loads(t, strict=False)  # models often leave raw newlines in strings
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and isinstance(data.get("files"), (dict, list)):
        data = data["files"]
    if isinstance(data, list):
        data = {d.get("path"): d.get("content") for d in data if isinstance(d, dict)}
    if not isinstance(data, dict):
        return None
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def parse_files(reply: str) -> dict[str, str]:
    """Accepts `### FILE: path` + fence, ```lang path, ```lang title="path", a path comment on
    the first line of the block, or a JSON object {path: content}."""
    js = _try_json(reply)
    if js:
        return {p: c for k, c in js.items() if (p := _clean_path(k))}

    files: dict[str, str] = {}
    lines = reply.split("\n")
    pending: str | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _FENCE_OPEN.match(line)
        if m:
            ticks, info, rest = m.group(1), m.group(2), m.group(3)
            body: list[str] = []
            j = i + 1
            # a closing fence is a bare run of the same char, at least as long as the opener
            while j < len(lines):
                t = lines[j].strip()
                if t and set(t) == {ticks[0]} and len(t) >= len(ticks):
                    break
                body.append(lines[j])
                j += 1
            name = pending
            if not name:
                inline = _INLINE_NAME.search(rest or "")
                if ":" in info:  # ```tsx:app/page.tsx
                    name = info.split(":", 1)[1]
                elif inline:  # ```js title="server.js"
                    name = inline.group(1)
                elif rest and " " not in rest.strip() and ("." in rest or "/" in rest):  # ```js server.js
                    name = rest.strip()
                elif "." in info or "/" in info:  # ```server.js
                    name = info
                elif body and (t := _FIRST_LINE_NAME.match(body[0])):  # // server.js
                    name = t.group(1)
            path = _clean_path(name) if name else None
            if path:
                content = "\n".join(body).rstrip("\n") + "\n"
                files[path] = content
            pending = None
            i = j + 1
            continue
        h = _HEADER.match(line) or _LOOSE_HEADER.match(line)
        if h:
            pending = h.group(1)
        i += 1
    return files


# ---------------------------------------------------------------- generation

def write_app(app_dir: Path, spec_path: Path, files: dict[str, str], spec: dict, meta: dict) -> None:
    app_dir.mkdir(parents=True, exist_ok=True)
    for rel, content in list(files.items())[:MAX_FILES]:
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            continue
        target = app_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(scrub_secrets(content), encoding="utf-8", newline="\n")
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(json.dumps({**spec, **meta}, indent=2), encoding="utf-8")


def generate_one(spec: dict, model: str, host: str, temperature: float, num_ctx: int,
                 num_predict: int, timeout: float) -> tuple[dict[str, str], dict]:
    messages = [{"role": "system", "content": GEN_SYSTEM}, {"role": "user", "content": spec["prompt"]}]
    opts = {"temperature": temperature, "num_ctx": num_ctx, "num_predict": num_predict,
            "seed": spec["index"]}
    r = ollama_chat(model, messages, host=host, options=opts, timeout=timeout)
    files = parse_files(r["content"])
    meta = {"gen_model": model, "gen_seconds": r["seconds"], "gen_tokens": r["completion_tokens"],
            "n_files": len(files), "files": sorted(files)}
    return files, {**meta, "_raw": r["content"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=2000, help="number of specs (2000 pilot, 20000 full)")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--model", default="qwen2.5-coder:14b")
    ap.add_argument("--models", default="", help="comma list; spec i uses models[i %% n] for variety")
    ap.add_argument("--host", default=DEFAULT_OLLAMA)
    ap.add_argument("--workers", type=int, default=2, help="match OLLAMA_NUM_PARALLEL")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--num-predict", type=int, default=6144)
    ap.add_argument("--timeout", type=float, default=1200)
    ap.add_argument("--min-files", type=int, default=2, help="retry once if fewer files parsed")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--keep-raw", action="store_true", help="save raw replies to <out>/raw/<app_id>.md")
    a = ap.parse_args()

    models = [m.strip() for m in a.models.split(",") if m.strip()] or [a.model]
    apps_dir = a.out / "apps"
    apps_dir.mkdir(parents=True, exist_ok=True)
    log_path = a.out / "generate.log"
    err_path = a.out / "generate_errors.jsonl"
    lock = threading.Lock()

    specs = sample_specs(a.limit, a.seed, start=a.start)
    specs_dir = a.out / "specs"
    todo = [s for s in specs if not (specs_dir / f"{s['app_id']}.json").exists()]
    log(f"generate: {len(specs)} specs, {len(specs) - len(todo)} already done, {len(todo)} to go, "
        f"models={models}", log_path)

    done = failed = 0
    t0 = time.time()

    def work(spec: dict) -> tuple[str, bool, str]:
        model = models[spec["index"] % len(models)]
        files, meta = {}, {}
        for attempt in range(2):
            try:
                files, meta = generate_one(spec, model, a.host, a.temperature + 0.1 * attempt,
                                           a.num_ctx, a.num_predict, a.timeout)
            except Exception as e:  # noqa: BLE001
                append_jsonl(err_path, {"app_id": spec["app_id"], "model": model, "error": str(e)[:500]}, lock)
                return spec["app_id"], False, str(e)[:120]
            if len(files) >= a.min_files:
                break
        if len(files) < a.min_files:
            append_jsonl(err_path, {"app_id": spec["app_id"], "model": model,
                                    "error": f"parsed {len(files)} files", "raw": meta.get("_raw", "")[:2000]}, lock)
            return spec["app_id"], False, f"parsed {len(files)} files"
        raw = meta.pop("_raw", "")
        if a.keep_raw:
            (a.out / "raw").mkdir(parents=True, exist_ok=True)
            (a.out / "raw" / f"{spec['app_id']}.md").write_text(raw, encoding="utf-8")
        write_app(apps_dir / spec["app_id"], specs_dir / f"{spec['app_id']}.json", files, spec, meta)
        return spec["app_id"], True, f"{len(files)} files, {meta['gen_seconds']:.0f}s"

    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futs = [pool.submit(work, s) for s in todo]
        for fut in as_completed(futs):
            app_id, ok, info = fut.result()
            done += ok
            failed += not ok
            n = done + failed
            rate = n / max(1e-9, time.time() - t0)
            eta = (len(todo) - n) / rate if rate else 0
            log(f"[{n}/{len(todo)}] {app_id} {'ok' if ok else 'FAIL'} {info} | eta {eta / 3600:.1f}h", log_path)

    log(f"generate finished: {done} ok, {failed} failed", log_path)


if __name__ == "__main__":
    main()
