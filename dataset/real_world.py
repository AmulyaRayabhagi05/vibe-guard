"""Real-world vuln -> fix pairs (Python / JavaScript / TypeScript) in the same pair format.

All sources are free and optional; a source that is missing or offline is skipped with a warning.

  hf-cvefixes   CVEfixes commits mirrored on the Hugging Face hub (dataset: hitoshura25/cvefixes,
                https://huggingface.co/datasets/hitoshura25/cvefixes). Fetched over the free
                datasets-server JSON API, stdlib only. Uses /filter by language; if that endpoint is
                down it pages /rows and filters locally (slow: ~13k rows, use --max-rows).
                Set HF_TOKEN to raise rate limits (optional).
  cvefixes-db   The official CVEfixes SQLite database (Bhandari et al., PROMISE '21):
                https://doi.org/10.5281/zenodo.4476563 (latest version on Zenodo), code at
                https://github.com/secureIT-project/CVEfixes. Download + unzip, pass --cvefixes-db.
  crossvul      CrossVul (Nikitopoulos et al., FSE '21): https://doi.org/10.5281/zenodo.4734050.
                Unzip and pass --crossvul-dir (expects CWE-*/<ext>/bad_* and good_* file pairs).
  cybernative   CyberNative/Code_Vulnerability_Security_DPO on the HF hub (synthetic secure vs
                insecure programs): https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO

Each changed hunk becomes REGION (vulnerable side) -> chosen (fixed side). The "finding" is a
pseudo-finding built from the CWE (rule_id "cwe-79" etc.) unless --scan finds a real engine rule
on the vulnerable file whose fix the upstream patch also resolves; those get validatable=true.
Rejected = a plausible-but-wrong mutation (or --rejected base to ask the base model).

    python dataset/real_world.py --sources hf-cvefixes,cybernative --max-pairs 5000
    python dataset/real_world.py --sources cvefixes-db --cvefixes-db CVEfixes.db --scan
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from common import (
    DEFAULT_OLLAMA, OUT, extract_code, fence, language_for, log, make_messages, mutate_wrong_fix,
    ollama_chat, run_scan, splice, stable_hash, validate_fix,
)

DS_SERVER = "https://datasets-server.huggingface.co"
LANGS = {"python", "javascript", "typescript", "tsx"}
MAX_REGION = 60
CONTEXT_PAD = 40

CWE_INFO = {
    "20": ("Improper input validation", "Input is used without checking its type, range or format."),
    "22": ("Path traversal", "A user-controlled path can escape the intended directory."),
    "78": ("OS command injection", "User input reaches a shell command."),
    "79": ("Cross-site scripting (XSS)", "User input is written into HTML without escaping."),
    "89": ("SQL injection", "User input is concatenated into a SQL query."),
    "94": ("Code injection", "User input reaches eval/exec or a code generator."),
    "200": ("Sensitive data exposure", "Sensitive information is returned or logged."),
    "287": ("Broken authentication", "The endpoint does not properly authenticate the caller."),
    "352": ("Cross-site request forgery", "A state-changing request has no CSRF protection."),
    "400": ("Uncontrolled resource consumption", "Input can make the server do unbounded work."),
    "434": ("Unrestricted file upload", "Uploaded files are not checked for type, name or size."),
    "502": ("Unsafe deserialization", "Untrusted data is deserialized with an unsafe loader."),
    "601": ("Open redirect", "A user-controlled URL is used as a redirect target."),
    "611": ("XML external entities", "The XML parser resolves external entities."),
    "770": ("No limits on allocation", "Resources are allocated without a limit."),
    "798": ("Hard-coded credentials", "A credential is embedded in source code."),
    "862": ("Missing authorization", "The action does not check the caller's permissions."),
    "863": ("Incorrect authorization", "The permission check can be bypassed."),
    "918": ("Server-side request forgery", "The server fetches a user-controlled URL."),
    "1321": ("Prototype pollution", "User input can set properties on Object.prototype."),
    "1333": ("Inefficient regular expression (ReDoS)", "A regex can backtrack catastrophically."),
}

_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|docs?|examples?)(/|$)|\.(min|test|spec)\.\w+$|_test\.py$", re.I)


# ---------------------------------------------------------------- http (HF datasets-server)

def _get_json(url: str, cache: Path | None, timeout: float = 60, retries: int = 3):
    if cache and cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    headers = {"User-Agent": "vibecheck-dataset/0.1"}
    if os.environ.get("HF_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['HF_TOKEN']}"
    err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8"))
            if isinstance(data, dict) and "error" in data and "rows" not in data:
                raise RuntimeError(data["error"])
            if cache:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(data), encoding="utf-8")
            return data
        except (urllib.error.URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as e:
            err = e
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"{url[:120]}: {err}")


def hf_rows(dataset: str, cache_dir: Path, where: str | None = None, max_rows: int = 0,
            page: int = 100, split: str = "train", config: str = "default"):
    """Yield row dicts. Uses /filter when `where` is given and falls back to /rows."""
    tag = re.sub(r"\W+", "_", dataset)
    q = {"dataset": dataset, "config": config, "split": split}
    offset, n = 0, 0
    use_filter = bool(where)
    while True:
        params = dict(q, offset=offset, length=page)
        if use_filter:
            params["where"] = where
        endpoint = "filter" if use_filter else "rows"
        url = f"{DS_SERVER}/{endpoint}?{urllib.parse.urlencode(params)}"
        cache = cache_dir / f"{tag}_{endpoint}_{stable_hash(where or '')[:8]}_{offset}.json"
        try:
            data = _get_json(url, cache)
        except RuntimeError as e:
            if use_filter:
                log(f"  /filter unavailable ({str(e)[:100]}); paging /rows and filtering locally")
                use_filter, offset = False, 0
                continue
            raise
        rows = data.get("rows", [])
        if not rows:
            return
        for r in rows:
            yield r["row"]
            n += 1
            if max_rows and n >= max_rows:
                return
        offset += len(rows)
        if offset >= data.get("num_rows_total", 0):
            return


# ---------------------------------------------------------------- hunks

def hunks_from_files(before: str, after: str, ctx: int = 2):
    """Yield (old_start_1based, old_lines, new_lines) for each changed block, with ctx lines around."""
    a, b = before.split("\n"), after.split("\n")
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for group in sm.get_grouped_opcodes(ctx):
        i1, i2 = group[0][1], group[-1][2]
        j1, j2 = group[0][3], group[-1][4]
        yield i1 + 1, a[i1:i2], b[j1:j2]


_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def hunks_from_unified_diff(diff: str):
    """Yield (path, old_start, old_lines, new_lines) per hunk of a git diff."""
    path, old, new, start = None, [], [], 0
    in_hunk = False

    def flush():
        if path and in_hunk and (old or new):
            return (path, start, list(old), list(new))
        return None

    for line in diff.split("\n"):
        if line.startswith("diff --git "):
            if (h := flush()):
                yield h
            path, old, new, in_hunk = None, [], [], False
            m = re.search(r" b/(.+)$", line)
            path = m.group(1) if m else None
        elif not in_hunk and (line.startswith("+++ ") or line.startswith("--- ")):
            if line.startswith("+++ b/"):
                path = line[6:].strip()
        elif (m := _HUNK.match(line)):
            if (h := flush()):
                yield h
            old, new, start, in_hunk = [], [], int(m.group(1)), True
        elif in_hunk:
            if line.startswith("-"):
                old.append(line[1:])
            elif line.startswith("+"):
                new.append(line[1:])
            elif line.startswith("\\"):
                continue
            else:
                old.append(line[1:] if line.startswith(" ") else line)
                new.append(line[1:] if line.startswith(" ") else line)
    if (h := flush()):
        yield h


def _trim_trailing_blank(old: list[str], new: list[str]):
    while old and new and not old[-1].strip() and not new[-1].strip():
        old, new = old[:-1], new[:-1]
    return old, new


def meaningful(old: list[str], new: list[str]) -> bool:
    if not old or len(old) > MAX_REGION or len(new) > MAX_REGION + 20:
        return False
    sm = difflib.SequenceMatcher(None, [x.strip() for x in old], [x.strip() for x in new])
    changed = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            changed += old[i1:i2] + new[j1:j2]
    code = [c for c in changed if c.strip() and not re.match(r"\s*(#|//|/\*|\*|<!--)", c)]
    if not code:
        return False
    if all(re.search(r"version|__version__|copyright", c, re.I) for c in code):
        return False
    return True


# ---------------------------------------------------------------- pair building

def pseudo_finding(cwe: str, path: str, start: int, end: int, title: str = "", desc: str = "") -> dict:
    num = re.sub(r"\D", "", cwe or "") or "0"
    t, msg = CWE_INFO.get(num, (title or "Security weakness", desc or "Fix the security weakness in this code."))
    return {"rule_id": f"cwe-{num}" if num != "0" else "security-fix", "title": t, "message": msg,
            "severity": "high", "category": "app", "path": path, "start_line": start, "end_line": end,
            "cwe": f"CWE-{num}" if num != "0" else "", "owasp": "", "wcag": "", "snippet": ""}


def build_pair(*, source: str, group_id: str, path: str, cwe: str, old: list[str], new: list[str],
               old_start: int, file_before: str | None, a, extra_meta: dict) -> dict | None:
    lang = language_for(path)
    if lang not in LANGS or _TEST_PATH.search(path):
        return None
    old, new = _trim_trailing_blank(old, new)
    while old and new and not old[0].strip() and not new[0].strip():
        old, new, old_start = old[1:], new[1:], old_start + 1
    if not meaningful(old, new):
        return None
    region = "\n".join(old)
    chosen = "\n".join(new)
    rs, re_ = old_start, old_start + len(old) - 1
    if file_before is not None:
        lines = file_before.split("\n")
        context = "\n".join(lines[max(0, rs - 1 - CONTEXT_PAD): min(len(lines), re_ + CONTEXT_PAD)])
    else:
        context = region  # diff-only sources have no surrounding file
    key = stable_hash(source, group_id, path, str(rs))[:20]
    finding = pseudo_finding(cwe, path, rs, re_, extra_meta.get("cwe_name", ""))
    validatable, app_dir = False, None

    if a.scan and file_before is not None:
        found = scan_for_rule(key, path, file_before, rs, re_, chosen, a)
        if found:
            finding, app_dir = found
            validatable = True

    messages = make_messages(finding, lang, region, context, rs, re_)
    rejected, rej_src = None, None
    if a.rejected == "base":
        try:
            r = ollama_chat(a.base, messages, host=a.host, options={"temperature": 0.7, "num_predict": 2048})
            code = extract_code(r["content"])
            if code and code.strip() not in (chosen.strip(), ""):
                rejected, rej_src = code, f"base:{a.base}"
        except RuntimeError as e:
            log(f"  base model unavailable: {e}")
    if rejected is None:
        rejected, kind = mutate_wrong_fix(region, finding, lang, seed=key)
        rej_src = f"mutation:{kind}"
    if rejected.strip() == chosen.strip():
        return None

    meta = {
        "key": key, "app_id": f"{source}-{stable_hash(group_id)[:12]}", "app_dir": app_dir, "source": source,
        "path": path, "language": lang, "rule_id": finding["rule_id"], "category": finding["category"],
        "severity": finding["severity"], "cwe": finding.get("cwe", ""), "owasp": finding.get("owasp", ""),
        "wcag": "", "start_line": finding["start_line"], "end_line": finding["end_line"],
        "region_start": rs, "region_end": re_, "validatable": validatable, "rejected_source": rej_src,
        **extra_meta,
    }
    return {"prompt": messages, "chosen": fence(lang, chosen), "rejected": fence(lang, rejected), "meta": meta}


def scan_for_rule(key: str, path: str, file_before: str, rs: int, re_: int, chosen: str, a):
    """Write the vulnerable file into out/real_world/apps/<key>/ and look for an engine finding
    inside the region that the upstream fix resolves."""
    app_dir = a.out / "real_world" / "apps" / key
    target = app_dir / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(file_before, encoding="utf-8", newline="")
    try:
        findings = run_scan(app_dir, python=a.python)
    except Exception as e:  # noqa: BLE001
        log(f"  scan failed for {key}: {str(e)[:100]}")
        return None
    fixed_text = splice(file_before, rs, re_, chosen)
    for f in findings:
        if f["path"] != path or not (rs <= f.get("start_line", 0) <= re_):
            continue
        v = validate_fix(app_dir, f, fixed_text, findings, python=a.python)
        if v["passed"]:
            return f, app_dir.relative_to(a.out).as_posix()
    return None


# ---------------------------------------------------------------- sources

def src_hf_cvefixes(a):
    where = "\"language\" IN ('Python','JavaScript','TypeScript')"
    for row in hf_rows("hitoshura25/cvefixes", a.cache, where=where, max_rows=a.max_rows):
        if row.get("language") not in ("Python", "JavaScript", "TypeScript"):
            continue
        group = row.get("repo_url") or row.get("hash", "")
        per_commit = 0
        for path, start, old, new in hunks_from_unified_diff(row.get("diff_with_context") or ""):
            p = build_pair(source="cvefixes", group_id=group, path=path, cwe=row.get("cwe_id", ""),
                           old=old, new=new, old_start=start, file_before=None, a=a,
                           extra_meta={"cve_id": row.get("cve_id"), "repo": row.get("repo_url"),
                                       "commit": row.get("hash"), "cwe_name": row.get("cwe_name", "")})
            if p:
                yield p
                per_commit += 1
                if per_commit >= a.max_hunks:
                    break


def src_cvefixes_db(a):
    if not a.cvefixes_db or not Path(a.cvefixes_db).exists():
        raise FileNotFoundError("--cvefixes-db not given or missing (download from https://doi.org/10.5281/zenodo.4476563)")
    con = sqlite3.connect(f"file:{a.cvefixes_db}?mode=ro", uri=True)
    q = """
        SELECT fc.file_change_id, fc.filename, fc.old_path, fc.code_before, fc.code_after,
               fc.programming_language, f.repo_url, f.hash, f.cve_id,
               (SELECT group_concat(cwe_id) FROM cwe_classification c WHERE c.cve_id = f.cve_id) AS cwes
        FROM file_change fc JOIN fixes f ON f.hash = fc.hash
        WHERE fc.programming_language IN ('Python', 'JavaScript', 'TypeScript')
          AND fc.code_before IS NOT NULL AND fc.code_after IS NOT NULL
    """
    for (fcid, filename, old_path, before, after, _lang, repo, commit, cve, cwes) in con.execute(q):
        path = (old_path or filename or "").replace("\\", "/")
        if before in (None, "None") or after in (None, "None"):
            continue
        per_file = 0
        for start, old, new in hunks_from_files(before, after):
            p = build_pair(source="cvefixes", group_id=repo or commit, path=path,
                           cwe=(cwes or "").split(",")[0], old=old, new=new, old_start=start,
                           file_before=before, a=a, extra_meta={"cve_id": cve, "repo": repo, "commit": commit})
            if p:
                yield p
                per_file += 1
                if per_file >= a.max_hunks:
                    break


def src_crossvul(a):
    root = Path(a.crossvul_dir or "")
    if not a.crossvul_dir or not root.exists():
        raise FileNotFoundError("--crossvul-dir not given or missing (download from https://doi.org/10.5281/zenodo.4734050)")
    ext_ok = {"py": ".py", "js": ".js", "ts": ".ts", "jsx": ".jsx", "tsx": ".tsx"}
    for bad in sorted(root.rglob("bad_*")):
        ext = bad.parent.name.lower()
        if ext not in ext_ok:
            continue
        good = bad.with_name("good_" + bad.name[4:])
        if not good.exists():
            continue
        cwe = next((p.name for p in bad.parents if p.name.upper().startswith("CWE-")), "")
        before = bad.read_text(encoding="utf-8", errors="replace")
        after = good.read_text(encoding="utf-8", errors="replace")
        path = f"src/{bad.name}{ext_ok[ext]}"
        per_file = 0
        for start, old, new in hunks_from_files(before, after):
            p = build_pair(source="crossvul", group_id=bad.name.split("_")[1] if "_" in bad.name else bad.name,
                           path=path, cwe=cwe, old=old, new=new, old_start=start, file_before=before, a=a,
                           extra_meta={"crossvul_file": bad.relative_to(root).as_posix()})
            if p:
                yield p
                per_file += 1
                if per_file >= a.max_hunks:
                    break


_FENCED = re.compile(r"```[\w+-]*\n(.*?)```", re.S)


def src_cybernative(a):
    ext = {"python": ".py", "javascript": ".js", "typescript": ".ts"}
    for row in hf_rows("CyberNative/Code_Vulnerability_Security_DPO", a.cache, max_rows=a.max_rows):
        lang = (row.get("lang") or "").lower()
        if lang not in ext:
            continue
        bad = _FENCED.search(row.get("rejected") or "")
        good = _FENCED.search(row.get("chosen") or "")
        if not bad or not good:
            continue
        before, after = bad.group(1).rstrip("\n"), good.group(1).rstrip("\n")
        gid = stable_hash(row.get("question", ""))[:16]
        if len(before.split("\n")) <= MAX_REGION:
            hunks = [(1, before.split("\n"), after.split("\n"))]  # small programs: whole file is the region
        else:
            hunks = list(hunks_from_files(before, after))[: a.max_hunks]
        for start, old, new in hunks:
            p = build_pair(source="cybernative", group_id=gid, path=f"app{ext[lang]}", cwe="", old=old,
                           new=new, old_start=start, file_before=before, a=a,
                           extra_meta={"vulnerability": row.get("vulnerability", "")})
            if p:
                p["prompt"] = make_messages(
                    {**pseudo_finding("", p["meta"]["path"], p["meta"]["start_line"], p["meta"]["end_line"]),
                     "title": "Security weakness", "message": row.get("vulnerability") or "Fix the security weakness."},
                    lang, "\n".join(old), before, p["meta"]["region_start"], p["meta"]["region_end"])
                yield p


SOURCES = {"hf-cvefixes": src_hf_cvefixes, "cvefixes-db": src_cvefixes_db,
           "crossvul": src_crossvul, "cybernative": src_cybernative}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", default="hf-cvefixes,cybernative", help=f"comma list of {sorted(SOURCES)}")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--output", type=Path, default=None, help="default <out>/real_world_pairs.jsonl")
    ap.add_argument("--cvefixes-db", default=None)
    ap.add_argument("--crossvul-dir", default=None)
    ap.add_argument("--max-pairs", type=int, default=5000, help="cap per source")
    ap.add_argument("--max-rows", type=int, default=0, help="cap rows fetched from HF per source (0 = all)")
    ap.add_argument("--max-hunks", type=int, default=3, help="per commit / file")
    ap.add_argument("--scan", action="store_true", help="look for a real engine rule on the vulnerable file")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--rejected", choices=["mutation", "base"], default="mutation")
    ap.add_argument("--base", default="deepseek-coder:6.7b-instruct")
    ap.add_argument("--host", default=DEFAULT_OLLAMA)
    a = ap.parse_args()
    a.cache = a.out / "real_world" / "cache"
    output = a.output or a.out / "real_world_pairs.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    if output.exists():
        for line in output.read_text(encoding="utf-8").splitlines():
            try:
                seen.add(json.loads(line)["meta"]["key"])
            except (json.JSONDecodeError, KeyError):
                pass
    log(f"real_world: {len(seen)} pairs already in {output}")

    with output.open("a", encoding="utf-8") as fh:
        for name in [s.strip() for s in a.sources.split(",") if s.strip()]:
            fn = SOURCES.get(name)
            if not fn:
                log(f"unknown source {name}, skipping")
                continue
            n = 0
            try:
                for pair in fn(a):
                    if pair["meta"]["key"] in seen:
                        continue
                    seen.add(pair["meta"]["key"])
                    fh.write(json.dumps(pair, ensure_ascii=False) + "\n")
                    fh.flush()
                    n += 1
                    if n % 100 == 0:
                        log(f"  {name}: {n} pairs")
                    if n >= a.max_pairs:
                        break
            except Exception as e:  # noqa: BLE001 - one broken source must not stop the others
                log(f"source {name} stopped: {str(e)[:200]}")
            log(f"{name}: {n} new pairs")


if __name__ == "__main__":
    main()
