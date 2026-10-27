"""Turn labeled findings into validated DPO pairs and SFT examples.

For every finding: cut REGION (enclosing function or +-8 lines) and CONTEXT (+-40 lines),
build the prompt with engine/vibecheck_engine/fixer/prompt.py, then
  chosen   = teacher model fix that passes validation (finding gone, no new findings, parses)
  rejected = base model fix that fails validation, else a plausible-but-wrong mutation.

Stage 1 appends every attempt to out/pairs_raw.jsonl (resumable).
Stage 2 (always run at the end, or alone with --split-only) writes
  out/pairs/dpo_{train,val,test}.jsonl  {"prompt": [system, user], "chosen": "```lang..```", "rejected": "...", "meta": {...}}
  out/pairs/sft_{train,val,test}.jsonl  {"messages": [system, user, assistant], "meta": {...}}
split 90/5/5 by app id (hash-based, see common.split_for).

    python dataset/build_pairs.py --teacher qwen2.5-coder:32b --base deepseek-coder:6.7b-instruct
    python dataset/build_pairs.py --split-only --extra dataset/out/real_world_pairs.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import (
    DEFAULT_OLLAMA, OUT, append_jsonl, extract_code, extract_region, fence, language_for, log,
    make_messages, mutate_wrong_fix, ollama_chat, read_jsonl, splice, split_for, stable_hash,
    validate_fix,
)

SUPPORTED = {"python", "javascript", "typescript", "tsx", "html", "vue", "svelte", "astro"}
SKIP_CATEGORIES = {"dependency", "web"}  # lockfile bumps and live-site checks are not code edits


def load_labels(path: Path) -> dict[str, dict]:
    labels = {}
    for rec in read_jsonl(path):
        labels[rec["app_id"]] = rec  # last record wins (rescans append)
    return {k: v for k, v in labels.items() if not v.get("error")}


def candidate_findings(rec: dict, out_dir: Path, max_per_app: int) -> list[dict]:
    app_dir = out_dir / rec["app_dir"] if not Path(rec["app_dir"]).is_absolute() else Path(rec["app_dir"])
    seen, picked = set(), []
    # most severe first, so the per-app cap keeps the interesting ones
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(rec["findings"], key=lambda f: order.get(f.get("severity"), 5)):
        if f.get("category") in SKIP_CATEGORIES or f.get("fixable") is False:
            continue
        if not f.get("path") or not f.get("start_line"):
            continue
        if language_for(f["path"]) not in SUPPORTED or not (app_dir / f["path"]).is_file():
            continue
        dedupe = (f["rule_id"], f["path"], f["start_line"])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        picked.append(f)
        if len(picked) >= max_per_app:
            break
    return picked


def ask_fix(model: str, messages: list[dict], host: str, temperature: float, timeout: float) -> tuple[str | None, dict]:
    r = ollama_chat(model, messages, host=host, timeout=timeout,
                    options={"temperature": temperature, "num_ctx": 8192, "num_predict": 2048})
    return extract_code(r["content"]), r


def process(rec: dict, f: dict, a, out_dir: Path) -> dict:
    app_dir = out_dir / rec["app_dir"]
    path = f["path"]
    lang = language_for(path)
    text = (app_dir / path).read_text(encoding="utf-8", errors="replace")
    region, context, rs, re_ = extract_region(text, f["start_line"], f.get("end_line") or f["start_line"], lang)
    messages = make_messages(f, lang, region, context, rs, re_)
    key = stable_hash(rec["app_id"], f.get("id") or f["rule_id"], path, str(rs))[:20]
    meta = {
        "key": key, "app_id": rec["app_id"], "app_dir": rec["app_dir"], "source": "synthetic",
        "path": path, "language": lang, "rule_id": f["rule_id"], "category": f.get("category"),
        "severity": f.get("severity"), "cwe": f.get("cwe", ""), "owasp": f.get("owasp", ""),
        "wcag": f.get("wcag", ""), "finding_id": f.get("id", ""), "start_line": f["start_line"],
        "end_line": f.get("end_line") or f["start_line"], "region_start": rs, "region_end": re_,
        "validatable": True, "teacher_model": a.teacher, "split": split_for(rec["app_id"]),
    }
    baseline = rec["findings"]

    def check(code: str) -> dict:
        return validate_fix(app_dir, f, splice(text, rs, re_, code), baseline,
                            python=a.python, timeout=a.scan_timeout)

    # chosen: teacher, a couple of tries at rising temperature
    chosen, verdict, tries = None, {}, 0
    for t in range(a.teacher_tries):
        tries = t + 1
        code, _ = ask_fix(a.teacher, messages, a.host, 0.2 + 0.3 * t, a.timeout)
        if code is None or code.strip() == region.strip():
            verdict = {"passed": False, "error": "no code" if code is None else "unchanged"}
            continue
        verdict = check(code)
        if verdict["passed"]:
            chosen = code
            break
    meta.update(teacher_tries=tries, chosen_validation=verdict)
    if chosen is None:
        return {"key": key, "status": "teacher_failed", "meta": meta}

    # rejected: base model output that fails validation, else a heuristic mutation
    rejected, rej_src = None, None
    if a.rejected in ("base", "auto"):
        code, _ = ask_fix(a.base, messages, a.host, 0.7, a.timeout)
        if code is not None and code.strip() and code.strip() != chosen.strip():
            v = {"passed": False, "error": "unchanged"} if code.strip() == region.strip() else check(code)
            meta["base_validation"] = v
            if not v["passed"]:
                rejected, rej_src = code, f"base:{a.base}"
        elif code is None:
            meta["base_validation"] = {"passed": False, "error": "no code"}
    if rejected is None and a.rejected in ("mutation", "auto"):
        rejected, kind = mutate_wrong_fix(region, f, lang, seed=key)
        rej_src = f"mutation:{kind}"
    if rejected is None:
        return {"key": key, "status": "no_rejected", "meta": meta}

    meta["rejected_source"] = rej_src
    return {
        "key": key, "status": "ok",
        "prompt": messages,
        "chosen": fence(lang, chosen),
        "rejected": fence(lang, rejected),
        "meta": meta,
    }


def write_splits(raw_path: Path, extras: list[Path], pairs_dir: Path) -> dict:
    pairs_dir.mkdir(parents=True, exist_ok=True)
    recs = {}
    for r in read_jsonl(raw_path):
        if r.get("status") == "ok":
            recs[r["key"]] = r
    for p in extras:
        for r in read_jsonl(p):
            k = r.get("meta", {}).get("key") or stable_hash(json.dumps(r["prompt"]))[:20]
            recs[k] = r
    files = {}
    for split in ("train", "val", "test"):
        files[("dpo", split)] = (pairs_dir / f"dpo_{split}.jsonl").open("w", encoding="utf-8")
        files[("sft", split)] = (pairs_dir / f"sft_{split}.jsonl").open("w", encoding="utf-8")
    stats: Counter = Counter()
    try:
        for r in recs.values():
            meta = r.get("meta", {})
            split = split_for(meta.get("app_id") or meta.get("key", ""))
            meta["split"] = split
            dpo = {"prompt": r["prompt"], "chosen": r["chosen"], "rejected": r["rejected"], "meta": meta}
            sft = {"messages": r["prompt"] + [{"role": "assistant", "content": r["chosen"]}], "meta": meta}
            files[("dpo", split)].write(json.dumps(dpo, ensure_ascii=False) + "\n")
            files[("sft", split)].write(json.dumps(sft, ensure_ascii=False) + "\n")
            stats[f"{split}"] += 1
            stats[f"source:{meta.get('source', '?')}"] += 1
            stats[f"category:{meta.get('category', '?')}"] += 1
            stats[f"rejected:{(meta.get('rejected_source') or '?').split(':')[0]}"] += 1
    finally:
        for fh in files.values():
            fh.close()
    summary = dict(sorted(stats.items()))
    (pairs_dir / "stats.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--teacher", default="qwen2.5-coder:32b", help="strong local model for chosen fixes")
    ap.add_argument("--base", default="deepseek-coder:6.7b-instruct", help="base model for rejected fixes")
    ap.add_argument("--rejected", choices=["auto", "base", "mutation"], default="auto")
    ap.add_argument("--host", default=DEFAULT_OLLAMA)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--teacher-tries", type=int, default=2)
    ap.add_argument("--max-per-app", type=int, default=5)
    ap.add_argument("--limit-apps", type=int, default=0)
    ap.add_argument("--python", default=sys.executable, help="python for the engine scan")
    ap.add_argument("--timeout", type=float, default=600, help="per Ollama call")
    ap.add_argument("--scan-timeout", type=float, default=600)
    ap.add_argument("--extra", type=Path, action="append", default=[],
                    help="extra pair jsonl to merge into the splits (e.g. real_world_pairs.jsonl)")
    ap.add_argument("--split-only", action="store_true")
    a = ap.parse_args()

    raw_path = a.out / "pairs_raw.jsonl"
    log_path = a.out / "build_pairs.log"
    if not a.split_only:
        labels = load_labels(a.out / "labels.jsonl")
        app_ids = sorted(labels)[: a.limit_apps or None]
        done = {r["key"] for r in read_jsonl(raw_path)}
        jobs = []
        for app_id in app_ids:
            rec = labels[app_id]
            for f in candidate_findings(rec, a.out, a.max_per_app):
                jobs.append((rec, f))
        log(f"build_pairs: {len(app_ids)} apps, {len(jobs)} findings, {len(done)} attempts already logged", log_path)

        lock = threading.Lock()
        status: Counter = Counter()
        t0 = time.time()

        def work(rec, f):
            try:
                out = process(rec, f, a, a.out)
            except Exception as e:  # noqa: BLE001
                return {"status": "error", "error": str(e)[:300], "app_id": rec["app_id"], "rule_id": f.get("rule_id")}
            if out["key"] in done:
                return {"status": "skipped"}
            append_jsonl(raw_path, out, lock)
            return out

        # cheap pre-filter so resumed runs don't re-ask the models
        def pending(rec, f):
            lang = language_for(f["path"])
            try:
                text = (a.out / rec["app_dir"] / f["path"]).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return False
            _, _, rs, _ = extract_region(text, f["start_line"], f.get("end_line") or f["start_line"], lang)
            return stable_hash(rec["app_id"], f.get("id") or f["rule_id"], f["path"], str(rs))[:20] not in done

        jobs = [j for j in jobs if pending(*j)]
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futs = [pool.submit(work, rec, f) for rec, f in jobs]
            for i, fut in enumerate(as_completed(futs), 1):
                out = fut.result()
                status[out["status"]] += 1
                if out["status"] == "error":
                    log(f"error {out['app_id']} {out['rule_id']}: {out['error']}", log_path)
                if i % 10 == 0 or i == len(jobs):
                    rate = i / max(1e-9, time.time() - t0)
                    log(f"[{i}/{len(jobs)}] {dict(status)} | eta {(len(jobs) - i) / rate / 3600:.1f}h", log_path)

    summary = write_splits(raw_path, a.extra, a.out / "pairs")
    log(f"splits written to {a.out / 'pairs'}: {json.dumps(summary)}", log_path)


if __name__ == "__main__":
    main()
