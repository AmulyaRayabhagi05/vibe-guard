"""Evaluate fix models served by Ollama on the held-out test split.

For each test pair: send the stored prompt, take the fenced REGION from the reply, splice it into
a temp copy of the app and re-run the engine scan.
  fix_rate         validator passed (finding gone, no new findings, file still parses)
  regression_rate  the patch introduced new findings or broke parsing
  format_fail      no fenced code block in the reply
  latency / tokens average and p95 seconds, prompt and completion tokens
Pairs without an app on disk (diff-only real-world pairs) are scored only by similarity to the
reference fix.

    python training/evaluate.py --models deepseek-coder:6.7b-instruct,vibecheck-coder
    MLFLOW_TRACKING_URI=http://127.0.0.1:5000 python training/evaluate.py --models vibecheck-coder --limit 300
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dataset"))
from common import (  # noqa: E402
    DEFAULT_OLLAMA, OUT, extract_code, ollama_chat, read_jsonl, run_scan, splice, validate_fix,
)


class Baselines:
    """Findings of the unpatched app: from labels.jsonl when present, else a fresh scan (cached)."""

    def __init__(self, out: Path, python: str):
        self.python = python
        self.cache: dict[str, list[dict]] = {}
        self.lock = threading.Lock()
        for rec in read_jsonl(out / "labels.jsonl"):
            if not rec.get("error"):
                self.cache[rec["app_dir"]] = rec["findings"]

    def get(self, app_dir_rel: str, app_dir: Path) -> list[dict]:
        with self.lock:
            if app_dir_rel in self.cache:
                return self.cache[app_dir_rel]
        found = run_scan(app_dir, python=self.python)
        with self.lock:
            self.cache[app_dir_rel] = found
        return found


def _strip_fence(s: str) -> str:
    return extract_code(s) or s


def eval_one(rec: dict, model: str, a, baselines: Baselines) -> dict:
    meta = rec["meta"]
    res = {"key": meta.get("key"), "app_id": meta.get("app_id"), "rule_id": meta.get("rule_id"),
           "category": meta.get("category"), "source": meta.get("source")}
    try:
        r = ollama_chat(model, rec["prompt"], host=a.host, timeout=a.timeout,
                        options={"temperature": a.temperature, "num_ctx": 8192, "num_predict": 1024})
    except RuntimeError as e:
        return {**res, "error": str(e)[:200]}
    res.update(seconds=r["seconds"], prompt_tokens=r["prompt_tokens"], completion_tokens=r["completion_tokens"])
    code = extract_code(r["content"])
    res["format_ok"] = code is not None
    if code is None:
        res.update(passed=False, regression=False)
        return res
    res["similarity"] = round(difflib.SequenceMatcher(None, code, _strip_fence(rec["chosen"])).ratio(), 4)

    app_rel = meta.get("app_dir")
    app_dir = (a.out / app_rel) if app_rel else None
    if not (meta.get("validatable") and app_dir and (app_dir / meta["path"]).is_file()):
        res["validated"] = False
        return res
    text = (app_dir / meta["path"]).read_text(encoding="utf-8", errors="replace")
    baseline = baselines.get(app_rel, app_dir)
    target = next((f for f in baseline if f.get("rule_id") == meta["rule_id"] and f.get("path") == meta["path"]),
                  {"rule_id": meta["rule_id"], "path": meta["path"]})
    v = validate_fix(app_dir, target, splice(text, meta["region_start"], meta["region_end"], code),
                     baseline, python=a.python, timeout=a.scan_timeout)
    res.update(validated=True, passed=v["passed"], target_gone=v.get("target_gone"),
               new_findings=v.get("new_findings", []), parses=v.get("parses"),
               regression=bool(v.get("new_findings")) or v.get("parses") is False)
    return res


def summarize(results: list[dict]) -> dict:
    ok = [r for r in results if "error" not in r]
    val = [r for r in ok if r.get("validated")]
    secs = sorted(r["seconds"] for r in ok if "seconds" in r)

    def rate(xs, key):
        return round(sum(bool(x.get(key)) for x in xs) / len(xs), 4) if xs else 0.0

    s = {
        "n": len(results), "n_errors": len(results) - len(ok), "n_validated": len(val),
        "fix_rate": rate(val, "passed"),
        "regression_rate": rate(val, "regression"),
        "format_fail_rate": round(1 - rate(ok, "format_ok"), 4) if ok else 0.0,
        "avg_similarity": round(statistics.mean([r["similarity"] for r in ok if "similarity" in r]), 4)
        if any("similarity" in r for r in ok) else 0.0,
        "avg_seconds": round(statistics.mean(secs), 3) if secs else 0.0,
        "p95_seconds": round(secs[min(len(secs) - 1, int(0.95 * len(secs)))], 3) if secs else 0.0,
        "avg_prompt_tokens": round(statistics.mean([r["prompt_tokens"] for r in ok]), 1) if ok else 0.0,
        "avg_completion_tokens": round(statistics.mean([r["completion_tokens"] for r in ok]), 1) if ok else 0.0,
    }
    for cat in sorted({r.get("category") or "?" for r in val}):
        sub = [r for r in val if (r.get("category") or "?") == cat]
        s[f"fix_rate_{cat}"] = rate(sub, "passed")
    return s


def log_mlflow(model: str, a, summary: dict, files: list[Path]) -> None:
    try:
        import mlflow
    except ImportError:
        print("mlflow not installed; skipping MLflow logging")
        return
    mlflow.set_experiment(os.environ.get("MLFLOW_EXPERIMENT_NAME", "vibecheck-eval"))
    with mlflow.start_run(run_name=f"eval-{model}"):
        mlflow.log_params({"model": model, "data": str(a.data), "limit": a.limit,
                           "temperature": a.temperature, "host": a.host})
        mlflow.log_metrics({k: float(v) for k, v in summary.items() if isinstance(v, (int, float))})
        for f in files:
            mlflow.log_artifact(str(f))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=OUT / "pairs" / "dpo_test.jsonl")
    ap.add_argument("--out", type=Path, default=OUT, help="dataset out dir (apps, labels.jsonl)")
    ap.add_argument("--models", default="vibecheck-coder", help="comma list of Ollama model names")
    ap.add_argument("--host", default=DEFAULT_OLLAMA)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--temperature", type=float, default=0.1)
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--scan-timeout", type=float, default=600)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--results", type=Path, default=OUT / "eval")
    ap.add_argument("--mlflow", action="store_true", help="log to MLflow (default: on if MLFLOW_TRACKING_URI is set)")
    a = ap.parse_args()

    recs = list(read_jsonl(a.data))
    if a.limit:
        recs = recs[: a.limit]
    if not recs:
        sys.exit(f"no records in {a.data}")
    baselines = Baselines(a.out, a.python)
    use_mlflow = a.mlflow or bool(os.environ.get("MLFLOW_TRACKING_URI"))

    table = {}
    for model in [m.strip() for m in a.models.split(",") if m.strip()]:
        out_dir = a.results / re.sub(r"[^\w.-]+", "_", model)
        out_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict] = []
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futs = [pool.submit(eval_one, r, model, a, baselines) for r in recs]
            for i, fut in enumerate(as_completed(futs), 1):
                results.append(fut.result())
                if i % 25 == 0 or i == len(recs):
                    print(f"{model}: {i}/{len(recs)} ({time.time() - t0:.0f}s)", flush=True)
        res_path = out_dir / "results.jsonl"
        res_path.write_text("".join(json.dumps(r) + "\n" for r in results), encoding="utf-8")
        summary = summarize(results)
        sum_path = out_dir / "summary.json"
        sum_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        table[model] = summary
        if use_mlflow:
            log_mlflow(model, a, summary, [res_path, sum_path])

    cols = ["n_validated", "fix_rate", "regression_rate", "format_fail_rate", "avg_similarity",
            "avg_seconds", "p95_seconds", "avg_completion_tokens"]
    print("\nmodel".ljust(34) + "".join(c[:14].rjust(15) for c in cols))
    for model, s in table.items():
        print(model[:33].ljust(33) + "".join(str(s.get(c, "")).rjust(15) for c in cols))


if __name__ == "__main__":
    main()
