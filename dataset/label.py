"""Scan every generated app with the VibeCheck engine and record findings.

One line per app in dataset/out/labels.jsonl:
    {"app_id", "app_dir", "n_findings", "by_category", "findings": [Finding dicts], "scan_seconds", "error"}
Resumable: apps already in labels.jsonl (without an error) are skipped.

    python dataset/label.py --workers 4
    python dataset/label.py --rescan-errors
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

from common import OUT, append_jsonl, log, read_jsonl, run_scan


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--apps", type=Path, default=None, help="apps dir (default <out>/apps)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--python", default=sys.executable, help="python that has the engine's deps")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--limit", type=int, default=0, help="only label the first N apps (by id)")
    ap.add_argument("--rescan-errors", action="store_true")
    a = ap.parse_args()

    apps_dir = a.apps or a.out / "apps"
    labels = a.out / "labels.jsonl"
    log_path = a.out / "label.log"
    lock = threading.Lock()

    done = {}
    for rec in read_jsonl(labels):
        if rec.get("error") and a.rescan_errors:
            continue
        done[rec["app_id"]] = rec
    # an app is finished once generate_apps wrote its spec
    specs_dir = a.out / "specs"
    apps = sorted(p for p in apps_dir.iterdir() if (specs_dir / f"{p.name}.json").exists()) if apps_dir.exists() else []
    if a.limit:
        apps = apps[:a.limit]
    todo = [p for p in apps if p.name not in done]
    log(f"label: {len(apps)} apps, {len(apps) - len(todo)} labeled, {len(todo)} to go", log_path)

    def work(app: Path) -> dict:
        t0 = time.time()
        rec = {"app_id": app.name, "app_dir": app.relative_to(a.out).as_posix() if app.is_relative_to(a.out) else str(app)}
        try:
            findings = run_scan(app, python=a.python, timeout=a.timeout)
            rec.update(n_findings=len(findings),
                       by_category=dict(Counter(f.get("category", "") for f in findings)),
                       findings=findings, error=None)
        except Exception as e:  # noqa: BLE001
            rec.update(n_findings=0, by_category={}, findings=[], error=str(e)[:500])
        rec["scan_seconds"] = round(time.time() - t0, 2)
        append_jsonl(labels, rec, lock)
        return rec

    totals: Counter = Counter()
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futs = [pool.submit(work, p) for p in todo]
        for i, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            totals.update(rec["by_category"])
            status = f"ERROR {rec['error'][:80]}" if rec["error"] else f"{rec['n_findings']} findings"
            log(f"[{i}/{len(todo)}] {rec['app_id']} {status} ({rec['scan_seconds']}s)", log_path)

    log(f"label finished. findings by category this run: {json.dumps(dict(totals))}", log_path)


if __name__ == "__main__":
    main()
