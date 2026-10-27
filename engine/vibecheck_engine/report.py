"""Audit report export: findings, fixes and who accepted them, model versions, chain status and
AI cost for a date range. HTML for people, JSON/CSV for evidence systems."""
from __future__ import annotations

import csv
import html
import io
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .store import Store


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def build(workspace: str | Path, days: int = 30) -> dict[str, Any]:
    store = Store(workspace)
    since = time.time() - days * 86400
    entries = list(reversed(store.audit_entries(limit=10000, since=since)))
    chain = store.verify_audit()
    patches = [dict(r) for r in store.db.execute(
        "SELECT id, finding_id, model, trace_id, decision, created, latency_ms, tokens FROM patches WHERE created >= ? ORDER BY id",
        (since,))]
    scans = [s for s in store.last_scans(500) if (s["started"] or 0) >= since]
    cost: dict[str, Any] = {}
    try:
        from .observability import query
        q = query.traces(hours=days * 24)
        if q.get("available"):
            cost = q["cost"] | {"summary": q["summary"]}
    except Exception:
        pass
    return {
        "workspace": str(Path(workspace).resolve()), "generated": _when(time.time()), "days": days,
        "chain": chain, "entries": entries, "patches": patches, "scans": scans, "ai_cost": cost,
        "accepted": sum(p["decision"] == "accepted" for p in patches),
        "rejected": sum(p["decision"] == "rejected" for p in patches),
    }


def export(workspace: str | Path, fmt: str = "html", days: int = 30) -> tuple[str, str]:
    data = build(workspace, days)
    out_dir = Path(workspace) / ".vibecheck" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    if fmt == "json":
        path = out_dir / f"audit-{stamp}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    elif fmt == "csv":
        path = out_dir / f"audit-{stamp}.csv"
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["seq", "time", "actor", "action", "detail", "hash"])
        for e in data["entries"]:
            w.writerow([e["seq"], _when(e["ts"]), e["actor"], e["action"], json.dumps(e["detail"]), e["hash"]])
        path.write_text(buf.getvalue(), encoding="utf-8")
    else:
        path = out_dir / f"audit-{stamp}.html"
        path.write_text(_html(data), encoding="utf-8")
    Store(workspace).audit("report.exported", {"format": fmt, "days": days, "file": path.name})
    return str(path), fmt


def _html(d: dict) -> str:
    e = html.escape
    chain = d["chain"]
    rows = "".join(
        f"<tr><td>{x['seq']}</td><td>{_when(x['ts'])}</td><td>{e(x['actor'])}</td><td>{e(x['action'])}</td>"
        f"<td><code>{e(json.dumps(x['detail'])[:220])}</code></td><td><code>{x['hash'][:10]}…</code></td></tr>"
        for x in d["entries"]
    )
    cost = d["ai_cost"]
    cost_html = (
        f"<p>AI cost in this period: <b>${cost.get('total_usd', 0):.4f}</b> across {cost.get('summary', {}).get('requests', 0)} traced calls "
        f"(projected ${cost.get('projected_month_usd', 0):.2f}/month).</p>"
        if cost else "<p>AI cost: MLflow wasn't running, so no trace data is included.</p>"
    )
    status = "Chain verified ✓" if chain["ok"] else f"Chain BROKEN at entry {chain.get('broken_at')}"
    return f"""<!doctype html><meta charset="utf-8"><title>VibeCheck audit report</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 16px;color:#0e1a24}}
table{{border-collapse:collapse;width:100%;font-size:12px}}td,th{{border-bottom:1px solid #d5dee5;padding:6px;text-align:left;vertical-align:top}}
code{{font:11px ui-monospace,Consolas,monospace}}.ok{{color:#0a8f7e}}.bad{{color:#c2263a}}</style>
<h1>VibeCheck audit report</h1>
<p>{e(d['workspace'])} · last {d['days']} days · generated {d['generated']}</p>
<p class="{'ok' if chain['ok'] else 'bad'}"><b>{status}</b> · {chain['entries']} entries · last hash <code>{chain.get('last_hash', '')[:16]}</code></p>
<p>{len(d['scans'])} scans · {len(d['patches'])} patches generated · {d['accepted']} accepted · {d['rejected']} rejected</p>
{cost_html}
<table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th><th>Hash</th></tr>{rows}</table>"""
