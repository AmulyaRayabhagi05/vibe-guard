"""Read traces back from the local MLflow server and shape them for the Traces and Cost views."""
from __future__ import annotations

import json
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..config import HOME, MLFLOW_URI
from . import guard
from .tracing import _server_up


def _attr(span, key: str, default=None):
    try:
        v = span.get_attribute(key)
    except Exception:
        v = (getattr(span, "attributes", None) or {}).get(key)
    return default if v is None else v


def _prices() -> dict[str, dict[str, float]]:
    """User price overrides for models MLflow can't price: ~/.vibecheck/prices.json
    {"model-name": {"input_per_1m": 0.8, "output_per_1m": 4.0}} (USD per million tokens)."""
    p = HOME / "prices.json"
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except (OSError, ValueError):
        return {}


def _override_cost(model: str, usage: dict) -> float | None:
    prices = _prices()
    price = prices.get(model) or next((v for k, v in prices.items() if model.startswith(k)), None)
    if not price:
        return None
    return (usage.get("input_tokens", 0) * price.get("input_per_1m", 0)
            + usage.get("output_tokens", 0) * price.get("output_per_1m", 0)) / 1_000_000


def _trace_row(t) -> dict[str, Any]:
    info = t.info
    spans = list(getattr(t.data, "spans", []) or [])
    root = next((s for s in spans if getattr(s, "parent_id", None) is None), spans[0] if spans else None)
    llm_spans = [s for s in spans if str(getattr(s, "span_type", "")).upper() in ("LLM", "CHAT_MODEL")] or spans
    model = provider = ""
    for s in llm_spans:
        model = model or _attr(s, "mlflow.llm.model", "") or _attr(s, "mlflow.chat.model", "")
        provider = provider or _attr(s, "mlflow.llm.provider", "") or _attr(s, "mlflow.message.format", "")
    usage = getattr(info, "token_usage", None) or {}
    cost = getattr(info, "cost", None)
    if cost is None:
        meta = getattr(info, "trace_metadata", None) or getattr(info, "request_metadata", None) or {}
        cost = meta.get("mlflow.trace.cost") or meta.get("mlflow.cost")
    if isinstance(cost, dict):
        cost = cost.get("total_cost") or cost.get("total")
    try:
        cost = float(cost) if cost is not None else None
    except (TypeError, ValueError):
        cost = None
    if cost is None and model:
        cost = _override_cost(model, usage)
    if cost is None and provider == "ollama":
        cost = 0.0  # local models are free
    state = str(getattr(info, "state", None) or getattr(info, "status", "")).split(".")[-1].upper()
    ts_ms = getattr(info, "request_time", None) or getattr(info, "timestamp_ms", 0)
    tags = getattr(info, "tags", None) or {}
    inputs = getattr(root, "inputs", None) if root else None
    outputs = getattr(root, "outputs", None) if root else None
    total = int(usage.get("total_tokens", 0) or 0)
    flags = guard.check(inputs, outputs, total)
    flags += [k.split(".", 2)[-1] for k, v in tags.items() if k.startswith("vibecheck.flag.") and v and k.split(".", 2)[-1] not in flags]
    return {
        "trace_id": getattr(info, "trace_id", None) or getattr(info, "request_id", ""),
        "time": int(ts_ms),
        "name": getattr(root, "name", "") if root else "",
        "endpoint": tags.get("vibecheck.endpoint") or tags.get("mlflow.traceName") or (getattr(root, "name", "") if root else ""),
        "model": model or "unknown",
        "provider": provider or "unknown",
        "latency_ms": int(getattr(info, "execution_duration", None) or getattr(info, "execution_time_ms", 0) or 0),
        "input_tokens": int(usage.get("input_tokens", 0) or 0),
        "output_tokens": int(usage.get("output_tokens", 0) or 0),
        "total_tokens": int(usage.get("total_tokens", 0) or 0),
        "cost_usd": cost,
        "status": "ERROR" if "ERROR" in state else "OK",
        "flags": flags,
        "input_preview": guard.redact(guard._text(inputs))[:600],
        "output_preview": guard.redact(guard._text(outputs))[:600],
        "spans": [
            {
                "name": s.name,
                "type": str(getattr(s, "span_type", "")),
                "start_ms": (getattr(s, "start_time_ns", 0) or 0) // 1_000_000,
                "end_ms": (getattr(s, "end_time_ns", 0) or 0) // 1_000_000,
                "parent": getattr(s, "parent_id", None),
            }
            for s in spans
        ],
    }


def traces(hours: int = 24, experiment: str | None = None, limit: int = 500) -> dict[str, Any]:
    if not _server_up():
        return {"available": False, "reason": f"MLflow isn't running at {MLFLOW_URI}. Run 'VibeCheck: Start AI tracing'."}
    import mlflow

    mlflow.set_tracking_uri(MLFLOW_URI)
    client = mlflow.MlflowClient()
    exps = client.search_experiments()
    ids = [e.experiment_id for e in exps if experiment is None or e.name == experiment]
    if not ids:
        return {"available": True, "rows": [], "summary": _summary([]), "cost": _cost([], hours)}
    since = int((time.time() - hours * 3600) * 1000)
    found = mlflow.search_traces(
        locations=ids, max_results=limit, return_type="list",
        filter_string=f"trace.timestamp_ms > {since}", order_by=["timestamp_ms DESC"],
    )
    rows = [_trace_row(t) for t in found]
    return {"available": True, "rows": rows, "summary": _summary(rows), "cost": _cost(rows, hours)}


def _pct(values: list[int], p: float) -> int:
    if not values:
        return 0
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p * (len(values) - 1))))]


def _summary(rows: list[dict]) -> dict[str, Any]:
    lat = [r["latency_ms"] for r in rows]
    toks = [r["total_tokens"] for r in rows if r["total_tokens"]]
    return {
        "requests": len(rows),
        "errors": sum(r["status"] == "ERROR" for r in rows),
        "error_rate": round(100 * sum(r["status"] == "ERROR" for r in rows) / len(rows), 1) if rows else 0.0,
        "p50_ms": _pct(lat, 0.5),
        "p95_ms": _pct(lat, 0.95),
        "tokens_per_trace": int(statistics.mean(toks)) if toks else 0,
        "total_tokens": sum(r["total_tokens"] for r in rows),
        "flagged": sum(bool(r["flags"]) for r in rows),
    }


def _cost(rows: list[dict], hours: int) -> dict[str, Any]:
    by_model: dict[str, float] = defaultdict(float)
    by_provider: dict[str, float] = defaultdict(float)
    by_endpoint: dict[str, float] = defaultdict(float)
    by_day: dict[str, float] = defaultdict(float)
    tokens_by_day: dict[str, int] = defaultdict(int)
    priced = 0
    for r in rows:
        day = datetime.fromtimestamp(r["time"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        tokens_by_day[day] += r["total_tokens"]
        c = r["cost_usd"]
        if c is None:
            continue
        priced += 1
        by_model[r["model"]] += c
        by_provider[r["provider"]] += c
        by_endpoint[r["endpoint"]] += c
        by_day[day] += c
    total = sum(by_model.values())
    days = max(1.0, hours / 24)
    return {
        "total_usd": round(total, 6),
        "avg_per_trace_usd": round(total / priced, 6) if priced else 0,
        "projected_month_usd": round(total / days * 30, 2),
        "priced_traces": priced,
        "unpriced_traces": len(rows) - priced,
        "by_model": dict(sorted(by_model.items(), key=lambda kv: -kv[1])),
        "by_provider": dict(sorted(by_provider.items(), key=lambda kv: -kv[1])),
        "by_endpoint": dict(sorted(by_endpoint.items(), key=lambda kv: -kv[1])),
        "by_day": dict(sorted(by_day.items())),
        "tokens_by_day": dict(sorted(tokens_by_day.items())),
    }
