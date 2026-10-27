"""JSON-RPC over stdio for the VS Code extension. One JSON object per line in each direction.
No network port is opened, so there's nothing for another process or site to connect to."""
from __future__ import annotations

import json
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from . import __version__, report, tools
from .a11y import axe
from .fixer import fix, ollama
from .link import ownership
from .link.scan import check_a11y, scan_link
from .models import a11y_score, security_score
from .observability import instrument, query, server
from .scan import scan_workspace
from .store import Store
from .triage import merge


def _status(_: dict) -> dict:
    return {
        "version": __version__, "tools": tools.status(), "ollama_models": ollama.models(),
        "mlflow": server.is_running(), "axe": axe.available(),
    }


def _setup(_: dict) -> dict:
    installed = tools.ensure_all()
    return {"installed": installed, **_status({})}


def _findings(p: dict) -> dict:
    store = Store(p["workspace"])
    findings = merge(store.open_findings(), store.statuses())
    return {"findings": [f.to_dict() for f in findings], "security_score": security_score(findings), "a11y_score": a11y_score(findings)}


def _ignore(p: dict) -> dict:
    Store(p["workspace"]).set_status(p["finding_id"], "accepted", p.get("reason", ""))
    return {"ok": True}


def _audit_list(p: dict) -> dict:
    store = Store(p["workspace"])
    return {"entries": store.audit_entries(p.get("limit", 200)), "chain": store.verify_audit()}


def _report(p: dict) -> dict:
    path, fmt = report.export(p["workspace"], p.get("format", "html"), p.get("days", 30))
    return {"path": path, "format": fmt}


METHODS: dict[str, Callable[[dict], Any]] = {
    "status": _status,
    "setup": _setup,
    "scan": lambda p: scan_workspace(p["workspace"], p.get("files")),
    "findings": _findings,
    "finding.ignore": _ignore,
    "fix.propose": lambda p: fix.propose(p["workspace"], p["finding_id"], test_command=p.get("test_command")),
    "fix.decide": lambda p: fix.decide(p["workspace"], int(p["patch_id"]), bool(p["accept"])),
    "link.scan": lambda p: scan_link(p["workspace"], p["link"], p.get("a11y", True)),
    "a11y.check": lambda p: check_a11y(p["workspace"], p["url"]),
    "ownership.verify": lambda p: ownership.verify(p["host"]),
    "mlflow.start": lambda p: server.start(),
    "mlflow.stop": lambda p: server.stop(),
    "traces": lambda p: query.traces(p.get("hours", 24), p.get("experiment")),
    "app.trace": lambda p: instrument.trace_app(p["workspace"]),
    "app.untrace": lambda p: instrument.untrace_app(p["workspace"]),
    "audit.list": _audit_list,
    "audit.verify": lambda p: Store(p["workspace"]).verify_audit(),
    "report.export": _report,
}


def serve() -> None:
    out = sys.stdout
    # Libraries (MLflow, Playwright) sometimes print; keep stdout for protocol messages only.
    sys.stdout = sys.stderr
    lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=4)

    def send(msg: dict) -> None:
        with lock:
            out.write(json.dumps(msg, default=str) + "\n")
            out.flush()

    def handle(req: dict) -> None:
        rid = req.get("id")
        fn = METHODS.get(req.get("method", ""))
        if fn is None:
            send({"id": rid, "error": {"message": f"Unknown method {req.get('method')}"}})
            return
        try:
            send({"id": rid, "result": fn(req.get("params") or {})})
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            send({"id": rid, "error": {"message": str(e) or e.__class__.__name__}})

    send({"event": "ready", "version": __version__})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            send({"id": None, "error": {"message": "Invalid JSON"}})
            continue
        if req.get("method") == "shutdown":
            send({"id": req.get("id"), "result": {"ok": True}})
            break
        pool.submit(handle, req)
    pool.shutdown(wait=False, cancel_futures=True)
