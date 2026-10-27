"""CLI: `python -m vibecheck_engine <command>`. `serve` is what the VS Code extension runs."""
from __future__ import annotations

import argparse
import json
import sys


def _print(obj, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))
        return
    findings = obj.get("findings")
    if findings is None:
        print(json.dumps(obj, indent=2, default=str))
        return
    for f in findings:
        loc = f"{f['path']}:{f['start_line']}" if f["start_line"] else f["path"]
        tag = f["wcag"] or f["cwe"] or f["owasp"]
        print(f"[{f['severity'].upper():8}] {f['category']:6} {loc}\n           {f['title']}  ({tag})")
    if "security_score" in obj:
        print(f"\nSecurity score {obj['security_score']}/100 · Accessibility score {obj.get('a11y_score', '-')}/100 · {len(findings)} findings")
    elif "a11y_score" in obj:
        print(f"\nAccessibility score {obj['a11y_score']}/100 · {len(findings)} WCAG findings")
    for e in obj.get("errors", []):
        print(f"! {e}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap =argparse.ArgumentParser(prog="vibecheck-engine", description="VibeCheck security + accessibility engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="JSON-RPC over stdio (used by the VS Code extension)")
    sub.add_parser("setup", help="download Opengrep + TruffleHog (pinned, checksum-verified)")
    sub.add_parser("status")
    s = sub.add_parser("scan", help="scan a folder")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 1 if any finding is at least this severe (for CI)")
    l = sub.add_parser("scan-link", help="scan a GitHub repo or a website")
    l.add_argument("link")
    l.add_argument("--workspace", default=".")
    l.add_argument("--no-a11y", action="store_true")
    l.add_argument("--json", action="store_true")
    a = sub.add_parser("a11y", help="WCAG check a URL (e.g. your dev server) with axe-core")
    a.add_argument("url")
    a.add_argument("--workspace", default=".")
    a.add_argument("--json", action="store_true")
    v = sub.add_parser("verify-audit", help="check the audit hash chain")
    v.add_argument("path", nargs="?", default=".")
    r = sub.add_parser("report", help="export an audit report")
    r.add_argument("path", nargs="?", default=".")
    r.add_argument("--format", choices=["html", "json", "csv"], default="html")
    r.add_argument("--days", type=int, default=30)
    m = sub.add_parser("mlflow", help="start/stop the local MLflow server")
    m.add_argument("action", choices=["start", "stop", "status"])
    t = sub.add_parser("traces", help="summarize AI traces")
    t.add_argument("--hours", type=int, default=24)
    args = ap.parse_args(argv)

    if args.cmd == "serve":
        from .rpc import serve
        serve()
        return 0
    if args.cmd == "setup":
        from . import tools
        print(json.dumps({"installed": tools.ensure_all(), "status": tools.status()}, indent=2))
        return 0
    if args.cmd == "status":
        from .rpc import _status
        print(json.dumps(_status({}), indent=2))
        return 0
    if args.cmd == "scan":
        from .models import SEVERITIES
        from .scan import scan_workspace
        res = scan_workspace(args.path)
        _print(res, args.json)
        if args.fail_on:
            limit = SEVERITIES.index(args.fail_on)
            return 1 if any(SEVERITIES.index(f["severity"]) <= limit for f in res["findings"]) else 0
        return 0
    if args.cmd == "scan-link":
        from .link.scan import scan_link
        _print(scan_link(args.workspace, args.link, a11y=not args.no_a11y), args.json)
        return 0
    if args.cmd == "a11y":
        from .link.scan import check_a11y
        _print(check_a11y(args.workspace, args.url), args.json)
        return 0
    if args.cmd == "verify-audit":
        from .store import Store
        res = Store(args.path).verify_audit()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    if args.cmd == "report":
        from .report import export
        print(export(args.path, args.format, args.days)[0])
        return 0
    if args.cmd == "mlflow":
        from .observability import server
        fn = {"start": server.start, "stop": server.stop, "status": lambda: {"running": server.is_running()}}[args.action]
        print(json.dumps(fn(), indent=2))
        return 0
    if args.cmd == "traces":
        from .observability import query
        res = query.traces(args.hours)
        print(json.dumps({k: res.get(k) for k in ("available", "reason", "summary", "cost")}, indent=2, default=str))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
