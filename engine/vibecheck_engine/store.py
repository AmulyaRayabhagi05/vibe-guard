"""SQLite store: scans, findings, patches and the hash-chained audit log."""
from __future__ import annotations

import getpass
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .config import workspace_dir
from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, target TEXT, kind TEXT, started REAL, finished REAL,
  security_score INTEGER, a11y_score INTEGER, counts TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, scan_id INTEGER, status TEXT DEFAULT 'open', data TEXT,
  first_seen REAL, last_seen REAL
);
CREATE TABLE IF NOT EXISTS patches (
  id INTEGER PRIMARY KEY, finding_id TEXT, model TEXT, trace_id TEXT, original TEXT,
  patched TEXT, checks TEXT, decision TEXT, created REAL, latency_ms INTEGER, tokens INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

GENESIS = "0" * 64


def _row_hash(prev: str, ts: float, actor: str, action: str, detail: str) -> str:
    payload = json.dumps([prev, round(ts, 6), actor, action, detail], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class Store:
    def __init__(self, workspace: str | Path, db_name: str = "vibecheck.db"):
        self.workspace = Path(workspace)
        # Link scans use their own db so they never mix with the workspace's findings or score.
        self.path = workspace_dir(workspace) / db_name
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---- audit ----
    def audit(self, action: str, detail: dict[str, Any] | None = None, actor: str | None = None) -> str:
        actor = actor or getpass.getuser()
        body = json.dumps(detail or {}, sort_keys=True, default=str)
        ts = time.time()
        with self.db:
            last = self.db.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            h = _row_hash(prev, ts, actor, action, body)
            self.db.execute(
                "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (ts, actor, action, body, prev, h),
            )
        return h

    def verify_audit(self) -> dict[str, Any]:
        prev = GENESIS
        n = 0
        for row in self.db.execute("SELECT * FROM audit_log ORDER BY seq"):
            n += 1
            expected = _row_hash(prev, row["ts"], row["actor"], row["action"], row["detail"])
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {"ok": False, "entries": n, "broken_at": row["seq"]}
            prev = row["hash"]
        return {"ok": True, "entries": n, "last_hash": prev}

    def audit_entries(self, limit: int = 200, since: float = 0) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM audit_log WHERE ts >= ? ORDER BY seq DESC LIMIT ?", (since, limit)
        ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]

    # ---- scans + findings ----
    def start_scan(self, target: str, kind: str) -> int:
        with self.db:
            cur = self.db.execute("INSERT INTO scans (target, kind, started) VALUES (?,?,?)", (target, kind, time.time()))
        return cur.lastrowid

    def finish_scan(self, scan_id: int, findings: list[Finding], security: int, a11y: int) -> None:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        now = time.time()
        with self.db:
            self.db.execute(
                "UPDATE scans SET finished=?, security_score=?, a11y_score=?, counts=? WHERE id=?",
                (now, security, a11y, json.dumps(counts), scan_id),
            )
            for f in findings:
                self.db.execute(
                    """INSERT INTO findings (id, scan_id, data, first_seen, last_seen) VALUES (?,?,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET scan_id=excluded.scan_id, data=excluded.data,
                       last_seen=excluded.last_seen,
                       status=CASE WHEN findings.status='fixed' THEN 'open' ELSE findings.status END""",
                    (f.id, scan_id, json.dumps(f.to_dict()), now, now),
                )

    def statuses(self) -> dict[str, str]:
        return {r["id"]: r["status"] for r in self.db.execute("SELECT id, status FROM findings")}

    def set_status(self, finding_id: str, status: str, reason: str = "") -> None:
        with self.db:
            self.db.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.audit(f"finding.{status}", {"finding": finding_id, "reason": reason})

    def get_finding(self, finding_id: str) -> Finding | None:
        r = self.db.execute("SELECT data FROM findings WHERE id=?", (finding_id,)).fetchone()
        return Finding(**json.loads(r["data"])) if r else None

    def open_findings(self) -> list[Finding]:
        """Open findings from the most recent scan."""
        last = self.db.execute("SELECT MAX(id) AS id FROM scans WHERE finished IS NOT NULL").fetchone()["id"]
        rows = self.db.execute("SELECT data FROM findings WHERE status='open' AND scan_id=?", (last,)).fetchall()
        return [Finding(**json.loads(r["data"])) for r in rows]

    def last_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- patches ----
    def add_patch(self, **kw: Any) -> int:
        kw.setdefault("created", time.time())
        cols = ",".join(kw)
        with self.db:
            cur = self.db.execute(
                f"INSERT INTO patches ({cols}) VALUES ({','.join('?' * len(kw))})",
                [json.dumps(v) if isinstance(v, (dict, list)) else v for v in kw.values()],
            )
        return cur.lastrowid

    def get_patch(self, patch_id: int) -> dict[str, Any] | None:
        r = self.db.execute("SELECT * FROM patches WHERE id=?", (patch_id,)).fetchone()
        return dict(r) if r else None

    def decide_patch(self, patch_id: int, decision: str) -> None:
        with self.db:
            self.db.execute("UPDATE patches SET decision=? WHERE id=?", (decision, patch_id))
