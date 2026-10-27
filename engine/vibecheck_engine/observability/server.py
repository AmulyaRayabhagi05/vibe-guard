"""Start/stop a local MLflow server: SQLite backend, bound to 127.0.0.1 only."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request

from ..config import MLFLOW_DIR, MLFLOW_HOST, MLFLOW_PORT, MLFLOW_URI

_PID_FILE = MLFLOW_DIR / "server.pid"


def is_running() -> bool:
    try:
        with urllib.request.urlopen(MLFLOW_URI + "/health", timeout=1) as r:
            return r.status == 200
    except OSError:
        return False


def start(wait: float = 60) -> dict:
    if is_running():
        return {"running": True, "uri": MLFLOW_URI, "started": False}
    try:
        import mlflow  # noqa: F401
    except ImportError:
        return {"running": False, "error": "MLflow isn't installed. Run: pip install \"vibecheck-engine[observability]\""}
    MLFLOW_DIR.mkdir(parents=True, exist_ok=True)
    db = (MLFLOW_DIR / "mlflow.db").as_posix()
    artifacts = (MLFLOW_DIR / "artifacts").as_posix()
    log = open(MLFLOW_DIR / "server.log", "a")
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    proc = subprocess.Popen(
        [sys.executable, "-m", "mlflow", "server", "--host", MLFLOW_HOST, "--port", str(MLFLOW_PORT),
         "--backend-store-uri", f"sqlite:///{db}", "--default-artifact-root", artifacts, "--workers", "1"],
        stdout=log, stderr=log, creationflags=flags, env={**os.environ, "MLFLOW_ENABLE_TELEMETRY": "false"},
    )
    _PID_FILE.write_text(str(proc.pid))
    deadline = time.time() + wait
    while time.time() < deadline:
        if is_running():
            return {"running": True, "uri": MLFLOW_URI, "started": True}
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    return {"running": False, "error": f"MLflow didn't start. See {MLFLOW_DIR / 'server.log'}"}


def stop() -> dict:
    if not _PID_FILE.exists():
        return {"stopped": False}
    pid = int(_PID_FILE.read_text())
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    _PID_FILE.unlink(missing_ok=True)
    return {"stopped": True}
