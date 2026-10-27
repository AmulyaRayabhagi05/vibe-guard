"""Where VibeCheck keeps things. Global tools live in ~/.vibecheck; per-workspace data in <ws>/.vibecheck."""
from __future__ import annotations

import os
from pathlib import Path

HOME = Path(os.environ.get("VIBECHECK_HOME", Path.home() / ".vibecheck"))
BIN_DIR = HOME / "bin"
MLFLOW_DIR = HOME / "mlflow"

# Repo layout: engine/vibecheck_engine/config.py -> ../../rules
_REPO_RULES = Path(__file__).resolve().parents[2] / "rules"
RULES_DIR = Path(os.environ.get("VIBECHECK_RULES", _REPO_RULES))

OLLAMA_URL = os.environ.get("VIBECHECK_OLLAMA_URL", "http://127.0.0.1:11434")
FIX_MODEL = os.environ.get("VIBECHECK_MODEL", "vibecheck-coder")
# Used until the fine-tuned model is installed.
FALLBACK_MODEL = os.environ.get("VIBECHECK_FALLBACK_MODEL", "deepseek-coder:6.7b-instruct")

MLFLOW_HOST = "127.0.0.1"
MLFLOW_PORT = int(os.environ.get("VIBECHECK_MLFLOW_PORT", "5000"))
MLFLOW_URI = f"http://{MLFLOW_HOST}:{MLFLOW_PORT}"

# Folders never worth scanning.
IGNORE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", ".venv", "venv", "__pycache__",
    ".vibecheck", "coverage", ".turbo", ".svelte-kit", "out", ".cache",
}


def workspace_dir(workspace: str | Path) -> Path:
    d = Path(workspace) / ".vibecheck"
    d.mkdir(parents=True, exist_ok=True)
    gi = d / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n")  # keep findings/audit out of the user's repo by default
    return d
