"""'Trace my app': add a dev-only MLflow tracing file to the user's project, and remove it again."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import MLFLOW_URI

MARKER = "vibecheck-tracing"
PY_FILE = "vibecheck_tracing.py"
JS_FILE = "vibecheck-tracing.mjs"
PY_ENTRIES = ("main.py", "app.py", "server.py", "manage.py", "app/main.py", "src/main.py", "api/index.py")

PY_TEMPLATE = '''# Added by VibeCheck "Trace my app". Dev only: sends traces to the local MLflow server
# at {uri}. Remove with "VibeCheck: Stop tracing my app".
import os

if os.environ.get("VIBECHECK_TRACE", "1") == "1":
    try:
        import mlflow

        mlflow.set_tracking_uri("{uri}")
        mlflow.set_experiment("{experiment}")
        for _name in ({providers}):
            try:
                getattr(mlflow, _name).autolog()
            except Exception:
                pass
    except ImportError:
        print("[vibecheck] tracing is off: pip install mlflow")
'''

JS_TEMPLATE = '''// Added by VibeCheck "Trace my app". Dev only: sends traces to the local MLflow server
// at {uri}. Remove with "VibeCheck: Stop tracing my app".
// Needs: npm i -D mlflow-tracing mlflow-openai
import * as mlflow from "mlflow-tracing";

if (process.env.VIBECHECK_TRACE !== "0") {{
  mlflow.init({{ trackingUri: "{uri}", experimentId: "{experiment_id}" }});
}}

// Wrap your OpenAI client so every call is traced:
//   import {{ tracedOpenAI }} from "mlflow-openai";
//   const openai = tracedOpenAI(new OpenAI());
export {{}};
'''

PY_PROVIDERS = {
    "openai": "openai", "anthropic": "anthropic", "google-genai": "gemini", "google-generativeai": "gemini",
    "langchain": "langchain", "langchain-core": "langchain", "litellm": "litellm", "llama-index": "llama_index",
    "groq": "groq", "mistralai": "mistral", "dspy": "dspy", "crewai": "crewai",
}


def detect(root: Path) -> dict:
    stack = {"python": False, "node": False, "python_providers": [], "node_providers": []}
    py_text = ""
    for name in ("requirements.txt", "pyproject.toml", "Pipfile"):
        p = root / name
        if p.exists():
            stack["python"] = True
            py_text += p.read_text(encoding="utf-8", errors="ignore").lower()
    for pkg, mod in PY_PROVIDERS.items():
        if re.search(rf"(^|[\s\"'\[]){re.escape(pkg)}\b", py_text, re.M) and mod not in stack["python_providers"]:
            stack["python_providers"].append(mod)
    pj = root / "package.json"
    if pj.exists():
        stack["node"] = True
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            stack["node_providers"] = [d for d in deps if d in ("openai", "@anthropic-ai/sdk", "ai", "@google/genai", "langchain")]
        except json.JSONDecodeError:
            pass
    return stack


def _experiment(root: Path) -> tuple[str, str | None]:
    name = f"vibecheck-app-{root.name}"
    try:
        import mlflow

        mlflow.set_tracking_uri(MLFLOW_URI)
        exp = mlflow.set_experiment(name)
        return name, exp.experiment_id
    except Exception:
        return name, None


def trace_app(workspace: str | Path) -> dict:
    root = Path(workspace).resolve()
    stack = detect(root)
    experiment, exp_id = _experiment(root)
    written, notes = [], []
    if stack["python"] or not stack["node"]:
        providers = stack["python_providers"] or ["openai", "anthropic", "gemini", "langchain", "litellm"]
        (root / PY_FILE).write_text(
            PY_TEMPLATE.format(uri=MLFLOW_URI, experiment=experiment, providers=", ".join(f'"{p}"' for p in providers) + ","),
            encoding="utf-8",
        )
        written.append(PY_FILE)
        entry = next((root / e for e in PY_ENTRIES if (root / e).exists()), None)
        if entry:
            code = entry.read_text(encoding="utf-8")
            if MARKER not in code:
                entry.write_text(f"import vibecheck_tracing  # {MARKER}: remove with 'Stop tracing my app'\n" + code, encoding="utf-8")
                written.append(entry.relative_to(root).as_posix())
        else:
            notes.append(f"Add `import vibecheck_tracing` at the top of your app's entry file.")
    if stack["node"]:
        if exp_id is None:
            notes.append("Start AI tracing (MLflow) first so the experiment id can be filled in.")
        (root / JS_FILE).write_text(JS_TEMPLATE.format(uri=MLFLOW_URI, experiment_id=exp_id or "START_MLFLOW_FIRST"), encoding="utf-8")
        written.append(JS_FILE)
        notes.append(
            f"Run `npm i -D mlflow-tracing mlflow-openai`, import ./{JS_FILE} once at server start, and wrap your "
            "OpenAI client with tracedOpenAI(). Other providers need manual spans (the JS SDK auto-traces OpenAI only)."
        )
    return {"experiment": experiment, "experiment_id": exp_id, "files": written, "notes": notes, "stack": stack}


def untrace_app(workspace: str | Path) -> dict:
    root = Path(workspace).resolve()
    removed = []
    for name in (PY_FILE, JS_FILE):
        if (root / name).exists():
            (root / name).unlink()
            removed.append(name)
    for e in PY_ENTRIES:
        p = root / e
        if p.exists():
            code = p.read_text(encoding="utf-8")
            if MARKER in code:
                p.write_text("".join(ln for ln in code.splitlines(keepends=True) if MARKER not in ln), encoding="utf-8")
                removed.append(f"{e} (import line)")
    return {"removed": removed}
