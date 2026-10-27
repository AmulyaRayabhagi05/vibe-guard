"""Deterministic fixes that don't need the model. Hardcoded secrets always get the same fix:
read the value from an environment variable."""
from __future__ import annotations

import re

from ..models import Finding

# Quoted strings long enough to be a credential.
_STRING = re.compile(r"""(?P<q>["'`])(?P<v>[^"'`\s]{16,})(?P=q)""")


def secret_to_env(finding: Finding, region: str, language: str | None) -> str | None:
    if finding.category != "secret" or finding.source != "trufflehog":
        return None
    name = finding.extra.get("env_name") or "SECRET_KEY"
    if language == "python":
        repl = f'os.environ["{name}"]'
    elif language in ("javascript", "typescript", "tsx"):
        repl = f"process.env.{name}"
    else:
        return None
    new, n = _STRING.subn(repl, region, count=1)
    # For Python the caller adds `import os` at file level (ensure_python_os_import).
    return new if n else None


def ensure_python_os_import(code: str) -> str:
    if re.search(r"^\s*(import os\b|from os import)", code, re.M):
        return code
    lines = code.split("\n")
    # after a module docstring / __future__ imports, before the first other line
    i = 0
    while i < len(lines) and (lines[i].startswith(("#!", "# -*-", "from __future__")) or not lines[i].strip()):
        i += 1
    return "\n".join(lines[:i] + ["import os"] + lines[i:])
