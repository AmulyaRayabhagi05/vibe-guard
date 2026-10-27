"""The fix prompt. Training data (dataset/) is built with these same functions, so the
model sees the exact format at train and inference time. Change it in one place only."""
from __future__ import annotations

import re

SYSTEM = (
    "You are VibeCheck, a code repair model for security and accessibility issues in "
    "AI-generated web apps. Fix only the issue described. Keep the code's behavior, names "
    "and style. Never invent secrets; read them from environment variables instead. "
    "Reply with the corrected REGION only, inside one fenced code block, and nothing else."
)

LANG_FENCE = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "tsx",
    "html": "html",
}


def build_user_prompt(
    *,
    language: str,
    path: str,
    rule_id: str,
    title: str,
    message: str,
    tags: str,
    start_line: int,
    end_line: int,
    region: str,
    context: str,
) -> str:
    fence = LANG_FENCE.get(language, "")
    return (
        f"Language: {language}\n"
        f"File: {path}\n"
        f"Issue: {rule_id}: {title}{f' ({tags})' if tags else ''}\n"
        f"Why: {message}\n\n"
        f"REGION (lines {start_line}-{end_line}), rewrite this:\n"
        f"```{fence}\n{region}\n```\n\n"
        f"CONTEXT (read-only, do not repeat):\n"
        f"```{fence}\n{context}\n```"
    )


def build_messages(**kwargs) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": build_user_prompt(**kwargs)},
    ]


_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.S)


def extract_code(reply: str) -> str | None:
    """Pull the first fenced block out of a model reply."""
    m = _FENCE_RE.search(reply)
    if not m:
        return None
    return m.group(1).rstrip("\n")
