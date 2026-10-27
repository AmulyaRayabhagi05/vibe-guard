"""Runtime checks on traced AI traffic. Flags are stored as trace tags (vibecheck.flag.*)."""
from __future__ import annotations

import json
import re
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\d)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
# Common phrasings of instruction-override attempts in user input.
INJECTION = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(system|previous) "
    r"(prompt|instructions)|reveal (your|the) (system prompt|instructions)|you are now (in )?(dan|developer mode)|"
    r"print (your|the) (system prompt|hidden instructions))"
)


def _luhn(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


def _text(v: Any) -> str:
    if v is None:
        return ""
    return v if isinstance(v, str) else json.dumps(v, default=str)


def has_secret(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS)


def has_pii(text: str) -> bool:
    return bool(EMAIL.search(text) or PHONE.search(text) or any(_luhn(m.group()) for m in CARD.finditer(text)))


def check(inputs: Any, outputs: Any, total_tokens: int, token_budget: int = 8000) -> list[str]:
    i, o = _text(inputs), _text(outputs)
    flags = []
    if INJECTION.search(i):
        flags.append("prompt_injection")
    if has_secret(o):
        flags.append("secret_in_output")
    if has_secret(i):
        flags.append("secret_in_prompt")
    if has_pii(i) or has_pii(o):
        flags.append("pii")
    if total_tokens > token_budget:
        flags.append("over_token_budget")
    return flags


def redact(text: str) -> str:
    """Mask secrets and personal data before showing trace content in the UI."""
    for p in SECRET_PATTERNS:
        text = p.sub(lambda m: m.group()[:4] + "…[secret]", text)
    text = EMAIL.sub("[email]", text)
    text = CARD.sub(lambda m: "[card]" if _luhn(m.group()) else m.group(), text)
    return PHONE.sub("[phone]", text)
