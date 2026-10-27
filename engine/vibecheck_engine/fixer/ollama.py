"""Minimal Ollama client (stdlib only). Talks to the local server; nothing leaves the machine."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..config import FALLBACK_MODEL, FIX_MODEL, OLLAMA_URL


class OllamaError(RuntimeError):
    pass


def _post(path: str, body: dict, timeout: int = 300) -> dict:
    req = urllib.request.Request(
        OLLAMA_URL + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.URLError as e:
        raise OllamaError(
            f"Can't reach Ollama at {OLLAMA_URL}. Start it with 'ollama serve' (free: https://ollama.com)."
        ) from e


def models() -> list[str]:
    try:
        with urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=3) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except (urllib.error.URLError, OSError, ValueError):
        return []


def pick_model() -> str:
    """The fine-tuned model if installed, else the base DeepSeek model."""
    names = models()
    for want in (FIX_MODEL, FALLBACK_MODEL):
        if any(n == want or n.split(":")[0] == want for n in names):
            return want
    if not names:
        raise OllamaError(f"Can't reach Ollama at {OLLAMA_URL}, or no models are installed. Run 'ollama pull {FALLBACK_MODEL}'.")
    raise OllamaError(f"No fix model installed. Run 'ollama pull {FALLBACK_MODEL}' (or create vibecheck-coder).")


def chat(messages: list[dict], model: str, max_tokens: int = 1200) -> dict:
    t0 = time.time()
    r = _post(
        "/api/chat",
        {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": max_tokens, "num_ctx": 8192},
        },
    )
    return {
        "content": r.get("message", {}).get("content", ""),
        "input_tokens": r.get("prompt_eval_count", 0),
        "output_tokens": r.get("eval_count", 0),
        "latency_ms": int((time.time() - t0) * 1000),
        "model": model,
    }
