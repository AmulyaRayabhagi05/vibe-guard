"""Trace VibeCheck's own fix calls into the local MLflow server. If MLflow isn't installed or
the server isn't running, every function here quietly does nothing."""
from __future__ import annotations

import contextlib
import urllib.request
from typing import Any, Iterator

from ..config import MLFLOW_URI

EXPERIMENT = "vibecheck-fixes"


def _server_up() -> bool:
    try:
        with urllib.request.urlopen(MLFLOW_URI + "/health", timeout=1) as r:
            return r.status == 200
    except OSError:
        return False


def _mlflow():
    try:
        import mlflow
    except ImportError:
        return None
    if not _server_up():
        return None
    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment(EXPERIMENT)
    return mlflow


class _Span:
    def __init__(self, span=None, mlflow=None):
        self._span = span
        self._mlflow = mlflow
        self.trace_id = getattr(span, "trace_id", None) or getattr(span, "request_id", None)

    def record_llm(self, model: str, messages: list[dict], reply: str, usage: dict[str, int]) -> None:
        if self._span is None:
            return
        self._span.set_inputs({"messages": messages})
        self._span.set_outputs({"content": reply})
        self._span.set_attributes({
            "mlflow.llm.model": model,
            "mlflow.llm.provider": "ollama",
            "mlflow.chat.tokenUsage": {
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "total_tokens": usage["input_tokens"] + usage["output_tokens"],
            },
        })

    def record_result(self, result: dict[str, Any]) -> None:
        if self._span is None:
            return
        self._span.set_attributes({
            "vibecheck.validator_ok": result["ok"],
            "vibecheck.checks": [f"{c['name']}={'ok' if c['ok'] else 'fail'}" for c in result["checks"]],
        })


@contextlib.contextmanager
def fix_span(finding) -> Iterator[_Span]:
    mlflow = _mlflow()
    if mlflow is None:
        yield _Span()
        return
    with mlflow.start_span(name="vibecheck.fix", span_type="LLM") as span:
        span.set_attributes({
            "vibecheck.rule": finding.rule_id,
            "vibecheck.category": finding.category,
            "vibecheck.severity": finding.severity,
            "vibecheck.path": finding.path,
        })
        yield _Span(span, mlflow)


def record_decision(trace_id: str | None, accepted: bool) -> None:
    mlflow = _mlflow() if trace_id else None
    if mlflow is None:
        return
    with contextlib.suppress(Exception):
        mlflow.set_trace_tag(trace_id, "vibecheck.decision", "accepted" if accepted else "rejected")
