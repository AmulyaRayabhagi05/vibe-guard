"""Propose, validate and apply fixes. Every proposal is traced (MLflow, when running) and every
decision is written to the audit chain."""
from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from ..context import context_window, language_for, region_lines, replace_lines, slice_lines
from ..observability import tracing
from ..store import Store
from . import ollama, prompt, quickfix
from .validate import validate


def _tags(f) -> str:
    return ", ".join(x for x in (f.cwe, f.owasp, f"WCAG {f.wcag}" if f.wcag else "") if x)


def propose(workspace: str | Path, finding_id: str, store: Store | None = None, test_command: str | None = None) -> dict[str, Any]:
    root = Path(workspace).resolve()
    store = store or Store(root)
    f = store.get_finding(finding_id)
    if f is None:
        raise ValueError("That finding no longer exists. Run a scan again.")
    if not f.fixable or f.source in ("web", "axe", "osv"):
        raise ValueError("This finding can't be fixed in code automatically. Follow the steps in its message.")
    file = root / f.path
    original = file.read_text(encoding="utf-8")
    lang = language_for(f.path)
    start, end = region_lines(original, lang, f.start_line, f.end_line)
    region = slice_lines(original, start, end)

    with tracing.fix_span(f) as span:
        new_region = quickfix.secret_to_env(f, region, lang)
        if new_region is not None:
            model, usage, latency = "quickfix:secret-to-env", {"input_tokens": 0, "output_tokens": 0}, 0
        else:
            model = ollama.pick_model()
            messages = prompt.build_messages(
                language=lang or Path(f.path).suffix.lstrip("."), path=f.path, rule_id=f.rule_id, title=f.title,
                message=f.message, tags=_tags(f), start_line=start, end_line=end, region=region,
                context=context_window(original, start, end),
            )
            reply = ollama.chat(messages, model)
            new_region = prompt.extract_code(reply["content"])
            usage = {"input_tokens": reply["input_tokens"], "output_tokens": reply["output_tokens"]}
            latency = reply["latency_ms"]
            span.record_llm(model, messages, reply["content"], usage)
            if new_region is None:
                raise ValueError("The model didn't return a code block. Try again, or fix it by hand.")
        patched = replace_lines(original, start, end, new_region)
        if lang == "python" and "os.environ[" in new_region:
            patched = quickfix.ensure_python_os_import(patched)
        result = validate(f, original, patched, test_command, str(root))
        span.record_result(result)
        trace_id = span.trace_id

    diff = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), patched.splitlines(keepends=True), f"a/{f.path}", f"b/{f.path}"
    ))
    patch_id = store.add_patch(
        finding_id=f.id, model=model, trace_id=trace_id, original=original, patched=patched,
        checks=result["checks"], latency_ms=latency, tokens=usage["input_tokens"] + usage["output_tokens"],
    )
    store.audit("patch.generated", {
        "finding": f.id, "rule": f.rule_id, "path": f.path, "patch": patch_id, "model": model,
        "trace_id": trace_id, "validator": f"{sum(c['ok'] for c in result['checks'])}/{len(result['checks'])}",
    })
    return {
        "patch_id": patch_id, "finding": f.to_dict(), "model": model, "trace_id": trace_id,
        "region": [start, end], "original": original, "patched": patched, "diff": diff,
        "checks": result["checks"], "ok": result["ok"], "latency_ms": latency, **usage,
    }


def decide(workspace: str | Path, patch_id: int, accept: bool, store: Store | None = None) -> dict[str, Any]:
    root = Path(workspace).resolve()
    store = store or Store(root)
    p = store.get_patch(patch_id)
    if p is None:
        raise ValueError("Patch not found.")
    f = store.get_finding(p["finding_id"])
    file = root / f.path
    detail: dict[str, Any] = {"patch": patch_id, "finding": f.id, "path": f.path, "model": p["model"], "trace_id": p["trace_id"]}
    if accept:
        current = file.read_text(encoding="utf-8")
        if current != p["original"]:
            raise ValueError("The file changed since this patch was made. Generate the fix again.")
        file.write_text(p["patched"], encoding="utf-8")
        detail["sha_before"] = _sha(p["original"])
        detail["sha_after"] = _sha(p["patched"])
        store.decide_patch(patch_id, "accepted")
        store.set_status(f.id, "fixed", reason=f"patch {patch_id}")
    else:
        store.decide_patch(patch_id, "rejected")
    store.audit("patch.accepted" if accept else "patch.rejected", detail)
    tracing.record_decision(p["trace_id"], accept)
    return {"ok": True, "accepted": accept, "path": f.path}


def _sha(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()
