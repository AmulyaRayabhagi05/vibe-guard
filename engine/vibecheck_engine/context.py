"""Tree-sitter helpers: language detection, syntax checks, and picking the code region a fix
should rewrite (the smallest whole statement, function or JSX element around a finding)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "tsx",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
}

# Node types that make a sensible, self-contained thing to rewrite.
UNIT_SUFFIXES = ("_statement", "_declaration", "_definition")
UNIT_TYPES = {"jsx_element", "jsx_self_closing_element", "decorated_definition", "method_definition", "pair"}
MAX_REGION_LINES = 80


def language_for(path: str | Path) -> str | None:
    return EXT_LANG.get(Path(path).suffix.lower())


@lru_cache(maxsize=None)
def _parser(lang: str):
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    if lang == "python":
        import tree_sitter_python as m
        language = Language(m.language())
    elif lang == "javascript":
        import tree_sitter_javascript as m
        language = Language(m.language())
    elif lang in ("typescript", "tsx"):
        import tree_sitter_typescript as m
        language = Language(m.language_tsx() if lang == "tsx" else m.language_typescript())
    else:
        return None
    return Parser(language)


def parse_ok(code: str, lang: str | None) -> bool | None:
    """True if the code parses cleanly, False if it has syntax errors, None if we can't tell."""
    parser = _parser(lang) if lang else None
    if parser is None:
        return None
    tree = parser.parse(code.encode())
    return not tree.root_node.has_error


def _is_unit(node) -> bool:
    return node.type in UNIT_TYPES or node.type.endswith(UNIT_SUFFIXES)


def region_lines(code: str, lang: str | None, start_line: int, end_line: int) -> tuple[int, int]:
    """1-based inclusive line range to hand to the fixer."""
    total = code.count("\n") + 1
    start_line = max(1, min(start_line, total))
    end_line = max(start_line, min(end_line or start_line, total))
    parser = _parser(lang) if lang else None
    if parser is not None:
        tree = parser.parse(code.encode())
        lines = code.split("\n")
        # first non-blank column on the start line, so we land inside the statement
        col = len(lines[start_line - 1]) - len(lines[start_line - 1].lstrip())
        last_col = max(0, len(lines[end_line - 1].rstrip()) - 1)
        node = tree.root_node.named_descendant_for_point_range((start_line - 1, col), (end_line - 1, last_col))
        while node is not None and node.parent is not None:
            if _is_unit(node) and node.end_point[0] >= end_line - 1:
                s, e = node.start_point[0] + 1, node.end_point[0] + 1
                if e - s + 1 <= MAX_REGION_LINES:
                    # Include decorators / export keyword that wrap this node.
                    p = node.parent
                    if p is not None and p.type in ("decorated_definition", "export_statement"):
                        s = p.start_point[0] + 1
                    return s, e
                break
            node = node.parent
    # Fallback: the flagged lines plus a little air.
    return max(1, start_line - 2), min(total, end_line + 2)


def slice_lines(code: str, start: int, end: int) -> str:
    return "\n".join(code.split("\n")[start - 1 : end])


def context_window(code: str, start: int, end: int, pad: int = 40) -> str:
    lines = code.split("\n")
    a, b = max(0, start - 1 - pad), min(len(lines), end + pad)
    return "\n".join(lines[a:b])


def replace_lines(code: str, start: int, end: int, new_region: str) -> str:
    lines = code.split("\n")
    # Keep the original indentation if the model dropped it.
    old_first = lines[start - 1]
    indent = old_first[: len(old_first) - len(old_first.lstrip())]
    new_lines = new_region.split("\n")
    if indent and new_lines and not new_lines[0].startswith(indent) and new_lines[0].strip():
        new_lines = [indent + ln if ln.strip() else ln for ln in new_lines]
    return "\n".join(lines[: start - 1] + new_lines + lines[end:])
