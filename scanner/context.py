"""Deterministic source preparation for LLM prompts (tokenize + ast only)."""
from __future__ import annotations

import ast
import io
import tokenize

MAX_CONTEXT_CHARS = 8000
MAX_HELPERS = 4
MAX_CONSTANTS = 4
MAX_CONSTANT_LINES = 12
LITERAL_NODES = (ast.Dict, ast.List, ast.Set, ast.Tuple, ast.Constant)
FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def strip_python_comments(source: str) -> tuple[str, bool]:
    """Blank out # comments but keep every line number. Returns (text, ok).

    Comments are author claims, not evidence. String literals and docstrings
    are left alone.
    """
    lines = io.StringIO(source).readlines()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            row, col = tok.start
            text = lines[row - 1]
            body = text.rstrip("\r\n")
            lines[row - 1] = body[:col].rstrip() + text[len(body):]
    except (tokenize.TokenError, SyntaxError, IndexError):
        return source, False
    return "".join(lines), True


def _span(node) -> tuple[int, int]:
    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
    return start, getattr(node, "end_lineno", node.lineno)


def enclosing_function(tree: ast.AST, line: int):
    """Innermost function whose span (decorators included) contains `line`."""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, FUNCTION_NODES):
            start, end = _span(node)
            if start <= line <= end and (best is None or start >= _span(best)[0]):
                best = node
    return best


def _loaded_names(*nodes) -> list[str]:
    found = sorted(
        (n.lineno, n.col_offset, n.id)
        for node in nodes
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    )
    ordered: list[str] = []
    for _, _, name in found:
        if name not in ordered:
            ordered.append(name)
    return ordered


def _numbered(lines: list[str], start: int, end: int) -> str:
    end = min(end, len(lines))
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))


def window_context(source: str, line: int, before: int = 15, after: int = 15) -> str:
    lines = source.splitlines()
    return _numbered(lines, max(1, line - before), min(len(lines), line + after))


def build_python_context(source: str, line: int) -> dict | None:
    """Enclosing function + same-file helpers it calls + literal constants they use."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    func = enclosing_function(tree, line)
    if func is None:
        return None

    lines = source.splitlines()
    functions = {n.name: n for n in tree.body if isinstance(n, FUNCTION_NODES)}
    constants = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            constants[n.targets[0].id] = n
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            constants[n.target.id] = n

    helpers = [
        functions[name] for name in _loaded_names(func)
        if name in functions and functions[name] is not func
    ][:MAX_HELPERS]

    consts = []
    for name in _loaded_names(func, *helpers):
        node = constants.get(name)
        if node is None or not isinstance(node.value, LITERAL_NODES):
            continue
        if node.end_lineno - node.lineno + 1 <= MAX_CONSTANT_LINES:
            consts.append((name, node.lineno, node.end_lineno))
    consts = consts[:MAX_CONSTANTS]

    start, end = _span(func)
    chunks = [f"[enclosing function {func.name}: lines {start}-{end}]\n"
              f"{_numbered(lines, start, end)}"]
    for helper in helpers:
        s, e = _span(helper)
        chunks.append(f"[helper {helper.name}: lines {s}-{e}]\n{_numbered(lines, s, e)}")
    for name, s, e in consts:
        chunks.append(f"[module constant {name}: lines {s}-{e}]\n{_numbered(lines, s, e)}")

    text, truncated = "", False
    for chunk in chunks:
        if text and len(text) + len(chunk) + 2 > MAX_CONTEXT_CHARS:
            truncated = True
            break
        text += ("\n\n" if text else "") + chunk
    if len(text) > MAX_CONTEXT_CHARS:
        text, truncated = text[:MAX_CONTEXT_CHARS], True

    return {"text": text, "meta": {
        "function": func.name,
        "helpers": [h.name for h in helpers],
        "constants": [c[0] for c in consts],
        "truncated": truncated,
        "fallback": None,
    }}


def prepare_context(source: str, line: int, suffix: str = ".py") -> dict:
    """Comment-stripped, line-numbered context for a prompt."""
    stripped_ok = False
    if suffix.lower() == ".py":
        source, stripped_ok = strip_python_comments(source)
        built = build_python_context(source, line)
        if built:
            built["meta"]["comments_stripped"] = stripped_ok
            return built
    return {
        "text": window_context(source, line)[:MAX_CONTEXT_CHARS],
        "meta": {"function": None, "helpers": [], "constants": [],
                 "truncated": False, "fallback": "line_window",
                 "comments_stripped": stripped_ok},
    }


def _parse_numbered(text: str) -> dict[int, str]:
    out = {}
    for row in text.splitlines():
        head, sep, rest = row.partition(": ")
        if sep and head.isdigit():
            out[int(head)] = rest
    return out


def verify_citations(context: str, citations, slack: int = 1) -> dict:
    """Check that each quoted snippet really appears on (or next to) the cited line."""
    numbered = _parse_numbered(context)
    checked = []
    for item in (citations[:10] if isinstance(citations, list) else []):
        if not isinstance(item, dict):
            continue
        quote = " ".join(str(item.get("quote", "")).split())
        try:
            n = int(item.get("line"))
        except (TypeError, ValueError):
            n = None
        ok = len(quote) >= 6 and n is not None and any(
            quote in " ".join(numbered.get(k, "").split())
            for k in range(n - slack, n + slack + 1)
        )
        checked.append({"line": n, "quote": quote[:120], "verified": ok})
    return {"checked": checked,
            "verified": sum(c["verified"] for c in checked),
            "total": len(checked)}