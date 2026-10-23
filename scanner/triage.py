"""Deterministic triage of scanner findings.

Uses ``ast`` only. Never imports or executes anything from the scanned project.
"""
from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath
import re

try:
    from .context import enclosing_function
    from .idor_scanner import IDENTITY_NAMES, OWNERSHIP_FIELDS
except ImportError:  # script mode
    from context import enclosing_function
    from idor_scanner import IDENTITY_NAMES, OWNERSHIP_FIELDS

TRIAGE_VERSION = "1"

IMPORT_ONLY_RULES = {"B404"}  # advisory about `import subprocess`; no usage claim
TEST_ONLY_RULES = {"B101"}    # assert statements
SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
WINDOWS_SCRIPT_SUFFIXES = (".bat", ".cmd")  # cmd.exe re-parses arguments for these


def _decision(classification: str, rule: str, reason: str, **extra) -> dict:
    return {
        "version": TRIAGE_VERSION,
        "classification": classification,
        "evidence_source": "deterministic_rule",
        "rule": rule,
        "reason": reason,
        **extra,
    }


def _unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "<unparseable>"


def _enclosing_function(tree: ast.AST, line: int):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end and (
                best is None or node.lineno >= best.lineno
            ):
                best = node
    return best


def _assignments(scope: ast.AST, name: str):
    """Simple assigned values for `name`; None if it is bound in a way we can't track."""
    stores = [
        n for n in ast.walk(scope)
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)
    ]
    values = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            values.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            values.append(node.value)
    return values if len(values) == len(stores) else None


def _is_parameter(scope: ast.AST, name: str) -> bool:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    a = scope.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    names += [x.arg for x in (a.vararg, a.kwarg) if x]
    return name in names


def _lookup(name: str, scope: ast.AST, tree: ast.AST):
    """Return ("param", None), ("value", node) or (None, None)."""
    for s in (scope, tree):
        values = _assignments(s, name)
        if values is None or len(values) > 1:
            return None, None
        if len(values) == 1:
            return "value", values[0]
        if s is scope and _is_parameter(scope, name):
            return "param", None
    return None, None


def _kind(node: ast.AST, scope: ast.AST, tree: ast.AST, depth: int = 0) -> str:
    """literal | sys.executable | parameter | dynamic"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "literal"
    if _unparse(node) == "sys.executable":
        return "sys.executable"
    if depth >= 3:
        return "dynamic"
    if (
        isinstance(node, ast.Call)
        and _unparse(node.func) == "str"
        and len(node.args) == 1
        and not node.keywords
    ):
        return _kind(node.args[0], scope, tree, depth + 1)
    if isinstance(node, ast.Name):
        how, value = _lookup(node.id, scope, tree)
        if how == "param":
            return "parameter"
        if how == "value":
            inner = _kind(value, scope, tree, depth + 1)
            if inner in {"literal", "sys.executable"}:
                return inner
    return "dynamic"


def _find_subprocess_call(tree: ast.AST, line: int):
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = _unparse(node.func)
        if not func.startswith("subprocess.") or func.split(".")[-1] not in SUBPROCESS_FUNCS:
            continue
        end = getattr(node, "end_lineno", node.lineno)
        if node.lineno <= line <= end and (best is None or node.lineno >= best.lineno):
            best = node
    return best


def _shell_value(call: ast.Call):
    """False if absent/False, True if True, None if unknown."""
    for kw in call.keywords:
        if kw.arg is None:
            return None  # **kwargs could set shell
        if kw.arg == "shell":
            if isinstance(kw.value, ast.Constant):
                return bool(kw.value.value)
            return None
    return False


def _argv_elements(argv_node, scope, tree):
    node = argv_node
    if isinstance(node, ast.Name):
        how, value = _lookup(node.id, scope, tree)
        node = value if how == "value" else None
    if isinstance(node, (ast.List, ast.Tuple)) and not any(
        isinstance(e, ast.Starred) for e in node.elts
    ):
        return list(node.elts), "list_literal"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [], "string"
    return [], "unresolved"



def _triage_subprocess(tree: ast.AST, line: int) -> dict | None:
    call = _find_subprocess_call(tree, line)
    if call is None:
        return None

    scope = _enclosing_function(tree, call.lineno) or tree
    shell = _shell_value(call)

    argv_node = call.args[0] if call.args else next(
        (k.value for k in call.keywords if k.arg == "args"), None
    )

    nodes, form = (
        _argv_elements(argv_node, scope, tree)
        if argv_node is not None
        else ([], "unresolved")
    )

    elements = [
        {"expr": _unparse(n), "kind": _kind(n, scope, tree)}
        for n in nodes
    ]

    facts = {
        "call": _unparse(call.func),
        "call_line": call.lineno,
        "shell": shell,
        "argv_form": form,
        "argv_elements": elements,
    }

    # Unknown shell settings, dynamic argv, and string commands
    # must be investigated rather than automatically dismissed.
    if shell is not False or form != "list_literal" or not nodes:
        return None

    first = nodes[0]
    first_ok = (
        isinstance(first, ast.Constant)
        and isinstance(first.value, str)
        and bool(first.value)
        and not first.value.lower().endswith(WINDOWS_SCRIPT_SUFFIXES)
    ) or elements[0]["kind"] == "sys.executable"

    # A dynamic executable or dynamic argument cannot be proven safe
    # by this limited deterministic analysis.
    if not first_ok or any(
        e["kind"] == "dynamic" for e in elements
    ):
        return None

    params = [
        e["expr"] for e in elements
        if e["kind"] == "parameter"
    ]

    residual = []
    if params:
        residual.append({
            "class": "argument_injection",
            "severity": "LOW",
            "detail": (
                f"Caller-supplied value(s) {params} become argv elements. "
                "List-form execution with shell=False prevents ordinary "
                "shell metacharacters from being interpreted by a shell, "
                "but does not rule out option injection or unsafe behavior "
                "in the invoked program. Review the callers and validate "
                "arguments against the invoked program's expected inputs."
            ),
        })

        # Do not mark the whole finding as a false positive when
        # caller-controlled arguments remain.
        return _decision(
            "uncertain",
            "subprocess_shell_risk_reduced",
            (
                "The AST supports ruling out ordinary shell command "
                "injection for this call, but caller-controlled arguments "
                "leave residual risks that require review."
            ),
            claim_ruled_out="shell command injection (CWE-78)",
            facts=facts,
            residual_risks=residual,
        )

    return _decision(
        "likely_false_positive",
        "subprocess_list_argv_no_shell",
        (
            "The analyzed call uses a fixed executable, list-form arguments, "
            "and shell=False. Ordinary shell command injection is not "
            "indicated by this call. This is not a general guarantee that "
            "the invoked program or its arguments are safe."
        ),
        claim_ruled_out="shell command injection (CWE-78)",
        facts=facts,
        residual_risks=residual,
    )



def _triage_test_assert(rel_path: str, tree: ast.AST, line: int) -> dict | None:
    parts = PurePosixPath(rel_path.lower()).parts
    name = parts[-1]
    in_tests_dir = any(p in {"tests", "test"} for p in parts[:-1]) or name == "conftest.py"
    named_like_test = name.startswith("test_") or name.endswith("_test.py")
    func = _enclosing_function(tree, line)
    in_test_func = func is not None and func.name.startswith("test")

    # A file *named* test_*.py is not enough (scanner/test_runner.py is app code).
    if in_tests_dir or (named_like_test and in_test_func):
        return _decision(
            "informational",
            "test_only_assert",
            "assert in test code; stripping under -O cannot weaken a production "
            "security check.",
        )
    return None


def _load(finding: dict, target: Path):
    target = target.resolve()
    raw = Path(str(finding.get("file", "")).replace("\\", "/"))
    path = (raw if raw.is_absolute() else target / raw).resolve()
    if not path.is_relative_to(target):
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return None
    return path.relative_to(target).as_posix(), tree


def triage_finding(finding: dict, target: Path) -> dict | None:
    """Return a deterministic decision, or None to defer to the LLM."""
    if finding.get("source") != "Bandit":
        return None

    rule = str(finding.get("rule_id", "")).upper()
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0

    if rule in IMPORT_ONLY_RULES:
        return _decision(
            "informational",
            "bandit_import_only",
            "Bandit B404 flags only the import. It makes no claim about how "
            "subprocess is used; call sites are assessed via their own findings.",
        )

    if rule not in TEST_ONLY_RULES and rule != "B603":
        return None

    loaded = _load(finding, target)
    if loaded is None:
        return None
    rel_path, tree = loaded

    if rule in TEST_ONLY_RULES:
        return _triage_test_assert(rel_path, tree, line)
    return _triage_subprocess(tree, line)

# ---- LLM-discovered candidates ---------------------------------------------
IDOR_WORDS = ("idor", "access control", "authorization", "direct object")
FRONTEND_SUFFIXES = {".tsx", ".jsx", ".vue", ".svelte", ".html", ".htm", ".css"}
FRONTEND_DIRS = {"frontend", "client"}
RECORD_NAMES = {"document", "doc"}  # mirrors idor_scanner.has_ownership_check
SERVER_DEPENDENCIES = {"Depends", "Security"}
LOOPBACK = re.compile(r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", re.I)
API_PATH = re.compile(r"""['"`](?:https?://[^/'"`\s]+)?(/api/[^'"`\s]*)""")


def _owner_compares(func):
    found = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        has_record = any(
            isinstance(s, ast.Subscript)
            and isinstance(s.value, ast.Name) and s.value.id in RECORD_NAMES
            and isinstance(s.slice, ast.Constant) and s.slice.value in OWNERSHIP_FIELDS
            for s in sides
        )
        identities = [s.id for s in sides if isinstance(s, ast.Name) and s.id in IDENTITY_NAMES]
        if has_record and identities:
            found.append((node, identities[0]))
    return found


def _guard(func, compare) -> str:
    """'raises' only for `if owner != user: raise` or `if owner == user: ... else: raise`."""
    if len(compare.ops) != 1:
        return "none_detected"
    negated = isinstance(compare.ops[0], (ast.NotEq, ast.IsNot))
    positive = isinstance(compare.ops[0], (ast.Eq, ast.Is))
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        plain = test is compare
        in_or = (isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or)
                 and any(v is compare for v in test.values))
        if negated and (plain or in_or):
            branch = node.body
        elif positive and plain and not (
            len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If)
        ):
            branch = node.orelse
        else:
            continue
        if any(
            isinstance(x, ast.Raise)
            or (isinstance(x, ast.Call) and _unparse(x.func) == "abort")
            for stmt in branch for x in ast.walk(stmt)
        ):
            return "raises"
    return "none_detected"


def _identity_source(func, name: str, before: int, module_functions: dict):
    """(label, helper_name). Last binding of `name` before the comparison."""
    last = None
    for node in ast.walk(func):
        if (isinstance(node, ast.Assign) and node.lineno < before
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)):
            if last is None or node.lineno > last.lineno:
                last = node
    if last is not None:
        value = last.value
        if isinstance(value, ast.Call):
            callee = _unparse(value.func)
            if callee in module_functions:
                return f"local_call:{callee}", callee
            return f"call:{callee}", None
        return f"assigned:{type(value).__name__}", None

    a = func.args
    positional = [x.arg for x in a.posonlyargs + a.args]
    defaults = dict(zip(positional[len(positional) - len(a.defaults):], a.defaults))
    defaults.update({k.arg: d for k, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
    if name in positional + [x.arg for x in a.kwonlyargs]:
        default = defaults.get(name)
        if (isinstance(default, ast.Call) and default.args
                and _unparse(default.func) in SERVER_DEPENDENCIES):
            dep = _unparse(default.args[0])
            if dep in module_functions:
                return f"dependency:{dep}", dep
            return f"external_dependency:{dep}", None
        return f"parameter:{_unparse(default) if default is not None else 'no default'}", None
    return "unknown", None


def ownership_facts(func, module_functions: dict) -> dict:
    compares = []
    for node, identity in _owner_compares(func):
        label, helper = _identity_source(func, identity, node.lineno, module_functions)
        compares.append({
            "line": node.lineno,
            "identity": identity,
            "identity_source": label,
            "identity_helper_rejects_invalid": (
                None if helper is None
                else any(isinstance(n, ast.Raise) for n in ast.walk(module_functions[helper]))
            ),
            "guard": _guard(func, node),
        })
    compares.sort(key=lambda c: c["line"])
    return {
        "function": func.name,
        "ownership_compares": compares,
        "enforced_server_identity": any(
            c["guard"] == "raises"
            and c["identity_source"].startswith(("local_call:", "dependency:"))
            and c["identity_helper_rejects_invalid"] is True
            for c in compares
        ),
    }


def candidate_facts(candidate: dict, target: Path) -> dict | None:
    """Deterministic facts for a Python IDOR-type candidate; None if not applicable."""
    category = str(candidate.get("category", "")).lower()
    if not any(word in category for word in IDOR_WORDS):
        return None
    root = target.resolve()
    path = (root / str(candidate.get("file", "")).replace("\\", "/")).resolve()
    if path.suffix.lower() != ".py" or not path.is_relative_to(root):
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        line = int(candidate.get("line") or 0)
    except (OSError, UnicodeError, SyntaxError, ValueError, TypeError):
        return None
    func = enclosing_function(tree, line)
    if func is None:
        return None
    module_functions = {
        n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return ownership_facts(func, module_functions)


def triage_candidate(candidate: dict, target: Path) -> dict | None:
    """Deterministic decision for an LLM-discovered candidate, or None to defer."""
    category = str(candidate.get("category", "")).lower()
    rel = str(candidate.get("file", "")).replace("\\", "/")
    root = target.resolve()
    path = (root / rel).resolve()
    if not path.is_relative_to(root):
        return None
    try:
        source = path.read_text(encoding="utf-8")
        line = int(candidate.get("line") or 0)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None

    idor_like = any(word in category for word in IDOR_WORDS)
    parts = PurePosixPath(rel.lower()).parts

    if idor_like and (path.suffix.lower() in FRONTEND_SUFFIXES
                      or any(p in FRONTEND_DIRS for p in parts[:-1])):
        return _decision(
            "uncertain",
            "frontend_idor_requires_backend_review",
        (
            "Client-side code cannot enforce server-side object authorization. "
            "This candidate alone does not establish an IDOR, but the associated "
            "backend endpoint must be reviewed before the issue can be dismissed."
        ),
            followups=[{
                "action": "audit_backend_handler",
                "endpoints": sorted(set(API_PATH.findall(source))),
                "required_checks": [
                    "Identify the server-side route and handler.",
                    "Trace the authenticated identity to a trusted server-side source.",
                    "Verify ownership or access permissions for the requested object.",
                    "Test that a different user's identity cannot access the object.",
                ],
            }],
        )

    window = " ".join(source.splitlines()[max(0, line - 4): line + 3])
    url_issue = any(w in category for w in ("endpoint", "url", "hardcoded", "host"))
    secret_issue = any(w in category for w in ("secret", "credential", "password", "token", "key"))
    if url_issue and not secret_issue and LOOPBACK.search(window):
        return _decision(
            "informational",
            "hardcoded_loopback_url",
            "A loopback URL in client code is a configuration/portability concern, "
            "not a vulnerability. Endpoint paths in front-end code are not secret.",
        )

    
    facts = candidate_facts(candidate, target)

    if facts and facts["enforced_server_identity"]:
        return _decision(
            "uncertain",
            "ownership_check_detected_review_required",
            (
                "A server-side identity source and ownership guard were detected "
                "by static analysis. This heuristic does not prove that every "
                "unauthorized request is rejected, so manual review is required."
            ),
            facts=facts,
            claim_ruled_out=None,
            not_assessed=[
                "Complete control-flow enforcement of the ownership check.",
                "Soundness of identity validation and authentication.",
                "Whether every access path enforces authorization.",
            ],
        )

    return None