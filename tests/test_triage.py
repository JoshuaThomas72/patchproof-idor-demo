from pathlib import Path

from scanner.ai_analyzer import build_consolidated_findings
from scanner.triage import triage_finding
from scanner.triage import candidate_facts, triage_candidate, triage_finding
import ast
from pathlib import Path

from scanner.triage import _triage_subprocess


UNIFIED = '''
import subprocess
import sys


def run_bandit(project_path):
    excluded = (
        "*/.venv/*,"
        "*/node_modules/*"
    )
    result = subprocess.run(
        [
            sys.executable, "-m", "bandit",
            "-r", str(project_path),
            "-x", excluded,
            "-f", "json",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result
'''

def _triage_source(source: str) -> dict | None:
    tree = ast.parse(source)

    call = next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and ast.unparse(node.func).startswith("subprocess.")
        ),
        None,
    )

    if call is None:
        return None

    return _triage_subprocess(tree, call.lineno)


def test_fixed_local_argv_can_rule_out_shell_injection():
    source = """
import subprocess
import sys

def run():
    command = [sys.executable, "-m", "pytest", "-q"]
    subprocess.run(command, shell=False)
"""
    result = _triage_source(source)

    assert result is not None
    assert result["classification"] == "likely_false_positive"
    assert result["rule"] == "subprocess_list_argv_no_shell"


def test_dynamic_command_is_not_dismissed():
    source = """
import subprocess

def run(command):
    subprocess.run(command, shell=False)
"""
    result = _triage_source(source)

    assert result is None


def test_shell_true_is_not_dismissed():
    source = """
import subprocess

def run(user_input):
    subprocess.run(["echo", user_input], shell=True)
"""
    result = _triage_source(source)

    assert result is None

def _write(root: Path, rel: str, source: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return rel


def _line_of(source: str, needle: str) -> int:
    return next(i for i, t in enumerate(source.splitlines(), 1) if needle in t)


def _bandit(rule: str, rel: str, line: int) -> dict:
    return {"source": "Bandit", "rule_id": rule, "file": rel, "line": line}


# ---- Issue A -------------------------------------------------------------
def test_list_argv_without_shell_rules_out_shell_injection(tmp_path):
    rel = _write(tmp_path, "scanner/unified_scanner.py", UNIFIED)
    line = _line_of(UNIFIED, "subprocess.run(")
    result = triage_finding(_bandit("B603", rel, line), tmp_path)

    assert result["classification"] == "uncertain"
    assert result["facts"]["shell"] is False
    assert not [e for e in result["facts"]["argv_elements"] if e["kind"] == "dynamic"]
    assert [r["class"] for r in result["residual_risks"]] == ["argument_injection"]


def test_shell_true_is_not_ruled_out(tmp_path):
    src = "import subprocess\n\ndef f(n):\n    subprocess.run(['ls', n], shell=True)\n"
    rel = _write(tmp_path, "a.py", src)
    assert triage_finding(_bandit("B603", rel, 4), tmp_path) is None


def test_string_command_is_not_ruled_out(tmp_path):
    src = "import subprocess\n\ndef f(p):\n    subprocess.run(f'tool {p}')\n"
    rel = _write(tmp_path, "a.py", src)
    assert triage_finding(_bandit("B603", rel, 4), tmp_path) is None


def test_untracked_argument_is_not_ruled_out(tmp_path):
    src = (
        "import subprocess\n\n"
        "def f(request):\n"
        "    arg = request.args['x']\n"
        "    subprocess.run(['tool', arg])\n"
    )
    rel = _write(tmp_path, "a.py", src)
    assert triage_finding(_bandit("B603", rel, 5), tmp_path) is None


def test_windows_batch_file_is_not_ruled_out(tmp_path):
    src = "import subprocess\n\ndef f(x):\n    subprocess.run(['run.bat', x])\n"
    rel = _write(tmp_path, "a.py", src)
    assert triage_finding(_bandit("B603", rel, 4), tmp_path) is None


# ---- Issue B -------------------------------------------------------------
def test_b404_is_informational(tmp_path):
    result = triage_finding(_bandit("B404", "x.py", 3), tmp_path)
    assert result["classification"] == "informational"


def test_assert_in_tests_dir_is_informational(tmp_path):
    rel = _write(tmp_path, "tests/test_x.py", "def test_a():\n    assert 1 == 1\n")
    result = triage_finding(_bandit("B101", rel, 2), tmp_path)
    assert result["classification"] == "informational"


def test_assert_in_production_code_is_not_triaged(tmp_path):
    rel = _write(tmp_path, "app.py", "def check(u):\n    assert u.is_admin\n")
    assert triage_finding(_bandit("B101", rel, 2), tmp_path) is None


def test_assert_in_test_named_app_module_is_not_triaged(tmp_path):
    # scanner/test_runner.py is application code despite its name.
    rel = _write(tmp_path, "scanner/test_runner.py", "def run():\n    assert True\n")
    assert triage_finding(_bandit("B101", rel, 2), tmp_path) is None


def test_non_bandit_findings_are_never_triaged(tmp_path):
    finding = {"source": "PatchProof-IDOR", "file": "main_vulnerable.py", "line": 40}
    assert triage_finding(finding, tmp_path) is None


# ---- Issue E -------------------------------------------------------------
def _triaged_b101(line: int) -> dict:
    return {
        "finding": {
            "source": "Bandit", "rule_id": "B101", "category": "Python Security",
            "severity": "LOW", "file": "tests\\test_idor.py", "line": line,
            "message": "assert",
        },
        "triage": {"classification": "informational"},
    }


def test_bandit_findings_merge_only_when_adjacent(tmp_path):
    results = [_triaged_b101(n) for n in (26, 27, 29, 40, 41)]
    groups = build_consolidated_findings({"target": str(tmp_path)}, results, [])

    assert sorted(g["lines"] for g in groups) == [[26, 27, 29], [40, 41]]
    assert sum(g["duplicate_count"] for g in groups) == 5  # nothing dropped
    assert {g["classification"] for g in groups} == {"informational"}

MAIN_SAFE = '''
from fastapi import FastAPI, Header, HTTPException
app = FastAPI()
TOKENS = {"alice-token": "alice"}
DOCUMENTS = {"doc-101": {"owner": "alice"}}

def signed_in_user(authorization: str | None = Header(default=None)):
    user = TOKENS.get((authorization or "").removeprefix("Bearer ").strip())
    if not user:
        raise HTTPException(status_code=401)
    return user

@app.get("/documents/{document_id}")
def get_document(document_id: str, user: str = Header(default=""),
                 authorization: str | None = Header(default=None)):
    user = signed_in_user(authorization)
    document = DOCUMENTS.get(document_id)
    if not document:
        raise HTTPException(status_code=404)
    if document["owner"] != user:
        raise HTTPException(status_code=404)
    return document
'''

SPOOFED = '''
from fastapi import FastAPI, Header, HTTPException
app = FastAPI()
DOCUMENTS = {}

@app.get("/documents/{document_id}")
def get_document(document_id: str, user: str = Header(default="")):
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        raise HTTPException(status_code=404)
    return document
'''

NOOP = '''
DOCUMENTS = {}

def get_document(document_id: str, user: str):
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        pass
    return document
'''

NO_CHECK = '''
DOCUMENTS = {}

def get_document(document_id: str, user: str):
    document = DOCUMENTS.get(document_id)
    return document
'''

DEPENDS = '''
from fastapi import Depends, FastAPI, Header, HTTPException
app = FastAPI()
DOCUMENTS = {}

def signed_in_user(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return "alice"

@app.get("/documents/{document_id}")
def get_document(document_id: str, user: str = Depends(signed_in_user)):
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        raise HTTPException(status_code=404)
    return document
'''

UNSAFE_HELPER = '''
from fastapi import FastAPI, Header, HTTPException
app = FastAPI()
DOCUMENTS = {}

def current_user(x_user: str = Header(default="")):
    return x_user

@app.get("/documents/{document_id}")
def get_document(document_id: str, x_user: str = Header(default="")):
    user = current_user(x_user)
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        raise HTTPException(status_code=404)
    return document
'''

TSX = "const r = await fetch('http://127.0.0.1:8765/api/scan-zip', { method: 'POST' });\n"
IDOR = "Broken Access Control (IDOR)"


def _cand(rel: str, line: int, category: str = IDOR) -> dict:
    return {"file": rel, "line": line, "category": category}


# ---- Issue C -------------------------------------------------------------
def test_enforced_owner_check_with_server_identity_is_ruled_out(tmp_path):
    rel = _write(tmp_path, "main.py", MAIN_SAFE)
    line = _line_of(MAIN_SAFE, 'if document["owner"] != user')
    result = triage_candidate(_cand(rel, line), tmp_path)
    compare = result["facts"]["ownership_compares"][0]
    assert result["classification"] == "uncertain"
    assert compare["identity_source"] == "local_call:signed_in_user"
    assert compare["guard"] == "raises"
    assert result["not_assessed"]


def test_dependency_injected_identity_is_ruled_out(tmp_path):
    rel = _write(tmp_path, "main.py", DEPENDS)
    line = _line_of(DEPENDS, 'if document["owner"] != user')
    assert triage_candidate(_cand(rel, line), tmp_path)["classification"] == "uncertain"


def test_header_supplied_identity_is_not_ruled_out(tmp_path):
    rel = _write(tmp_path, "main.py", SPOOFED)
    line = _line_of(SPOOFED, 'if document["owner"] != user')
    assert triage_candidate(_cand(rel, line), tmp_path) is None
    facts = candidate_facts(_cand(rel, line), tmp_path)
    assert facts["ownership_compares"][0]["identity_source"].startswith("parameter:Header")


def test_helper_that_never_rejects_is_not_ruled_out(tmp_path):
    rel = _write(tmp_path, "main.py", UNSAFE_HELPER)
    line = _line_of(UNSAFE_HELPER, 'if document["owner"] != user')
    assert triage_candidate(_cand(rel, line), tmp_path) is None


def test_noop_comparison_is_not_ruled_out(tmp_path):
    rel = _write(tmp_path, "main.py", NOOP)
    line = _line_of(NOOP, 'if document["owner"] != user')
    assert triage_candidate(_cand(rel, line), tmp_path) is None
    assert candidate_facts(_cand(rel, line), tmp_path)["ownership_compares"][0]["guard"] == "none_detected"


def test_missing_owner_check_is_not_ruled_out(tmp_path):
    rel = _write(tmp_path, "main_vulnerable.py", NO_CHECK)
    line = _line_of(NO_CHECK, "DOCUMENTS.get")
    assert triage_candidate(_cand(rel, line), tmp_path) is None
    assert candidate_facts(_cand(rel, line), tmp_path)["ownership_compares"] == []


# ---- Issue D -------------------------------------------------------------
def test_frontend_idor_candidate_is_ruled_out_with_followup(tmp_path):
    rel = _write(tmp_path, "frontend/src/components/Upload.tsx", TSX)
    result = triage_candidate(_cand(rel, 1), tmp_path)
    assert result["classification"] == "uncertain"
    assert result["followups"][0]["endpoints"] == ["/api/scan-zip"]


def test_loopback_endpoint_is_informational(tmp_path):
    rel = _write(tmp_path, "frontend/src/components/Upload.tsx", TSX)
    result = triage_candidate(_cand(rel, 1, "Hardcoded Internal Endpoint"), tmp_path)
    assert result["classification"] == "informational"


def test_other_frontend_classes_are_never_ruled_out(tmp_path):
    rel = _write(tmp_path, "frontend/src/components/Upload.tsx", TSX)
    assert triage_candidate(_cand(rel, 1, "Hardcoded Credentials"), tmp_path) is None
    assert triage_candidate(_cand(rel, 1, "Cross-Site Scripting (XSS)"), tmp_path) is None