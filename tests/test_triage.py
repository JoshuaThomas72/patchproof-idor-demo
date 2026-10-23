from pathlib import Path

from scanner.ai_analyzer import build_consolidated_findings
from scanner.triage import triage_finding

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

    assert result["classification"] == "likely_false_positive"
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