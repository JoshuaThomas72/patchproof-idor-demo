from pathlib import Path
import io
import tokenize

import pytest

from scanner.idor_scanner import scan_project

ROOT = Path(__file__).resolve().parent.parent


from scanner.context import strip_python_comments
from scanner.triage import triage_candidate


def _strip_comments(src: str) -> str:
    tokens = [
        t for t in tokenize.generate_tokens(io.StringIO(src).readline)
        if t.type != tokenize.COMMENT
    ]
    return tokenize.untokenize(tokens)

def test_detection_does_not_depend_on_comments(tmp_path):
    src = (ROOT / "main_vulnerable.py").read_text(encoding="utf-8")
    stripped, ok = strip_python_comments(src)
    assert ok
    (tmp_path / "main_vulnerable.py").write_text(stripped, encoding="utf-8")
    assert "main_vulnerable.py" in _files(scan_project(str(tmp_path)))


def _line_containing(path: Path, needle: str) -> int:
    text = path.read_text(encoding="utf-8").splitlines()
    return next(i for i, row in enumerate(text, 1) if needle in row)


def test_real_main_py_ownership_claim_is_ruled_out():
    line = _line_containing(ROOT / "main.py", 'document["owner"] != user')
    cand = {"file": "main.py", "line": line, "category": "Broken Access Control (IDOR)"}
    assert triage_candidate(cand, ROOT)["classification"] == "uncertain"


def test_real_main_vulnerable_is_never_ruled_out():
    line = _line_containing(ROOT / "main_vulnerable.py", "DOCUMENTS.get(document_id)")
    cand = {"file": "main_vulnerable.py", "line": line, "category": "Broken Access Control (IDOR)"}
    assert triage_candidate(cand, ROOT) is None


NOOP_COMPARISON = '''
def get_document(document_id, user):
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        pass
    return document
'''

CLIENT_SUPPLIED_IDENTITY = '''
from fastapi import Header, HTTPException

def get_document(document_id: str, user: str = Header(default="")):
    document = DOCUMENTS.get(document_id)
    if document["owner"] != user:
        raise HTTPException(status_code=404)
    return document
'''


@pytest.mark.xfail(strict=True, reason="idor_scanner accepts an owner comparison that has no effect")
def test_scanner_gap_noop_comparison(tmp_path):
    (tmp_path / "app.py").write_text(NOOP_COMPARISON, encoding="utf-8")
    assert "app.py" in _files(scan_project(str(tmp_path)))


@pytest.mark.xfail(strict=True, reason="idor_scanner does not check where the compared identity comes from")
def test_scanner_gap_client_supplied_identity(tmp_path):
    (tmp_path / "app.py").write_text(CLIENT_SUPPLIED_IDENTITY, encoding="utf-8")
    assert "app.py" in _files(scan_project(str(tmp_path)))

@pytest.fixture(scope="module")
def project_findings():
    return scan_project(str(ROOT))


def _files(findings):
    return {Path(f["file"]).name for f in findings}


def test_intentional_idor_is_detected(project_findings):
    assert "main_vulnerable.py" in _files(project_findings)


def test_ownership_checked_endpoint_is_not_flagged(project_findings):
    assert "main.py" not in _files(project_findings)


def test_detection_does_not_depend_on_comments(tmp_path):
    src = (ROOT / "main_vulnerable.py").read_text(encoding="utf-8")
    (tmp_path / "main_vulnerable.py").write_text(_strip_comments(src), encoding="utf-8")
    findings = scan_project(str(tmp_path))
    assert "main_vulnerable.py" in _files(findings)