import io
import tokenize
from pathlib import Path

import pytest

from scanner.idor_scanner import scan_project

ROOT = Path(__file__).resolve().parent.parent


def _strip_comments(src: str) -> str:
    tokens = [
        t for t in tokenize.generate_tokens(io.StringIO(src).readline)
        if t.type != tokenize.COMMENT
    ]
    return tokenize.untokenize(tokens)


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