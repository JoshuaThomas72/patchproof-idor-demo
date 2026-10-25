
import json
import subprocess
import sys
from pathlib import Path

from .idor_scanner import scan_project
from .test_runner import run_tests


BANDIT_RULES = {
    "B105": ("Hardcoded Secrets", "CWE-798"),
    "B106": ("Hardcoded Secrets", "CWE-798"),
    "B107": ("Hardcoded Secrets", "CWE-798"),
    "B301": ("Insecure Deserialization", "CWE-502"),
    "B303": ("Weak Cryptography", "CWE-327"),
    "B324": ("Weak Cryptography", "CWE-327"),
    "B307": ("Code Injection", "CWE-95"),
    "B602": ("Command Injection", "CWE-78"),
    "B605": ("Command Injection", "CWE-78"),
    "B608": ("SQL Injection", "CWE-89"),
    "B310": ("Potential SSRF / Unsafe URL Access", "CWE-918"),
    "B108": ("Insecure Temporary File", "CWE-377"),
    "B506": ("Unsafe YAML Loading", "CWE-502"),
}


def classify_bandit_rule(test_id: str) -> tuple[str, str]:
    """Return a display category and CWE for known Bandit rules."""
    if test_id in BANDIT_RULES:
        return BANDIT_RULES[test_id]

    if test_id in {"B102", "B307"}:
        return ("Code Injection", "CWE-94")

    if test_id.startswith("B6"):
        return ("Process / Command Security", "CWE-78")

    if test_id.startswith("B3"):
        return ("Cryptography / Deserialization", "CWE-327")

    return ("Python Security", "Needs review")


def run_bandit(project_path: Path) -> dict:
    """Scan Python files recursively, excluding dependencies and build output."""
    if not project_path.is_dir():
        return {
            "findings": [],
            "error": f"Target directory does not exist: {project_path}",
        }

    excluded = (
        "*/.venv/*,*/.venv-1/*,*/venv/*,"
        "*/.venv/**,*/.venv-1/**,*/venv/**,"
        "*/node_modules/*,*/.git/*,*/__pycache__/*,"
        "*/dist/*,*/build/*,*/site-packages/*"
    )

    try:
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
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"findings": [], "error": str(exc)}

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "findings": [],
            "error": result.stderr.strip()
            or "Could not parse Bandit output.",
        }

    findings = []

    for item in report.get("results", []):
        test_id = item.get("test_id", "Unknown")
        category, cwe = classify_bandit_rule(test_id)

        try:
            file_path = Path(item.get("filename", ""))
            relative_path = str(file_path.resolve().relative_to(
                project_path.resolve()
            ))
        except (ValueError, OSError):
            relative_path = item.get("filename", "")

        findings.append({
            "source": "Bandit",
            "rule_id": test_id,
            "category": category,
            "cwe": cwe,
            "severity": item.get("issue_severity", "UNKNOWN"),
            "confidence": item.get("issue_confidence", "UNKNOWN"),
            "file": relative_path,
            "line": item.get("line_number", 0),
            "message": item.get("issue_text", ""),
            "code": item.get("code", ""),
        })

    return {"findings": findings, "error": None}


def scan(project_path: str, output_path: str | Path | None = None) -> dict:
    root = Path(project_path).resolve()

    # Run the custom IDOR scanner.
    idor_findings = scan_project(str(root))

    findings = [
        {
            "source": "PatchProof-IDOR",
            "category": "Potential IDOR",
            "severity": item.get("severity", "WARNING"),
            "confidence": "MEDIUM",
            "file": item.get("file", ""),
            "line": item.get("line", 0),
            "message": item.get("message", ""),
        }
        for item in idor_findings
    ]

    # Run Bandit and combine results.
    bandit_report = run_bandit(root)
    findings.extend(bandit_report["findings"])

    # Run regression tests only for the PatchProof demo project.
    test_report = None

    if root == Path(__file__).resolve().parent.parent:
        try:
            test_report = run_tests()
        except (OSError, subprocess.TimeoutExpired) as exc:
            test_report = {
                "passed": False,
                "error": str(exc),
            }

    report = {
        "target": str(root),
        "total_findings": len(findings),
        "findings": findings,
        "test_verification": test_report,
        "errors": (
            [bandit_report["error"]]
            if bandit_report["error"]
            else []
        ),
    }

    output_file = (
        Path(output_path).resolve()
        if output_path is not None
        else Path(__file__).with_name("report.json")
    )
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return report


if __name__ == "__main__":
    target = input("Enter target project folder path: ").strip().strip('"')

    try:
        report = scan(target)
        print(f"\nScan complete. Total findings: {report['total_findings']}")

        for item in report["findings"]:
            print(
                f"[{item['severity']}] {item['source']} | "
                f"{item['file']}:{item['line']}"
            )
            print(f"  {item['message']}\n")

        if report["errors"]:
            print("Warnings/errors:", report["errors"])

        print(f"JSON report saved to: {Path(__file__).with_name('report.json')}")

    except (NotADirectoryError, PermissionError) as exc:
        print(f"Scan failed: {exc}")
