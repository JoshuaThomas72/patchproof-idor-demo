
import json
import subprocess
import sys
from pathlib import Path

from .idor_scanner import scan_project

def run_bandit(project_path: Path) -> dict:
    """Run Bandit only on top-level application Python files."""
    target_files = [
        project_path / "main.py",
        project_path / "main_vulnerable.py",
        project_path / "poc.py",
    ]

    target_files = [str(path) for path in target_files if path.is_file()]

    if not target_files:
        return {"findings": [], "error": "No target Python files found."}

    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "bandit",
                "-f", "json",
                *target_files,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"findings": [], "error": str(exc)}

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "findings": [],
            "error": result.stderr.strip() or "Could not parse Bandit output.",
        }

    findings = []
    for item in report.get("results", []):
        findings.append({
            "source": "Bandit",
            "category": item.get("test_id", "Unknown"),
            "severity": item.get("issue_severity", "UNKNOWN"),
            "confidence": item.get("issue_confidence", "UNKNOWN"),
            "file": item.get("filename", ""),
            "line": item.get("line_number", 0),
            "message": item.get("issue_text", ""),
        })

    return {"findings": findings, "error": None}

def scan(project_path: str) -> dict:
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

    report = {
        "target": str(root),
        "total_findings": len(findings),
        "findings": findings,
        "errors": (
            [bandit_report["error"]]
            if bandit_report["error"]
            else []
        ),
    }

    output_file = Path(__file__).with_name("report.json")
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
