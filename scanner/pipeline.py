
import json
import subprocess
import sys
from pathlib import Path

from .unified_scanner import scan
from .ai_analyzer import analyze_report

SCANNER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCANNER_DIR.parent


def run_pipeline():
    print("\n=== PatchProof Security Pipeline ===\n")

    # 1. Scan the project.
    print("[1/4] Scanning source code...")
    scan_report = scan(str(PROJECT_ROOT))
    print(f"Findings: {scan_report['total_findings']}")

    # 2. Analyze findings with local AI.
    print("\n[2/4] Running AI analysis...")
    ai_report = analyze_report(SCANNER_DIR / "report.json")

    # 3. Run regression tests.
    print("\n[3/4] Running regression tests...")
    test_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_idor.py",
            "-v",
            "--tb=short",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    test_output = test_result.stdout + "\n" + test_result.stderr
    print(test_output)

    # 4. Save one consolidated report.
    print("\n[4/4] Generating consolidated report...")

    final_report = {
        "project": PROJECT_ROOT.name,
        "scanner_findings": scan_report["findings"],
        "ai_analysis": ai_report["results"],
        "regression_tests": {
            "passed": test_result.returncode == 0,
            "exit_code": test_result.returncode,
            "output": test_output[-12000:],
        },
        "verification_note": (
            "Tests verify the known demo vulnerability and fixed version; "
            "they do not verify arbitrary AI-generated patches."
        ),
    }

    output_path = SCANNER_DIR / "final-report.json"
    output_path.write_text(
        json.dumps(final_report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\nPipeline complete. Report: {output_path}")
    print(
        "Regression tests:",
        "PASSED" if test_result.returncode == 0 else "FAILED",
    )


if __name__ == "__main__":
    try:
        run_pipeline()
    except Exception as exc:
        raise SystemExit(
            f"Pipeline failed: {type(exc).__name__}: {exc}"
        ) from exc
