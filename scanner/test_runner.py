
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(__file__).resolve().parent / "test-results.json"


def run_tests():
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_idor.py",
        "-v",
        "--tb=short",
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    output = result.stdout + "\n" + result.stderr

    report = {
        "test_file": "tests/test_idor.py",
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "output": output[-12000:],
    }

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(output)
    print(f"\nTest report saved to: {OUTPUT}")
    print("Status:", "PASSED" if report["passed"] else "FAILED")

    return report


if __name__ == "__main__":
    run_tests()
