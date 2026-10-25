
import ast
from pathlib import Path
import os

DOCUMENT_LOOKUPS = {
    "get_document",
    "get",
}

OWNERSHIP_FIELDS = {"owner", "owner_id", "user_id"}
IDENTITY_NAMES = {"user", "current_user", "owner"}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    ".venv-1",
    "venv",
    "env",
    "site-packages",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
}

def has_ownership_check(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Look for an explicit ownership comparison in a function."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare):
            continue

        sides = [child.left, *child.comparators]

        for side in sides:
            if not isinstance(side, ast.Subscript):
                continue

            if not isinstance(side.value, ast.Name):
                continue

            if side.value.id not in {"document", "doc"}:
                continue

            if not isinstance(side.slice, ast.Constant):
                continue

            if side.slice.value not in OWNERSHIP_FIELDS:
                continue

            # Example: document["owner"] != user
            if any(
                isinstance(other, ast.Name)
                and other.id in IDENTITY_NAMES
                for other in sides
            ):
                return True

    return False


def scan_file(file_path: Path) -> list[dict]:
    findings = []

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        return [{
            "file": str(file_path),
            "line": 1,
            "severity": "ERROR",
            "message": f"Could not analyze file: {exc}",
        }]

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        source_segment = ast.get_source_segment(source, node) or ""
        lower_source = source_segment.lower()

        looks_like_document_lookup = (
            "document" in lower_source
            and (
                "get_document" in lower_source
                or "document_id" in lower_source
                or "documents.get" in lower_source
            )
        )

        if not looks_like_document_lookup:
            continue

        if has_ownership_check(node):
            continue

        findings.append({
            "file": str(file_path),
            "line": node.lineno,
            "severity": "WARNING",
            "message": (
                f"Function '{node.name}' may retrieve a document "
                "without an explicit ownership comparison. "
                "Manual review required."
            ),
        })

    return findings


def scan_project(project_path: str) -> list[dict]:
    root = Path(project_path).resolve()
    findings = []

    for current, dirs, files in os.walk(root):
        # Prune excluded folders before scanning their contents
        dirs[:] = [
            d for d in dirs
            if d.lower() not in EXCLUDED_DIRS
            and not d.lower().startswith(".venv")
            and not d.lower().startswith("venv-")
        ]

        for filename in files:
            if filename.endswith(".py"):
                file_path = Path(current) / filename
                if file_path.resolve() == Path(__file__).resolve():
                    continue

                findings.extend(scan_file(file_path))

    return findings

if __name__ == "__main__":
    target = input("Enter the target project folder path: ").strip().strip('"')

    try:
        results = scan_project(target)

        if not results:
            print("\nNo suspicious document access patterns found.")
        else:
            print(f"\nFound {len(results)} potential issue(s):\n")
            for item in results:
                print(
                    f"[{item['severity']}] "
                    f"{item['file']}:{item['line']}"
                )
                print(f"  {item['message']}\n")

    except (NotADirectoryError, PermissionError) as exc:
        print(f"Scan failed: {exc}")
