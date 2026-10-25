
import json
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from scanner.unified_scanner import scan

app = FastAPI(title="PatchProof API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_FILES = 2000


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PatchProof API"}


@app.post("/api/scan")
def run_local_scan():
    """Scan the PatchProof repository itself."""
    try:
        root = Path(__file__).resolve().parent.parent
        return scan(str(root))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/scan-zip")
async def scan_zip(file: UploadFile = File(...)):
    """Safely extract and scan an uploaded Python source ZIP."""
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file.")

    archive_data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(archive_data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="ZIP exceeds 25 MB limit.")

    try:
        with tempfile.TemporaryDirectory(prefix="patchproof-") as temp_dir:
            temp_root = Path(temp_dir).resolve()
            archive_path = temp_root / "upload.zip"
            extract_root = temp_root / "project"
            extract_root.mkdir()
            archive_path.write_bytes(archive_data)

            try:
                with zipfile.ZipFile(archive_path) as archive:
                    entries = archive.infolist()

                    if len(entries) > MAX_FILES:
                        raise HTTPException(
                            status_code=413,
                            detail="ZIP contains too many files.",
                        )

                    total_size = sum(entry.file_size for entry in entries)
                    if total_size > MAX_EXTRACTED_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="Extracted ZIP exceeds 100 MB limit.",
                        )

                    for entry in entries:
                        name = entry.filename.replace("\\", "/")
                        path = PurePosixPath(name)

                        if (
                            path.is_absolute()
                            or ".." in path.parts
                            or (path.parts and ":" in path.parts[0])
                        ):
                            raise HTTPException(
                                status_code=400,
                                detail="ZIP contains an unsafe path.",
                            )

                        if entry.file_size > 0 and entry.compress_size == 0:
                            raise HTTPException(
                                status_code=400,
                                detail="ZIP contains an invalid compressed entry.",
                            )

                        if entry.compress_size and (
                            entry.file_size / entry.compress_size > 200
                        ):
                            raise HTTPException(
                                status_code=400,
                                detail="ZIP compression ratio is too high.",
                            )

                    for entry in entries:
                        name = entry.filename.replace("\\", "/")
                        destination = (extract_root / name).resolve()

                        if not destination.is_relative_to(extract_root):
                            raise HTTPException(
                                status_code=400,
                                detail="ZIP contains an unsafe path.",
                            )

                        if entry.is_dir():
                            destination.mkdir(parents=True, exist_ok=True)
                            continue

                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(entry) as source, destination.open("wb") as target:
                            shutil.copyfileobj(source, target)

            except zipfile.BadZipFile as exc:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded file is not a valid ZIP archive.",
                ) from exc

            # Handle ZIPs containing one top-level project directory.
            children = list(extract_root.iterdir())
            project_root = (
                children[0]
                if len(children) == 1 and children[0].is_dir()
                else extract_root
            )

            if not any(project_root.rglob("*.py")):
                raise HTTPException(
                    status_code=400,
                    detail="ZIP contains no Python source files.",
                )

            # Keep each scan's reports inside its temporary workspace. This avoids
            # cross-request overwrites of scanner/report.json and ai-report.json.
            scanner_report_path = temp_root / "scan-report.json"
            ai_report_path = temp_root / "ai-report.json"
            report = scan(str(project_root), output_path=scanner_report_path)

            errors = list(report.get("errors", []))
            ai_report = None
            ai_analysis_status = "unavailable"
            try:
                # Import lazily so the API can still serve static findings if the
                # optional Ollama Python client is not installed.
                from scanner.ai_analyzer import analyze_report

                ai_report = analyze_report(
                    scanner_report_path,
                    output_path=ai_report_path,
                )
                ai_analysis_status = "completed"
            except Exception as exc:
                # Preserve static scanner findings if the local model is unavailable.
                errors.append(
                    f"AI analysis unavailable: {type(exc).__name__}: {exc}"
                )

            target_findings = (
                ai_report.get("consolidated_findings", [])
                if ai_report
                else report.get("findings", [])
            )

            # Convert absolute paths into project-relative paths for the UI.
            normalized_findings = []
            for item in target_findings:
                finding = dict(item)
                raw_file = finding.get("file", "")
                if raw_file:
                    try:
                        candidate_path = Path(raw_file)
                        if not candidate_path.is_absolute():
                            candidate_path = project_root / candidate_path
                        finding["file"] = str(
                            candidate_path.resolve().relative_to(project_root)
                        )
                    except (ValueError, OSError):
                        finding["file"] = str(raw_file)
                if ai_report and ai_report.get("model"):
                    finding["ai_model"] = ai_report["model"]
                normalized_findings.append(finding)

            return {
                "filename": file.filename,
                "target": project_root.name,
                "total_findings": len(normalized_findings),
                "findings": normalized_findings,
                "raw_findings": report.get("findings", []),
                "ai_analysis_status": ai_analysis_status,
                "ai_summary": ai_report.get("summary") if ai_report else None,
                "ai_model": ai_report.get("model") if ai_report else None,
                "errors": errors,
                # Uploaded projects are analyzed statically; we do not execute
                # untrusted test suites from uploaded archives.
                "test_verification": None,
                "tests_executed": False,
            }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {type(exc).__name__}: {exc}",
        ) from exc


@app.get("/api/reports/latest")
def latest_report():
    path = Path(__file__).resolve().parent.parent / "scanner" / "report.json"

    if not path.exists():
        raise HTTPException(status_code=404, detail="No report found.")

    return json.loads(path.read_text(encoding="utf-8"))
