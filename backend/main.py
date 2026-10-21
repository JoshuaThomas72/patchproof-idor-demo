
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

            report = scan(str(project_root))

            return {
                "filename": file.filename,
                "total_findings": report.get("total_findings", 0),
                "findings": report.get("findings", []),
                "errors": report.get("errors", []),
                "test_verification": report.get("test_verification"),
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
