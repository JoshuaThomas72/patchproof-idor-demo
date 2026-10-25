# PatchProof frontend/backend/scanner integration patch

This patch overlays the following files onto the existing PatchProof repository:

- `backend/main.py`
- `scanner/ai_analyzer.py`
- `scanner/unified_scanner.py`
- `frontend/src/App.tsx`
- `frontend/src/types.ts`
- `frontend/src/components/ScanUploadModal.tsx`
- `frontend/src/components/FindingsTable.tsx`
- `frontend/src/components/VerificationView.tsx`
- `frontend/src/components/FindingDetailModal.tsx`
- `frontend/.env.example`
- `scanner/__init__.py`

Do not replace the rest of your scanner modules; keep `classify.py`, `context.py`, `idor_scanner.py`, `triage.py`, and the other existing files in `scanner/`.

## What this patch changes

1. ZIP scans run the static scanner, then invoke the existing AI analysis/consolidation pipeline.
2. Each upload writes its intermediate scan and AI reports to that upload's temporary workspace instead of shared `scanner/report.json` and `scanner/ai-report.json` files.
3. If Ollama or Bandit is unavailable, the API returns available static findings and an explicit warning rather than losing the entire scan.
4. The frontend maps consolidated classifications, evidence, suggested fixes, and severity into the existing finding UI.
5. The dashboard labels uploaded results as live scan results, not demo data.
6. Uploaded-project tests are **not executed**. The UI no longer fabricates passing test results or claims that remediation was applied.

## Install / run on Windows PowerShell

From the repository root (the directory containing `backend`, `scanner`, and `frontend`):

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-integration.txt
ollama pull qwen3.5:4b
python -m uvicorn backend.main:app --reload --port 8765
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend defaults to `http://127.0.0.1:8765` for the backend. To override it, set `VITE_API_BASE_URL` in `frontend/.env.local`, for example:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8765
```

## Verification performed while preparing this patch

- Python syntax compilation passed for the modified backend and scanner modules.
- Frontend TypeScript check passed with `tsc --noEmit`.
- FastAPI ZIP-upload smoke test returned HTTP 200 and a finding when the optional `bandit` and `ollama` packages were absent; the response correctly reported AI analysis as unavailable and stated that uploaded tests were not executed.
- A production Vite build could not be run in this Linux workspace because the uploaded `node_modules` lacked platform-specific optional native dependencies. Run `npm install` on your Windows machine and then `npm run build` locally.

## Safety note

The endpoint performs static scanning and AI analysis only. It does not run code or pytest from an uploaded ZIP. A separate, sandboxed verification service would be needed before executing untrusted project tests.
