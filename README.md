# PatchProof --- AI-Assisted Source-Code Vulnerability Scanner

> A local-first web application combining static security checks, custom
> IDOR detection, and local LLM-assisted review to help developers
> investigate potential vulnerabilities in source code.

## 1. Project Overview

PatchProof is a cybersecurity project for authorized source-code review,
secure-coding education, and controlled demonstrations. A developer
uploads a ZIP archive through a React web interface. A FastAPI backend
validates the archive, runs configured scanner components, consolidates
available findings, and returns a structured report for the frontend
dashboard.

PatchProof is a decision-support tool, not a replacement for a
professional security audit. Automated findings may be false positives
or false negatives and should be reviewed against source evidence and
reproducible tests.

### At a glance

  -----------------------------------------------------------------------
  Item                                Description
  ----------------------------------- -----------------------------------
  Project                             PatchProof

  Purpose                             AI-assisted source-code security
                                      analysis

  Backend                             Python, FastAPI, Uvicorn

  Frontend                            React, TypeScript, Vite

  Static analysis                     Bandit plus custom scanner rules

  Primary custom focus                Insecure Direct Object Reference
                                      (IDOR) and authorization patterns

  AI analysis                         Local Ollama model; configured
                                      model has been `qwen3.5:4b`

  API default                         `http://127.0.0.1:8765`

  Testing                             Pytest

  Intended use                        Local, authorized testing and
                                      education
  -----------------------------------------------------------------------

## 2. Problem Statement

Security defects can hide in routes, helper functions, access-control
decisions, and interactions between frontend and backend code. A scanner
based on one technique may miss context-sensitive issues or report
benign patterns as vulnerabilities.

IDOR is a key example: an endpoint may accept a document identifier from
a client, but the security question is whether the server verifies that
the authenticated user is allowed to access that specific document. The
presence of an identifier alone does not prove a vulnerability;
identity, ownership checks, control flow, and endpoint behavior matter.

PatchProof combines repeatable static checks with AI-assisted analysis
to surface candidates and explain why they may need attention.

## 3. Objectives

-   Provide a simple web interface for uploading a source-code ZIP.
-   Orchestrate multiple security-analysis components through one
    backend.
-   Detect suspicious code patterns, particularly IDOR and missing
    object-level authorization.
-   Use local AI-assisted review to help explain or triage findings
    where available.
-   Show finding locations, categories, severity, classifications,
    evidence, and remediation guidance when supplied by the scanner.
-   Distinguish uncertain findings from test-backed results.
-   Support repeatable regression testing against known vulnerable and
    secure examples.
-   Establish a foundation for evaluating precision, recall, false
    positives, and false negatives.

## 4. Key Features

### ZIP upload and scanning

The frontend sends a selected archive to the backend through
`POST /api/scan-zip`. The backend is responsible for enforcing upload
and archive constraints before scanning.

### Multiple analysis sources

The scanner integrates custom IDOR-oriented checks and Bandit results.
AI-assisted analysis can add context or candidate findings when the
local model is available.

### Local LLM support

The project has used Ollama with `qwen3.5:4b`. Local inference can
reduce reliance on a hosted model API, but does not guarantee
correctness or automatically make all processing private; configuration,
logs, uploaded code, and reports still need care.

### Dashboard and finding details

The React/TypeScript frontend is intended to display scan progress,
summary counts, and finding details. The precise fields and
report/export capabilities depend on the current branch.

### Regression tests

Automated tests cover IDOR detection, triage behavior, and scanner
regressions. Changes to detection rules, AI prompts, report
normalization, or integration should be accompanied by tests.

## 5. Architecture

``` mermaid
flowchart TD
    A[Developer selects source ZIP] --> B[React + TypeScript frontend]
    B --> C[FastAPI API]
    C --> D[Archive validation and safe extraction]
    D --> E[Custom IDOR scanner]
    D --> F[Bandit static analysis]
    E --> G[Normalize and consolidate findings]
    F --> G
    G --> H[Optional local AI analysis via Ollama]
    H --> I[Structured report]
    I --> J[Dashboard and finding details]
```

### Component responsibilities

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Frontend                            File selection, scan initiation,
                                      progress and findings display

  FastAPI backend                     HTTP routes, upload handling,
                                      orchestration, report response

  Custom IDOR scanner                 Detect source patterns that may
                                      indicate missing object-level
                                      authorization

  Bandit                              Identify Python security patterns
                                      covered by Bandit rules

  AI analyzer                         Candidate discovery, contextual
                                      review, explanation, or triage as
                                      implemented

  Ollama                              Local model runtime

  Pytest suite                        Validate known cases and prevent
                                      regressions

  JSON/SARIF reporting                Structured results where
                                      implemented and enabled
  -----------------------------------------------------------------------

The intended flow is upload → validate → scan → optional AI review →
normalize results → return report → display findings. If an optional
stage fails or is skipped, the application should make that clear rather
than imply that every stage completed.

## 6. Why Combine Static Analysis, AI, and Tests?

-   **Static analysis** is repeatable and rule-driven, but may miss
    context.
-   **AI analysis** can help interpret context, but may hallucinate or
    overstate confidence.
-   **Tests** provide stronger evidence when they reproduce behavior,
    but only cover the scenarios executed.
-   **Human review** is necessary to assess exploitability, impact, and
    business context.

The report should preserve evidence provenance. A static rule, an LLM
opinion, and a test result are not equivalent sources of proof.

## 7. Technology Stack

  Technology     Purpose
  -------------- --------------------------------------------
  Python         Backend and scanner
  FastAPI        HTTP API
  Uvicorn        ASGI server
  React          User interface
  TypeScript     Frontend types
  Vite           Frontend dev/build tooling
  Bandit         Python static security checks
  Ollama         Local LLM runtime
  `qwen3.5:4b`   Configured local model used in development
  Pytest         Automated testing
  Git            Version control

Use the dependency files and lockfiles in the checked-out repository for
exact package versions.

## 8. Repository Layout

This is a conceptual map of the project; verify filenames against your
branch.

``` text
patchproof-idor-demo/
├── backend/
│   └── main.py                 # FastAPI application/API routes
├── frontend/
│   ├── src/
│   │   ├── App.tsx             # Main UI
│   │   ├── components/         # Upload and finding components
│   │   └── types.ts            # Frontend types
│   ├── package.json
│   └── .env.example
├── scanner/
│   ├── unified_scanner.py      # Scanner orchestration
│   ├── ai_analyzer.py          # AI-assisted analysis and triage
│   └── ...                     # Additional scanner modules
├── tests/                      # Automated tests
├── requirements*.txt
├── INTEGRATION_README.md
└── README.md
```

## 9. Requirements

-   Python version compatible with the repository dependencies.
-   Node.js and npm.
-   Git.
-   Python virtual environment recommended.
-   Ollama and the configured model for AI-assisted analysis.
-   Network access may be needed for installing packages or downloading
    the model. After setup, scanning can run locally depending on
    configuration.

## 10. Installation

Commands below are for Windows PowerShell. Use the requirements file
that actually exists in your branch.

### Step 1 --- Clone or open the repository

``` powershell
git clone <YOUR_REPOSITORY_URL>
cd patchproof-idor-demo
```

If the repository is already on your computer, open PowerShell in its
root. Replace the placeholder URL with the real repository URL.

### Step 2 --- Create a virtual environment

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If activation is inconvenient, use the environment's Python executable
directly:

``` powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
```

### Step 3 --- Install Python dependencies

Use the dependency file that matches your branch:

``` powershell
python -m pip install -r requirements.txt
```

If your branch uses `requirements-integration.txt`, install from that
file instead. Do not assume both files are interchangeable.

### Step 4 --- Install frontend dependencies

``` powershell
cd frontend
npm install
cd ..
```

For repeatable installs when `package-lock.json` is current, use
`npm ci`.

### Step 5 --- Set up Ollama (optional)

Install Ollama using its official installation instructions, then run:

``` powershell
ollama pull qwen3.5:4b
ollama list
```

The model name must match the scanner configuration. If your branch uses
a different name, use that name instead.

### Step 6 --- Check configuration

Review `frontend/.env.example` and backend configuration. The frontend
integration has used `http://127.0.0.1:8765` as the API base URL. Ensure
the frontend and backend agree on the port. Never commit real API keys
or credentials.

## 11. Running the Application

Open two PowerShell terminals in the repository root.

### Terminal A --- backend

For a branch where the FastAPI object is in `backend/main.py`:

``` powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8765 --reload
```

If the FastAPI object is instead in `backend/app/main.py`, use:

``` powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765 --reload
```

Use only the command matching the actual location of
`app = FastAPI(...)`.

Check the health endpoint:

``` powershell
Invoke-RestMethod http://127.0.0.1:8765/api/health
```

### Terminal B --- frontend

``` powershell
cd frontend
npm run dev
```

Open the local URL printed by Vite. The port may differ if the default
is occupied.

## 12. Using PatchProof

1.  Start the backend and frontend.
2.  Open the local frontend.
3.  Open the scan/upload workflow.
4.  Select a ZIP containing code you are authorized to test.
5.  Start the scan and wait for the API response.
6.  Review the summary and any scanner/AI warnings.
7.  Open findings and inspect location, evidence, classification, and
    suggested remediation.
8.  Treat uncertain findings as review candidates.
9.  Save or export the report if supported by the active build.
10. Validate important findings with a controlled, reproducible test.

A useful initial benchmark is a small sample with one intentionally
vulnerable object-access endpoint and one secure counterpart that checks
ownership server-side.

## 13. API Reference

These routes have been used by the integration; verify them in the
current backend source.

  -----------------------------------------------------------------------
  Method                  Endpoint                Purpose
  ----------------------- ----------------------- -----------------------
  `GET`                   `/api/health`           Check backend
                                                  availability

  `POST`                  `/api/scan-zip`         Upload a ZIP and
                                                  request a scan

  `POST`                  `/api/scan`             Trigger a scan using
                                                  the request format
                                                  supported by the
                                                  backend

  `GET`                   `/api/reports/latest`   Retrieve the latest
                                                  report if persistence
                                                  is enabled
  -----------------------------------------------------------------------

The frontend sends a ZIP using multipart form data with the field name
`file`:

``` javascript
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch("http://127.0.0.1:8765/api/scan-zip", {
  method: "POST",
  body: formData
});
```

Do not manually set the multipart `Content-Type` header when sending
`FormData`; the browser supplies the boundary. The response schema can
evolve. Inspect the actual API response for fields such as `filename`,
`files_scanned`, `findings`, `total_findings`, `errors`, and AI-analysis
status.

## 14. Finding Lifecycle and Classification

A typical finding lifecycle is:

1.  **Detected:** a rule or AI discovery creates a candidate.
2.  **Normalized:** the result is mapped to a common structure.
3.  **Triaged:** available rules or contextual analysis assess it.
4.  **Consolidated:** duplicates may be grouped where implemented.
5.  **Verified (optional):** a test or manual reproduction supplies
    additional evidence.
6.  **Displayed:** the frontend presents the finding.

  -----------------------------------------------------------------------
  Status concept                      Interpretation
  ----------------------------------- -----------------------------------
  Potential/candidate                 Worth investigating; not yet proven

  Likely vulnerability                Evidence supports the hypothesis;
                                      verification may still be needed

  Uncertain/manual review             Evidence is incomplete or
                                      conflicting

  Likely false positive               Evidence suggests the rule may not
                                      apply; review before dismissal

  Test-verified                       A named test reproduced the
                                      behavior under defined conditions
  -----------------------------------------------------------------------

Do not call a finding confirmed solely because an LLM says it is likely.
If tests were not executed, the report should say so. A test file
existing in the repository does not prove that the test ran or passed
against the scanned target.

## 15. Security Design and Threat Model

Because the scanner accepts untrusted archives, it has its own attack
surface.

  -----------------------------------------------------------------------
  Threat                  Example                 Mitigation direction
  ----------------------- ----------------------- -----------------------
  Malicious ZIP           Path traversal entry    Validate paths and
                                                  extraction destinations

  Resource exhaustion     Huge archive or file    Upload, size,
                          count                   file-count, and time
                                                  limits

  Arbitrary code          Uploaded test/build     Do not execute uploaded
  execution               script executes         code by default;
                                                  isolate any future
                                                  execution

  Prompt injection        Source comments try to  Treat scanned content
                          instruct the LLM        as untrusted data, not
                                                  instructions

  False positive          Secure route flagged    Context-aware triage,
                          despite ownership check counter-evidence,
                                                  tests, human review

  False negative          Unsupported language or Document scope and
                          complex control flow    benchmark known cases

  Sensitive data exposure Uploaded source/reports Local-only defaults and
                          retained unexpectedly   a defined retention
                                                  policy
  -----------------------------------------------------------------------

The backend integration has included upload, file-count,
extraction-size, and unsafe-path protections. Verify the implementation
and tests before treating these as complete security guarantees.

Additional recommendations: - Keep the development API bound to
localhost unless deployment hardening has been done. - Do not expose the
scanner service publicly without authentication and appropriate
controls. - Apply timeouts and resource limits to subprocesses. - Keep
secrets out of source control. - Clean up temporary files and sensitive
reports according to a documented policy. - Report when optional
analysis stages fail or are skipped.

## 16. Testing and Validation

Run tests from the repository root:

``` powershell
python -m pytest -v
```

Focused test groups used during development, if present in your
checkout:

``` powershell
python -m pytest tests/test_idor.py -v
python -m pytest tests/test_idor_regression.py -v
python -m pytest tests/test_triage.py -v
```

### Historical development checkpoints

Previously reported results include:

-   IDOR tests: **3 passed** in a focused run.
-   IDOR regression tests: **5 passed, 2 xfailed** in a focused run.
-   Triage tests: **23 passed** in a focused run.
-   Full suite: **44 passed, 2 xfailed** in a previous run.

These are historical results, not a guarantee about the current
checkout. Re-run tests after changes. `xfailed` means a test was marked
as an expected failure and should be documented.

A separate companion vulnerability-lab app had a reported run of **29
passed and 2 failed out of 31 tests**. The failures involved Windows
shell quoting in a command-injection marker test and attempting to run
`echo` as a standalone executable with `shell=False`. These results
belong to that companion target app, not PatchProof's scanner test
suite.

### Evaluation goals

-   Test vulnerable and secure implementations.
-   Verify owner access succeeds and cross-user access is rejected.
-   Test admin exceptions separately.
-   Match findings to specific test cases.
-   Record whether tests actually ran.
-   Keep tests deterministic across operating systems.
-   Preserve raw outputs and configuration for repeatability.

## 17. Evaluation Methodology

To evaluate detection quality, create a labeled benchmark of known
vulnerable and secure cases. Give each case a stable ID, vulnerability
category, expected outcome, file/route, and rationale.

For each run: 1. Scan every benchmark case with the same configuration.
2. Match findings to manifest cases using category, source location, and
evidence---not title alone. 3. Count true positives (TP), false
positives (FP), false negatives (FN), and true negatives (TN) under a
documented matching rule. 4. Calculate: - **Precision** = TP / (TP +
FP) - **Recall** = TP / (TP + FN) - **F1** = 2 × Precision × Recall /
(Precision + Recall) 5. Report metrics by vulnerability class and
overall. 6. Record scan time, model availability, model name, and
test-execution status. 7. Manually inspect false positives and false
negatives. 8. Re-run the same benchmark after scanner improvements.

Do not publish scores until labels, matching rules, and raw scan outputs
have been reviewed and preserved.

## 18. Known Limitations

-   Static heuristics and LLMs can flag secure code, particularly when
    they miss ownership checks elsewhere in a function.
-   Complex control flow, indirect helpers, dynamic routes, or
    unsupported languages can lead to false negatives.
-   Bandit focuses on Python and is not a full multi-language security
    analyzer.
-   An LLM can misread code, follow misleading comments, or invent an
    exploit path.
-   Tests only validate scenarios they execute; passing tests does not
    prove that the application is vulnerability-free.
-   Uploaded code should not be executed by the scanner unless a
    separately designed, isolated execution environment exists.
-   Report fields, SARIF validity, verification states, and export
    behavior must be checked against the current branch.
-   Performance depends on archive size, file count, dependencies,
    hardware, and AI availability.

## 19. Future Scope

-   Improve authorization analysis by tracing trusted identity, object
    ownership, and control flow across helper functions.
-   Give every rule a stable identifier and use valid CWE identifiers in
    structured reports.
-   Preserve provenance so static rules, AI opinions, and test results
    are distinguishable.
-   Validate AI-cited source snippets and line numbers against the
    actual file.
-   Improve independent AI validation and reduce anchoring on initial
    model claims.
-   Map frontend API calls to backend routes where feasible.
-   Consolidate duplicates without treating repeated outputs from the
    same model as independent evidence.
-   Improve SARIF compatibility and report export.
-   Add reproducible per-category benchmark reporting.
-   Expand language/framework support.
-   Add team access, job tracking, and report retention controls if the
    project moves beyond local demos.
-   Consider isolated sandbox execution only if needed and properly
    secured.

## 20. Presentation Guide

This README is structured so a teammate can prepare a project
presentation from it.

### Recommended 10-slide deck

  -----------------------------------------------------------------------
  Slide                   Title                   Include
  ----------------------- ----------------------- -----------------------
  1                       PatchProof              Project name, team,
                                                  department, guide,
                                                  one-line summary

  2                       Problem Statement       Why code security
                                                  matters; limitations of
                                                  one detection technique

  3                       Objectives              Upload, scan, explain
                                                  findings, test, improve
                                                  reliability

  4                       Proposed Solution       The end-to-end scan
                                                  workflow

  5                       Architecture            Frontend → FastAPI →
                                                  validation → scanners →
                                                  AI → report

  6                       Technology Stack        Python, FastAPI, React,
                                                  TypeScript, Vite,
                                                  Bandit, Ollama, Pytest

  7                       Live Demonstration      Upload a controlled
                                                  sample and inspect a
                                                  finding

  8                       Testing and Evaluation  Vulnerable/secure
                                                  cases, test approach,
                                                  historical checkpoint
                                                  with context

  9                       Limitations and         False
                          Security                positives/negatives, AI
                                                  uncertainty, archive
                                                  safety

  10                      Conclusion and Future   Main contribution, next
                          Work                    improvements, Q&A
  -----------------------------------------------------------------------

### Suggested demonstration sequence

1.  Show the dashboard and upload workflow.
2.  Upload a small, intentionally vulnerable project owned by the team.
3.  Show the scan result and open a relevant finding.
4.  Explain the code evidence and why the result may still require
    verification.
5.  Compare with a secure version containing a server-side ownership
    check.
6.  Show the related regression test and its actual result.
7.  End with limitations and planned improvements.

Use screenshots from the current running application. Do not invent scan
counts, accuracy scores, or test outcomes.

### One-minute project explanation

PatchProof is a local-first, AI-assisted source-code security scanner.
Developers upload a project as a ZIP through a React and TypeScript web
interface. A FastAPI backend validates the archive and orchestrates
custom IDOR checks, Bandit static analysis, and optional local
LLM-assisted review through Ollama. Findings are returned in a
structured report and presented in a dashboard. The project emphasizes
evidence and uncertainty: automated findings need to be reviewed and,
where possible, verified with reproducible tests. The goal is to help
developers investigate security issues more efficiently, not to replace
a professional security assessment.

## 21. Troubleshooting

### Frontend cannot reach backend

-   Confirm backend is running on `127.0.0.1:8765`.
-   Check `GET /api/health`.
-   Confirm the frontend API URL matches the backend port.
-   Check browser developer tools and backend logs.

### AI analysis unavailable

-   Confirm Ollama is running.
-   Run `ollama list`.
-   Check the configured model name.
-   Review backend logs; static scanning may still work if fallback is
    implemented.

### Python dependencies fail

-   Confirm `.venv` is active or use `.venv\Scripts\python.exe`.
-   Check the requirements file for the current branch.
-   Avoid mixing packages across virtual environments.

### Frontend build fails

``` powershell
cd frontend
npm ci
npm run build
```

If `npm ci` reports a lockfile mismatch, inspect package changes rather
than deleting the lockfile automatically.

### Tests fail on Windows

-   Inspect the first failing assertion and traceback.
-   Check for Unix-only commands, shell quoting, and path assumptions.
-   Prefer platform-independent behavior for secure comparison routes.
-   Do not weaken an assertion unless it still proves the intended
    security behavior.

### Git reports LF/CRLF warnings

These are usually line-ending conversion warnings, not errors. Check
`git status` to see whether files are staged. A `.gitattributes` file
can establish a consistent team policy.

## 22. Contributing

1.  Create a branch for the change.
2.  Add regression tests for detection and triage changes.
3.  Preserve evidence provenance and avoid overstating confidence.
4.  Run focused tests and the full test suite.
5.  Run the frontend build if UI files changed.
6.  Review `git diff` before committing.
7.  Do not commit secrets or sensitive scan artifacts.
8.  Update this README when architecture, endpoints, commands, or
    configuration changes.

Example commit message:

``` text
Improve IDOR detection and scan reporting
```

## 23. Responsible Use

Use PatchProof only for code you own or are explicitly authorized to
assess. Do not scan third-party systems without permission. Treat
uploaded source and reports as potentially sensitive, and validate
findings before making risk or remediation decisions.

------------------------------------------------------------------------

**Project status:** Active development. Features, commands, report
fields, and test results can differ by branch. Verify them against the
exact commit used for a demo or evaluation.
