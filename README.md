# PatchProof IDOR Demo

A local FastAPI demo of an insecure direct object reference (IDOR).

The vulnerable version lets Bob read Alice's synthetic document. The fixed
version checks document ownership and denies Bob's request.

## Safety

This is an intentionally vulnerable teaching demo. It uses fake users and
synthetic data. Run it only on your own computer. Do not deploy the vulnerable
version or expose it to a network.

## Files

- `main_vulnerable.py` — demo app before the ownership check
- `main.py` — app with the ownership check
- `poc.py` — HTTPX script that requests Alice's document as Bob
- `evidence/` — screenshots from the local demo run

## Setup

In PowerShell, from this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt