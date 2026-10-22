import { SecurityFinding, RecentScan, ScannerSettings } from '../types';

export const INITIAL_FINDINGS: SecurityFinding[] = [
  {
    id: 'SEC-2026-081',
    ruleId: 'B608:hardcoded_sql_expressions',
    title: 'SQL Injection via Unsanitized Raw String Formatting',
    severity: 'Critical',
    category: 'SQL Injection',
    cwe: 'CWE-89',
    filePath: 'app/routers/auth.py',
    lineNumber: 42,
    endLineNumber: 47,
    confidence: 'High',
    verificationStatus: 'Verified Fixed',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Dynamic SQL query constructed using f-string interpolation from untrusted user input without parameterized query placeholders.',
    aiExplanation: {
      summary: 'An attacker can supply malicious SQL payload in the `username` field to manipulate the database query logic and bypass password checks or extract data.',
      rootCause: 'String interpolation directly concatenates user-supplied input into an unparameterized cursor.execute() statement.',
      attackVector: "Passing `admin' OR 1=1 --` into the authentication endpoint evaluates the WHERE clause to TRUE, returning the first account in the database without valid password validation.",
      impact: 'Full authentication bypass and read access to all tenant records in the users table.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `@router.post("/login")
async def login(credentials: LoginRequest, db: Connection = Depends(get_db)):
    # Vulnerable: Direct f-string interpolation into raw SQL cursor
    query = f"SELECT id, username, password_hash, role FROM users WHERE username = '{credentials.username}'"
    cursor = await db.execute(query)
    user = await cursor.fetchone()
    
    if not user or not verify_hash(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return create_session_token(user)`,
    remediatedCode: `@router.post("/login")
async def login(credentials: LoginRequest, db: Connection = Depends(get_db)):
    # Remediated: Parameterized SQL statement with query placeholders
    query = "SELECT id, username, password_hash, role FROM users WHERE username = :username"
    cursor = await db.execute(query, {"username": credentials.username})
    user = await cursor.fetchone()
    
    if not user or not verify_hash(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return create_session_token(user)`,
    patchDiff: `@@ -42,3 +42,3 @@
-    query = f"SELECT id, username, password_hash, role FROM users WHERE username = '{credentials.username}'"
-    cursor = await db.execute(query)
+    query = "SELECT id, username, password_hash, role FROM users WHERE username = :username"
+    cursor = await db.execute(query, {"username": credentials.username})`,
    testVerification: {
      testId: 'TEST-AUTH-SQLI',
      testFile: 'tests/security/test_auth_sqli.py',
      testFunction: 'test_login_rejects_sql_injection_payload',
      code: `import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_rejects_sql_injection_payload(client: AsyncClient):
    payload = {"username": "admin' OR '1'='1' --", "password": "any"}
    response = await client.post("/auth/login", json=payload)
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]`,
      status: 'passed',
      executionTimeMs: 42,
      outputLog: `tests/security/test_auth_sqli.py::test_login_rejects_sql_injection_payload PASSED [100%]
1 passed in 0.042s (Bandit invariant verified)`,
      assertionsCount: 2,
    },
    dateDetected: '2026-10-20 14:22:05',
  },
  {
    id: 'SEC-2026-084',
    ruleId: 'B301:pickle_and_modules',
    title: 'Arbitrary Code Execution via Unsafe Pickle Deserialization',
    severity: 'Critical',
    category: 'Insecure Deserialization',
    cwe: 'CWE-502',
    filePath: 'app/core/cache.py',
    lineNumber: 64,
    endLineNumber: 68,
    confidence: 'High',
    verificationStatus: 'Patch Available',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Deserialization of untrusted byte streams using standard library pickle.loads() enables arbitrary remote code execution via __reduce__ payloads.',
    aiExplanation: {
      summary: 'Pickle deserialization executes arbitrary code during object reconstruction if the cache entry or user-provided session payload can be controlled.',
      rootCause: 'Calling `pickle.loads(cached_bytes)` directly on Redis cache values where keys or session blobs originate from client-controlled headers.',
      attackVector: 'Submitting a crafted base64 payload containing a custom class with `__reduce__` method that spawns a reverse shell or executes shell commands.',
      impact: 'Remote Code Execution (RCE) with the operational privileges of the worker container.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `async def get_session_cache(session_id: str, redis_client: Redis):
    raw_data = await redis_client.get(f"session:{session_id}")
    if not raw_data:
        return None
    # Vulnerable: Insecure deserialization of byte stream
    return pickle.loads(raw_data)`,
    remediatedCode: `import json
from pydantic import ValidationError

async def get_session_cache(session_id: str, redis_client: Redis) -> SessionModel | None:
    raw_data = await redis_client.get(f"session:{session_id}")
    if not raw_data:
        return None
    # Remediated: Type-validated JSON parsing replacing unsafe pickle
    try:
        decoded_json = json.loads(raw_data.decode("utf-8"))
        return SessionModel.model_validate(decoded_json)
    except (json.JSONDecodeError, ValidationError):
        logger.warning("Corrupted or tampered session payload", extra={"session_id": session_id})
        return None`,
    patchDiff: `@@ -64,2 +64,7 @@
-    return pickle.loads(raw_data)
+    try:
+        decoded_json = json.loads(raw_data.decode("utf-8"))
+        return SessionModel.model_validate(decoded_json)
+    except (json.JSONDecodeError, ValidationError):
+        return None`,
    testVerification: {
      testId: 'TEST-CACHE-DESERIAL',
      testFile: 'tests/security/test_cache_deserialization.py',
      testFunction: 'test_cache_rejects_pickle_rce_payload',
      code: `import pytest

def test_cache_rejects_pickle_rce_payload():
    malicious_payload = b"cos\\nsystem\\n(S'id'\\ntR."
    # Remediated parser should safely return None without executing
    result = safe_deserialize_session(malicious_payload)
    assert result is None`,
      status: 'passed',
      executionTimeMs: 18,
      outputLog: `tests/security/test_cache_deserialization.py::test_cache_rejects_pickle_rce_payload PASSED [100%]
1 passed in 0.018s`,
      assertionsCount: 1,
    },
    dateDetected: '2026-10-20 14:22:08',
  },
  {
    id: 'SEC-2026-089',
    ruleId: 'B108:hardcoded_tmp_directory',
    title: 'Path Traversal & Arbitrary File Read in Export Handler',
    severity: 'High',
    category: 'Path Traversal',
    cwe: 'CWE-22',
    filePath: 'app/services/exporter.py',
    lineNumber: 88,
    endLineNumber: 94,
    confidence: 'High',
    verificationStatus: 'Verified Fixed',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Path traversal via path concatenation without resolve() sandboxing allows users to specify relative path prefixes like ../../etc/passwd.',
    aiExplanation: {
      summary: 'The file exporter accepts a filename query parameter and opens the file path directly using `os.path.join`, enabling traversal out of the designated export directory.',
      rootCause: 'Lack of canonical path containment validation against the export storage root before reading.',
      attackVector: 'Calling GET `/api/export?filename=../../../../etc/passwd` escapes `STORAGE_DIR` and streams sensitive system files to the client.',
      impact: 'Unauthorized access to server configuration, private keys, environment variables, and filesystem assets.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `def retrieve_export_file(filename: str) -> FileResponse:
    # Vulnerable: Insecure path concatenation without confinement
    target_path = os.path.join(EXPORT_DIR, filename)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(target_path)`,
    remediatedCode: `from pathlib import Path

def retrieve_export_file(filename: str) -> FileResponse:
    # Remediated: Strict canonical resolution and boundary confinement
    base_dir = Path(EXPORT_DIR).resolve()
    target_path = (base_dir / filename).resolve()
    
    # Invariant: Ensure target file resides strictly within base export directory
    if not target_path.is_relative_to(base_dir):
        logger.security_alert("Path traversal attempt detected", extra={"filename": filename})
        raise HTTPException(status_code=403, detail="Access denied")
        
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(target_path))`,
    patchDiff: `@@ -88,4 +88,7 @@
-    target_path = os.path.join(EXPORT_DIR, filename)
+    base_dir = Path(EXPORT_DIR).resolve()
+    target_path = (base_dir / filename).resolve()
+    if not target_path.is_relative_to(base_dir):
+        raise HTTPException(status_code=403, detail="Access denied")`,
    testVerification: {
      testId: 'TEST-EXP-TRAVERSAL',
      testFile: 'tests/security/test_exporter_traversal.py',
      testFunction: 'test_export_rejects_parent_directory_traversal',
      code: `from fastapi.testclient import TestClient

def test_export_rejects_parent_directory_traversal(client: TestClient):
    response = client.get("/api/export", params={"filename": "../../../../etc/passwd"})
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]`,
      status: 'passed',
      executionTimeMs: 29,
      outputLog: `tests/security/test_exporter_traversal.py::test_export_rejects_parent_directory_traversal PASSED [100%]
1 passed in 0.029s`,
      assertionsCount: 2,
    },
    dateDetected: '2026-10-20 14:22:11',
  },
  {
    id: 'SEC-2026-092',
    ruleId: 'B105:hardcoded_password_string',
    title: 'Hardcoded Cryptographic Secret & Default JWT Signing Key',
    severity: 'High',
    category: 'Hardcoded Secret',
    cwe: 'CWE-798',
    filePath: 'app/config.py',
    lineNumber: 19,
    endLineNumber: 23,
    confidence: 'High',
    verificationStatus: 'Verified Fixed',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Cryptographic signing secret hardcoded in source repository as a fallback string literal rather than enforced runtime environment variable.',
    aiExplanation: {
      summary: 'A predictable default secret `"super-secret-jwt-key-2026-dev-fallback"` is present in the configuration module.',
      rootCause: 'Using `os.getenv("JWT_SECRET", "super-secret-jwt-key...")` permits deployment in environments where unconfigured secrets use known tokens.',
      attackVector: 'Anyone with repository read access or knowledge of common dev templates can forge administrative JWT tokens.',
      impact: 'Complete administrative authorization compromise across all tenant APIs.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `class Settings(BaseSettings):
    APP_NAME: str = "PaymentsCore"
    # Vulnerable: Insecure hardcoded fallback secret
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET", "super-secret-jwt-key-2026-dev-fallback")
    ALGORITHM: str = "HS256"`,
    remediatedCode: `from pydantic import Field, field_validator

class Settings(BaseSettings):
    APP_NAME: str = "PaymentsCore"
    # Remediated: Enforced environment secret with strict entropy validation
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET")
    ALGORITHM: str = "HS256"

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_entropy(cls, v: str) -> str:
        if len(v) < 32 or "fallback" in v.lower() or "secret" in v.lower():
            raise ValueError("JWT_SECRET must be at least 32 characters and cryptographically random.")
        return v`,
    patchDiff: `@@ -19,2 +19,8 @@
-    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET", "super-secret-jwt-key-2026-dev-fallback")
+    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET")
+    @field_validator("JWT_SECRET_KEY")
+    def validate_entropy(cls, v: str): ...`,
    testVerification: {
      testId: 'TEST-CONF-ENTROPY',
      testFile: 'tests/security/test_config_validation.py',
      testFunction: 'test_rejects_weak_or_missing_jwt_secret',
      code: `import pytest
from pydantic import ValidationError

def test_rejects_weak_or_missing_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(ValidationError):
        Settings()`,
      status: 'passed',
      executionTimeMs: 12,
      outputLog: `tests/security/test_config_validation.py::test_rejects_weak_or_missing_jwt_secret PASSED [100%]
1 passed in 0.012s`,
      assertionsCount: 1,
    },
    dateDetected: '2026-10-20 14:22:15',
  },
  {
    id: 'SEC-2026-095',
    ruleId: 'B310:urllib_urlopen',
    title: 'Server-Side Request Forgery (SSRF) in Outbound Webhook Dispatcher',
    severity: 'High',
    category: 'SSRF',
    cwe: 'CWE-918',
    filePath: 'app/webhooks/dispatcher.py',
    lineNumber: 105,
    endLineNumber: 112,
    confidence: 'Medium',
    verificationStatus: 'Needs Review',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Outbound HTTP requests dispatched to user-controlled URLs without validating IP destinations against loopback, link-local, or private RFC1918 ranges.',
    aiExplanation: {
      summary: 'Clients registering webhook endpoints can specify cloud metadata addresses (`169.254.169.254`) or internal service endpoints to extract IAM credentials or probe internal networks.',
      rootCause: 'Calling `httpx.post(target_url, json=payload)` directly without DNS pre-resolution and IP CIDR denylisting.',
      attackVector: 'Registering webhook `http://169.254.169.254/latest/meta-data/iam/security-credentials/` causes the backend server to fetch cloud credentials and report them in delivery logs.',
      impact: 'Cloud account takeover, internal microservice reconnaissance, and port scanning behind firewalls.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `async def dispatch_webhook(event: WebhookEvent, destination_url: str):
    # Vulnerable: Unvalidated outbound request to user-supplied endpoint
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(destination_url, json=event.model_dump())
        return response.status_code`,
    remediatedCode: `import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_webhook_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        return False
    host = parsed.hostname
    if not host:
        return False
    ip_addrs = socket.getaddrinfo(host, None)
    for family, _, _, _, sockaddr in ip_addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True

async def dispatch_webhook(event: WebhookEvent, destination_url: str):
    if not is_safe_webhook_url(destination_url):
        raise HTTPException(status_code=400, detail="Target destination violates outbound SSRF policy.")
    async with httpx.AsyncClient(timeout=5.0) as client:
        return (await client.post(destination_url, json=event.model_dump())).status_code`,
    patchDiff: `@@ -105,3 +105,5 @@
+    if not is_safe_webhook_url(destination_url):
+        raise HTTPException(status_code=400, detail="Target destination violates outbound SSRF policy.")
     async with httpx.AsyncClient(timeout=5.0) as client:`,
    testVerification: {
      testId: 'TEST-SSRF-GUARD',
      testFile: 'tests/security/test_webhook_ssrf.py',
      testFunction: 'test_blocks_metadata_service_ip',
      code: `import pytest

def test_blocks_metadata_service_ip():
    assert is_safe_webhook_url("http://169.254.169.254/metadata") is False
    assert is_safe_webhook_url("http://127.0.0.1:8000/internal") is False
    assert is_safe_webhook_url("https://hooks.slack.com/services/safe") is True`,
      status: 'passed',
      executionTimeMs: 34,
      outputLog: `tests/security/test_webhook_ssrf.py::test_blocks_metadata_service_ip PASSED [100%]
1 passed in 0.034s`,
      assertionsCount: 3,
    },
    dateDetected: '2026-10-20 14:22:20',
  },
  {
    id: 'SEC-2026-101',
    ruleId: 'B602:subprocess_popen_with_shell_equals_true',
    title: 'Command Injection via Subprocess Execution with shell=True',
    severity: 'Critical',
    category: 'Command Injection',
    cwe: 'CWE-78',
    filePath: 'app/tasks/worker.py',
    lineNumber: 73,
    endLineNumber: 78,
    confidence: 'High',
    verificationStatus: 'Pytest Failing',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Subprocess invocations utilizing `subprocess.call` with `shell=True` and unescaped format arguments allow arbitrary system shell command execution.',
    aiExplanation: {
      summary: 'Invoking system shell commands with user parameter concatenation allows command chaining using `;`, `&&`, or `|` operators.',
      rootCause: '`subprocess.check_output(f"ffmpeg -i {input_file} {output_path}", shell=True)` executes through the system bash shell without argument tokenization.',
      attackVector: 'Supplying a filename like `sample.mp4; rm -rf /;` causes bash to execute the second command immediately.',
      impact: 'Full underlying OS command execution inside the task worker container.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `def convert_media(input_file: str, output_path: str):
    # Vulnerable: shell=True with unescaped string interpolation
    cmd = f"ffmpeg -i {input_file} -codec:v libx264 {output_path}"
    subprocess.check_call(cmd, shell=True)`,
    remediatedCode: `import shlex
import subprocess

def convert_media(input_file: str, output_path: str):
    # Remediated: Explicit argument list without system shell
    cmd = ["ffmpeg", "-i", input_file, "-codec:v", "libx264", output_path]
    subprocess.check_call(cmd, shell=False)`,
    patchDiff: `@@ -73,3 +73,2 @@
-    cmd = f"ffmpeg -i {input_file} -codec:v libx264 {output_path}"
-    subprocess.check_call(cmd, shell=True)
+    cmd = ["ffmpeg", "-i", input_file, "-codec:v", "libx264", output_path]
+    subprocess.check_call(cmd, shell=False)`,
    testVerification: {
      testId: 'TEST-CMD-INJECT',
      testFile: 'tests/security/test_worker_command_injection.py',
      testFunction: 'test_command_injection_payload_does_not_execute',
      code: `import pytest

def test_command_injection_payload_does_not_execute(tmp_path):
    marker = tmp_path / "injected.txt"
    payload = f"test.mp4; touch {marker}"
    with pytest.raises(subprocess.CalledProcessError):
        convert_media(payload, str(tmp_path / "out.mp4"))
    assert not marker.exists(), "Command injection payload executed!"`,
      status: 'failed',
      executionTimeMs: 58,
      outputLog: `tests/security/test_worker_command_injection.py::test_command_injection_payload_does_not_execute FAILED [100%]
FAILED test_command_injection_payload_does_not_execute - AssertionError: Command injection payload executed!
Unpatched worker still runs shell=True`,
      assertionsCount: 2,
    },
    dateDetected: '2026-10-20 14:22:24',
  },
  {
    id: 'SEC-2026-104',
    ruleId: 'B303:md5_for_passwords',
    title: 'Use of Insecure Cryptographic Hash Algorithm (MD5)',
    severity: 'Medium',
    category: 'Insecure Cryptography',
    cwe: 'CWE-327',
    filePath: 'app/utils/crypto.py',
    lineNumber: 28,
    endLineNumber: 32,
    confidence: 'High',
    verificationStatus: 'Verified Fixed',
    detectedBy: 'Bandit AST Parser v1.8',
    description: 'Hashing sensitive token identifiers using hashlib.md5 is vulnerable to collision attacks and rapid rainbow table inversion.',
    aiExplanation: {
      summary: 'MD5 is cryptographically broken and should never be used for security-critical token hashes or signature generation.',
      rootCause: 'Direct use of `hashlib.md5()` on session identifiers.',
      attackVector: 'Collision generation allows an attacker to generate a second pre-image collision with the same digest.',
      impact: 'Token collision attacks permitting session hijacking.',
      suggestedByModel: 'Qwen 2.5 Coder (14B local Ollama)',
    },
    vulnerableCode: `import hashlib

def generate_token_fingerprint(token: str) -> str:
    # Vulnerable: Broken MD5 algorithm
    return hashlib.md5(token.encode("utf-8")).hexdigest()`,
    remediatedCode: `import hashlib

def generate_token_fingerprint(token: str) -> str:
    # Remediated: Modern SHA-256 with 256-bit collision resistance
    return hashlib.sha256(token.encode("utf-8")).hexdigest()`,
    patchDiff: `@@ -28,2 +28,2 @@
-    return hashlib.md5(token.encode("utf-8")).hexdigest()
+    return hashlib.sha256(token.encode("utf-8")).hexdigest()`,
    testVerification: {
      testId: 'TEST-CRYPTO-SHA',
      testFile: 'tests/security/test_crypto_hash.py',
      testFunction: 'test_token_fingerprint_uses_sha256',
      code: `def test_token_fingerprint_uses_sha256():
    digest = generate_token_fingerprint("sample-token-uuid")
    assert len(digest) == 64  # 64 hex chars = 256 bits`,
      status: 'passed',
      executionTimeMs: 8,
      outputLog: `tests/security/test_crypto_hash.py::test_token_fingerprint_uses_sha256 PASSED [100%]
1 passed in 0.008s`,
      assertionsCount: 1,
    },
    dateDetected: '2026-10-20 14:22:28',
  },
];

export const INITIAL_RECENT_SCANS: RecentScan[] = [
  {
    id: 'SCAN-904',
    projectName: 'fastapi-auth-service.zip',
    branch: 'main',
    commitHash: '7b2e4fa',
    scanDate: '2026-10-20 14:22',
    durationSeconds: 14.8,
    filesScanned: 84,
    linesOfCode: 14920,
    findingsCount: {
      critical: 3,
      high: 3,
      medium: 1,
      low: 0,
      total: 7,
    },
    verifiedFixes: 5,
    status: 'Completed',
    scannerEngines: ['Bandit AST 1.8.2', 'Ollama Qwen 2.5 Coder', 'Pytest 8.2'],
  },
  {
    id: 'SCAN-903',
    projectName: 'payment-webhook-worker.zip',
    branch: 'staging',
    commitHash: 'c94f11d',
    scanDate: '2026-10-19 18:05',
    durationSeconds: 9.3,
    filesScanned: 42,
    linesOfCode: 7350,
    findingsCount: {
      critical: 1,
      high: 1,
      medium: 2,
      low: 1,
      total: 5,
    },
    verifiedFixes: 4,
    status: 'Completed',
    scannerEngines: ['Bandit AST 1.8.2', 'Ollama Qwen 2.5 Coder', 'Pytest 8.2'],
  },
  {
    id: 'SCAN-902',
    projectName: 'flask-data-pipeline.zip',
    branch: 'main',
    commitHash: '210a45e',
    scanDate: '2026-10-18 11:40',
    durationSeconds: 18.2,
    filesScanned: 112,
    linesOfCode: 22100,
    findingsCount: {
      critical: 0,
      high: 2,
      medium: 3,
      low: 2,
      total: 7,
    },
    verifiedFixes: 6,
    status: 'Completed',
    scannerEngines: ['Bandit AST 1.8.2', 'Pytest 8.2'],
  },
  {
    id: 'SCAN-901',
    projectName: 'micro-inventory-api.zip',
    branch: 'feature/v2-ingest',
    commitHash: 'ea923c1',
    scanDate: '2026-10-17 09:12',
    durationSeconds: 7.1,
    filesScanned: 29,
    linesOfCode: 4890,
    findingsCount: {
      critical: 0,
      high: 0,
      medium: 1,
      low: 1,
      total: 2,
    },
    verifiedFixes: 2,
    status: 'Completed',
    scannerEngines: ['Bandit AST 1.8.2', 'Ollama Qwen 2.5 Coder', 'Pytest 8.2'],
  },
];

export const DEFAULT_SETTINGS: ScannerSettings = {
  fastApiEndpoint: 'http://127.0.0.1:8000/api/v1',
  ollamaEndpoint: 'http://127.0.0.1:11434',
  ollamaModel: 'qwen2.5-coder:14b',
  banditConfigPath: '.bandit.yaml',
  pytestRunnerCommand: 'pytest -v --tb=short',
  enableAutomaticPytest: true,
  strictInvariantCheck: true,
  concurrencyLimit: 4,
};

export const DEMO_PROJECT_PRESETS = [
  {
    name: 'fastapi-auth-service.zip',
    description: 'OAuth2 & session authentication service with Postgres & Redis caching layer.',
    language: 'Python 3.12 · FastAPI',
    files: 84,
    size: '1.4 MB',
    findingsSample: 7,
  },
  {
    name: 'payment-webhook-worker.zip',
    description: 'Asynchronous event consumer processing Stripe & Adyen webhooks via Celery.',
    language: 'Python 3.11 · Celery / Redis',
    files: 42,
    size: '860 KB',
    findingsSample: 5,
  },
  {
    name: 'flask-data-pipeline.zip',
    description: 'Batch data transformation and export pipeline with file exports and XML ingest.',
    language: 'Python 3.12 · Flask / Pandas',
    files: 112,
    size: '2.8 MB',
    findingsSample: 7,
  },
];
