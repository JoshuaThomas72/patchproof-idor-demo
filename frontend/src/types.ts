export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type FindingCategory = 
  | 'SQL Injection'
  | 'Path Traversal'
  | 'Insecure Deserialization'
  | 'Hardcoded Secret'
  | 'SSRF'
  | 'Command Injection'
  | 'Insecure Cryptography';

export type VerificationStatus =
  | 'Verified Fixed'
  | 'Needs Review'
  | 'Pytest Failing'
  | 'Patch Available'
  | 'Confirmed Vulnerability'
  | 'Likely Vulnerability'
  | 'Uncertain'
  | 'Likely False Positive'
  | 'Informational';

export interface VerificationTest {
  testId: string;
  testFile: string;
  testFunction: string;
  code: string;
  status: 'passed' | 'failed' | 'running' | 'unrun';
  executionTimeMs: number;
  outputLog: string;
  assertionsCount: number;
}

export interface SecurityFinding {
  id: string;
  ruleId: string; // e.g. B608 (Bandit SQLi), B108 (Tempfile), B301 (Pickle)
  title: string;
  severity: SeverityLevel;
  category: FindingCategory | string;
  cwe: string;
  filePath: string;
  lineNumber: number;
  endLineNumber?: number;
  confidence: 'High' | 'Medium' | 'Low';
  verificationStatus: VerificationStatus;
  detectedBy: string; // e.g., "Bandit AST Parser v1.8"
  description: string;
  aiExplanation: {
    summary: string;
    rootCause: string;
    attackVector: string;
    impact: string;
    suggestedByModel: string; // e.g. "Qwen 2.5 Coder (Local Ollama)"
  };
  vulnerableCode: string;
  remediatedCode: string;
  patchDiff: string;
  testVerification: VerificationTest;
  dateDetected: string;
  classification?: string;
  classificationBasis?: string;
  evidence?: string;
  suggestedFix?: string;
}

export interface RecentScan {
  id: string;
  projectName: string;
  branch: string;
  commitHash: string;
  scanDate: string;
  durationSeconds: number;
  filesScanned: number;
  linesOfCode: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  verifiedFixes: number;
  status: 'Completed' | 'In Progress' | 'Failed';
  scannerEngines: string[];
}

export interface ScannerSettings {
  fastApiEndpoint: string;
  ollamaEndpoint: string;
  ollamaModel: string;
  banditConfigPath: string;
  pytestRunnerCommand: string;
  enableAutomaticPytest: boolean;
  strictInvariantCheck: boolean;
  concurrencyLimit: number;
}
