import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { StatCards } from './components/StatCards';
import { FindingsTable } from './components/FindingsTable';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ScanUploadModal } from './components/ScanUploadModal';
import { VerificationView } from './components/VerificationView';
import { ReportsView } from './components/ReportsView';
import { SettingsView } from './components/SettingsView';
import { INITIAL_FINDINGS, INITIAL_RECENT_SCANS, DEFAULT_SETTINGS } from './data/mockData';
import { SecurityFinding, RecentScan, ScannerSettings } from './types';
import { generateSarifReport, downloadJsonFile } from './utils/sarifExport';
import { Shield, Sparkles, CheckCircle, ArrowRight } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [findings, setFindings] = useState<SecurityFinding[]>(INITIAL_FINDINGS);
  const [scans, setScans] = useState<RecentScan[]>(INITIAL_RECENT_SCANS);
  const [settings, setSettings] = useState<ScannerSettings>(DEFAULT_SETTINGS);

  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [scanInitialPreset, setScanInitialPreset] = useState<string | undefined>(undefined);
  const [notification, setNotification] = useState<string | null>(null);
  const [hasRealScan, setHasRealScan] = useState(false);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => {
      setNotification((curr) => (curr === msg ? null : curr));
    }, 3500);
  };

  const handleOpenScan = (presetName?: string) => {
    setScanInitialPreset(presetName);
    setIsScanModalOpen(true);
  };

  const handleScanCompleted = (newScan: RecentScan, realFindings: any[] = []) => {
    setScans((prev) => [newScan, ...prev]);
    setHasRealScan(true);

    const normalizeSeverity = (value: unknown): SecurityFinding['severity'] => {
      const severity = String(value ?? '').toUpperCase();
      if (severity === 'CRITICAL') return 'Critical';
      if (severity === 'HIGH') return 'High';
      if (severity === 'LOW' || severity === 'INFO' || severity === 'INFORMATIONAL') return 'Low';
      return 'Medium';
    };

    const mapClassification = (value: unknown): SecurityFinding['verificationStatus'] => {
      switch (String(value ?? '').toLowerCase()) {
        case 'confirmed': return 'Confirmed Vulnerability';
        case 'likely_vulnerability': return 'Likely Vulnerability';
        case 'likely_false_positive': return 'Likely False Positive';
        case 'informational': return 'Informational';
        case 'uncertain': return 'Uncertain';
        default: return 'Needs Review';
      }
    };

    const mappedFindings: SecurityFinding[] = realFindings.map((f, index) => {
      const records = Array.isArray(f.original_records) ? f.original_records : [];
      const scannerRecord = records.find((record: any) => record.kind === 'scanner_result');
      const discoveryRecord = records.find((record: any) => record.kind === 'ai_discovery');
      const rawFinding = scannerRecord?.finding ?? {};
      const ai = scannerRecord?.ai_analysis ?? discoveryRecord?.validation ?? {};
      const message = rawFinding.message ?? discoveryRecord?.message ?? f.message ?? f.category ?? 'Security finding';
      const evidence = ai.evidence ?? discoveryRecord?.evidence ?? discoveryRecord?.triage?.reason ?? f.evidence_sources?.reproducible_tests?.[0]?.proves ?? '';
      const suggestedFix = ai.suggested_fix ?? discoveryRecord?.suggested_fix ?? '';
      const classification = String(f.classification ?? f.triage?.classification ?? 'uncertain');
      const verificationStatus = mapClassification(classification);
      const confidenceValue = String(rawFinding.confidence ?? discoveryRecord?.confidence ?? 'MEDIUM').toLowerCase();
      const confidence: SecurityFinding['confidence'] = confidenceValue === 'high' ? 'High' : confidenceValue === 'low' ? 'Low' : 'Medium';
      const filePath = String(f.file ?? rawFinding.file ?? 'Unknown file');
      const lineNumber = Number(f.line ?? rawFinding.line ?? 0);

      return {
        id: `SCAN-${Date.now()}-${index}`,
        ruleId: String(rawFinding.rule_id ?? discoveryRecord?.category ?? rawFinding.category ?? f.category ?? 'Security finding'),
        title: String(discoveryRecord?.category ?? rawFinding.category ?? f.category ?? 'Security finding'),
        severity: normalizeSeverity(f.severity ?? rawFinding.severity ?? ai.severity),
        category: String(discoveryRecord?.category ?? rawFinding.category ?? f.category ?? 'Security finding'),
        cwe: String(rawFinding.cwe ?? 'Needs review'),
        filePath,
        lineNumber,
        confidence,
        verificationStatus,
        detectedBy: records.map((record: any) => record.source ?? record.finding?.source).filter(Boolean).join(' + ') || 'PatchProof',
        description: String(message),
        aiExplanation: {
          summary: String(ai.explanation ?? ai.reason ?? discoveryRecord?.message ?? message),
          rootCause: String(evidence || 'The analyzer did not provide a separate root-cause statement.'),
          attackVector: String(ai.verification_tests?.join(' ') ?? 'Review the reported source location and authorization flow.'),
          impact: String(suggestedFix || 'Impact and remediation require review of the affected application.'),
          suggestedByModel: String(discoveryRecord?.validation?.prompt_version ? 'Qwen (local Ollama)' : 'PatchProof analysis'),
        },
        vulnerableCode: String(rawFinding.code ?? rawFinding.evidence ?? discoveryRecord?.evidence ?? 'Source snippet was not included in the scan report.'),
        remediatedCode: String(suggestedFix || 'No remediation suggestion was provided.'),
        patchDiff: '',
        testVerification: {
          testId: `UNRUN-${index}`,
          testFile: 'Not run',
          testFunction: 'Not run',
          code: '',
          status: 'unrun',
          executionTimeMs: 0,
          outputLog: 'Uploaded project tests were not executed. Findings require manual or separately configured verification.',
          assertionsCount: 0,
        },
        dateDetected: new Date().toISOString(),
        classification,
        classificationBasis: String(f.classification_basis ?? 'static/AI analysis'),
        evidence: String(evidence),
        suggestedFix: String(suggestedFix),
      };
    });

    setFindings(mappedFindings);
    const confirmed = mappedFindings.filter((finding) => finding.verificationStatus === 'Confirmed Vulnerability').length;
    showNotification(`Scan completed: ${mappedFindings.length} finding(s); ${confirmed} confirmed by available evidence.`);
  };

  // Verification and remediation actions are intentionally non-mutating until
  // real backend endpoints exist; the UI must never fabricate a passing test.
  const handleApplyFix = (findingId: string) => {
    showNotification(`Automated remediation is not connected yet (${findingId}); no changes were applied.`);
  };

  const handleRunSingleTest = (findingId: string) => {
    showNotification(`No test was run for ${findingId}. Live verification is not connected yet.`);
  };

  const handleRunAllTests = () => {
    showNotification('No tests were run. Live verification for uploaded projects is not connected yet.');
  };

  const handleExportSarif = () => {
    const reportData = generateSarifReport(scans[0], findings);
    downloadJsonFile('patchproof-audit-report.sarif.json', reportData);
    showNotification('Downloaded SARIF 2.1.0 JSON report.');
  };

  const handleResetDemoData = () => {
    setFindings(INITIAL_FINDINGS);
    setScans(INITIAL_RECENT_SCANS);
    setHasRealScan(false);
    setSettings(DEFAULT_SETTINGS);
    showNotification('Reset workspace to initial demo state.');
  };

  return (
    <div className="min-h-screen bg-[#fbfbfd] text-[#1d1d1f] flex flex-col font-sans selection:bg-[#0071e3]/15 selection:text-[#0071e3]">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenScanModal={() => handleOpenScan()}
        findingsCount={findings.length}
      />

      {/* Floating Notification Pill */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-full border border-black/[0.08] bg-white px-4 py-2.5 text-xs font-medium text-[#1d1d1f] shadow-[0_8px_30px_rgba(0,0,0,0.12)] animate-in slide-in-from-bottom-3 duration-200">
          <CheckCircle className="h-4 w-4 text-[#34c759]" />
          <span>{notification}</span>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1">
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div>
            {/* Hero Section */}
            <HeroSection
              onStartScan={() => handleOpenScan()}
              onExploreFindings={() => setActiveTab('findings')}
              onSelectSamplePreset={(preset) => handleOpenScan(preset)}
            />

            {/* Container */}
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 space-y-12 pb-20">
              {/* Stat Cards */}
              <div>
                <div className="mb-4 flex items-center justify-between">
                  <h2 className="text-sm font-semibold tracking-tight text-[#1d1d1f]">
                    Security Health & Invariant Summary
                  </h2>
                  <span className="text-xs text-[#86868b]">
                    Live Local Engine Metrics
                  </span>
                </div>
                <StatCards
                  findings={findings}
                  scans={scans}
                  onFilterSeverity={(sev) => {
                    setActiveTab('findings');
                  }}
                />
              </div>

              {/* Findings Section */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-semibold tracking-tight text-[#1d1d1f]">
                      Active Security Findings
                    </h2>
                    <p className="text-xs text-[#6e6e73]">
                      AST-flagged vulnerabilities with local Qwen code reasoning and Pytest verification harnesses
                    </p>
                  </div>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="inline-flex items-center gap-1 text-xs font-medium text-[#0071e3] hover:underline"
                  >
                    <span>View all {findings.length} findings</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>

                <FindingsTable
                  findings={findings}
                  onSelectFinding={(f) => setSelectedFinding(f)}
                  selectedFindingId={selectedFinding?.id}
                  onExportSarif={handleExportSarif}
                  isLiveData={hasRealScan}
                />
              </div>

              {/* Verification & Test Preview */}
              <div className="rounded-3xl border border-black/[0.06] bg-white p-6 sm:p-8 shadow-[0_2px_16px_rgba(0,0,0,0.02)]">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-black/[0.06]">
                  <div>
                    <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#0071e3] mb-1">
                      <Shield className="h-3.5 w-3.5" />
                      <span>Test-Backed Remediation</span>
                    </div>
                    <h3 className="text-xl font-semibold text-[#1d1d1f]">
                      Deterministic Pytest Invariants
                    </h3>
                    <p className="mt-1 text-xs text-[#6e6e73] max-w-xl">
                      Every code fix produced by PatchProof is backed by an adversarial test case. If the test doesn't pass, the patch is rejected.
                    </p>
                  </div>

                  <button
                    onClick={() => setActiveTab('verification')}
                    className="inline-flex items-center gap-2 rounded-full border border-black/[0.1] bg-white px-4 py-2 text-xs font-medium text-[#1d1d1f] hover:bg-[#f5f5f7] shadow-sm transition-colors whitespace-nowrap self-start sm:self-auto"
                  >
                    <span>Inspect Verification Harness</span>
                    <ArrowRight className="h-3.5 w-3.5 text-[#86868b]" />
                  </button>
                </div>

                {/* 3 Steps summary */}
                <div className="mt-6 grid grid-cols-1 gap-6 sm:grid-cols-3 text-xs">
                  <div>
                    <span className="font-semibold text-[#1d1d1f]">Bandit AST Parser</span>
                    <p className="mt-1 text-[#6e6e73] leading-relaxed">
                      Matches insecure syntax tokens across Abstract Syntax Trees without executing untrusted code.
                    </p>
                  </div>
                  <div>
                    <span className="font-semibold text-[#1d1d1f]">Local Qwen 2.5 Coder</span>
                    <p className="mt-1 text-[#6e6e73] leading-relaxed">
                      Runs locally on Ollama to reason on code context and synthesize parameterized patches.
                    </p>
                  </div>
                  <div>
                    <span className="font-semibold text-[#1d1d1f]">Pytest Verification</span>
                    <p className="mt-1 text-[#6e6e73] leading-relaxed">
                      Proves that the exploit fails while legitimate inputs succeed, guarding against regressions.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* FINDINGS TAB */}
        {activeTab === 'findings' && (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#1d1d1f]">
                  Security Findings
                </h1>
                <p className="mt-1 text-xs sm:text-sm text-[#6e6e73]">
                  All vulnerabilities flagged by Bandit AST parser with Qwen code explanation and test verification.
                </p>
              </div>

              <div className="flex items-center gap-2.5">
                <button
                  onClick={() => handleOpenScan()}
                  className="rounded-full bg-[#0071e3] px-4 py-2 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed] transition-colors"
                >
                  Start New Scan
                </button>
              </div>
            </div>

            <FindingsTable
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
              selectedFindingId={selectedFinding?.id}
              onExportSarif={handleExportSarif}
              isLiveData={hasRealScan}
            />
          </div>
        )}

        {/* VERIFICATION TAB */}
        {activeTab === 'verification' && (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
            <VerificationView
              findings={findings}
              onRunSingleTest={handleRunSingleTest}
              onRunAllTests={handleRunAllTests}
            />
          </div>
        )}

        {/* REPORTS TAB */}
        {activeTab === 'reports' && (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
            <ReportsView
              scans={scans}
              findings={findings}
              onOpenScanModal={() => handleOpenScan()}
            />
          </div>
        )}

        {/* SETTINGS TAB */}
        {activeTab === 'settings' && (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
            <SettingsView
              settings={settings}
              onSaveSettings={(newSettings) => {
                setSettings(newSettings);
                showNotification('Engine settings updated successfully.');
              }}
              onResetDemoData={handleResetDemoData}
            />
          </div>
        )}
      </main>

      {/* Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onApplyFix={handleApplyFix}
        onRunTestVerification={handleRunSingleTest}
      />

      {/* Scan Project Modal */}
      <ScanUploadModal
        isOpen={isScanModalOpen}
        onClose={() => {
          setIsScanModalOpen(false);
          setScanInitialPreset(undefined);
        }}
        onScanCompleted={handleScanCompleted}
        initialPreset={scanInitialPreset}
      />

      {/* Apple-style minimalist Footer */}
      <footer className="border-t border-black/[0.06] bg-[#f5f5f7] py-10 text-xs text-[#86868b]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-[#1d1d1f]">PatchProof</span>
            <span>·</span>
            <span>Security, made clear.</span>
          </div>

          <div className="flex flex-wrap items-center gap-6">
            <button
              onClick={() => setActiveTab('overview')}
              className="hover:text-[#1d1d1f] transition-colors"
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab('findings')}
              className="hover:text-[#1d1d1f] transition-colors"
            >
              Findings
            </button>
            <button
              onClick={() => setActiveTab('verification')}
              className="hover:text-[#1d1d1f] transition-colors"
            >
              Verification
            </button>
            <button
              onClick={() => setActiveTab('reports')}
              className="hover:text-[#1d1d1f] transition-colors"
            >
              Reports
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className="hover:text-[#1d1d1f] transition-colors"
            >
              Settings
            </button>
          </div>

          <div>
            <span>Demo Workspace · Ready for FastAPI backend integration</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
