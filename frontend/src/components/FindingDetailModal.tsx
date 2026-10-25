import React, { useState } from 'react';
import { 
  X, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode, 
  Cpu, 
  ShieldCheck, 
  GitPullRequest, 
  Play, 
  Download, 
  Copy, 
  Check, 
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import { SecurityFinding } from '../types';
import { downloadDiffFile } from '../utils/sarifExport';

interface FindingDetailModalProps {
  finding: SecurityFinding | null;
  onClose: () => void;
  onApplyFix: (findingId: string) => void;
  onRunTestVerification: (findingId: string) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onApplyFix,
  onRunTestVerification,
}) => {
  const [activeTab, setActiveTab] = useState<'evidence' | 'ai' | 'fix' | 'test'>('evidence');
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRunVerification = () => {
    onRunTestVerification(finding.id);
  };

  const handleDownloadPatch = () => {
    const filename = `${finding.id.toLowerCase()}-patch.diff`;
    downloadDiffFile(filename, finding.patchDiff);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/40 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative flex flex-col w-full max-w-4xl max-h-[92vh] rounded-3xl border border-black/[0.08] bg-white shadow-[0_24px_70px_rgba(0,0,0,0.14)] overflow-hidden">
        {/* Header */}
        <div className="flex flex-col gap-3 border-b border-black/[0.06] bg-[#fbfbfd] p-5 sm:p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-0.5 text-xs font-semibold ${
                finding.severity === 'Critical'
                  ? 'bg-[#ff3b30]/10 text-[#d70015]'
                  : finding.severity === 'High'
                  ? 'bg-[#ff9500]/10 text-[#c96000]'
                  : 'bg-[#ffcc00]/15 text-[#8f6b00]'
              }`}>
                {finding.severity}
              </span>

              <span className="font-mono text-xs text-[#6e6e73]">
                {finding.id}
              </span>
              <span className="text-[#86868b]">·</span>
              <span className="font-mono text-xs text-[#1d1d1f] font-semibold">
                {finding.ruleId.split(':')[0]}
              </span>
              <span className="text-[#86868b]">·</span>
              <a
                href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-[#0071e3] hover:underline"
              >
                <span>{finding.cwe}</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>

            <button
              onClick={onClose}
              className="flex h-8 w-8 items-center justify-center rounded-full text-[#86868b] hover:bg-black/[0.05] hover:text-[#1d1d1f] transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <h2 className="text-lg sm:text-xl font-semibold text-[#1d1d1f] leading-snug">
            {finding.title}
          </h2>

          <div className="flex flex-wrap items-center gap-3 text-xs text-[#6e6e73]">
            <div className="flex items-center gap-1.5 font-mono text-[#1d1d1f]">
              <FileCode className="h-3.5 w-3.5 text-[#0071e3]" />
              <span>{finding.filePath}</span>
              <span className="text-[#86868b]">:{finding.lineNumber}</span>
            </div>
            <span>·</span>
            <span>Detected by {finding.detectedBy}</span>
            <span>·</span>
            <div className="flex items-center gap-1.5">
              <span>Status:</span>
              <span className="font-semibold text-[#1d1d1f]">{finding.verificationStatus}</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 border-b border-black/[0.06] bg-white px-5 sm:px-6 pt-2">
          <button
            onClick={() => setActiveTab('evidence')}
            className={`flex items-center gap-2 border-b-2 px-3 py-2.5 text-xs font-medium transition-all ${
              activeTab === 'evidence'
                ? 'border-[#0071e3] text-[#0071e3]'
                : 'border-transparent text-[#6e6e73] hover:text-[#1d1d1f]'
            }`}
          >
            <FileCode className="h-3.5 w-3.5" />
            <span>Code Evidence</span>
          </button>

          <button
            onClick={() => setActiveTab('ai')}
            className={`flex items-center gap-2 border-b-2 px-3 py-2.5 text-xs font-medium transition-all ${
              activeTab === 'ai'
                ? 'border-[#0071e3] text-[#0071e3]'
                : 'border-transparent text-[#6e6e73] hover:text-[#1d1d1f]'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            <span>AI Explanation</span>
          </button>

          <button
            onClick={() => setActiveTab('fix')}
            className={`flex items-center gap-2 border-b-2 px-3 py-2.5 text-xs font-medium transition-all ${
              activeTab === 'fix'
                ? 'border-[#0071e3] text-[#0071e3]'
                : 'border-transparent text-[#6e6e73] hover:text-[#1d1d1f]'
            }`}
          >
            <GitPullRequest className="h-3.5 w-3.5" />
            <span>Suggested Remediation</span>
          </button>

          <button
            onClick={() => setActiveTab('test')}
            className={`flex items-center gap-2 border-b-2 px-3 py-2.5 text-xs font-medium transition-all ${
              activeTab === 'test'
                ? 'border-[#0071e3] text-[#0071e3]'
                : 'border-transparent text-[#6e6e73] hover:text-[#1d1d1f]'
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Pytest Verification</span>
          </button>
        </div>

        {/* Tab Content (Scrollable) */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 bg-white">
          {/* TAB 1: CODE EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-[#1d1d1f]">
                    Vulnerable Source Code Location
                  </h3>
                  <p className="text-[11px] text-[#86868b]">
                    Exact Python AST token flagged by Bandit rule {finding.ruleId}
                  </p>
                </div>
                <button
                  onClick={() => handleCopyCode(finding.vulnerableCode)}
                  className="inline-flex items-center gap-1 rounded-lg border border-black/[0.08] bg-white px-2.5 py-1 text-xs text-[#424245] hover:bg-[#fbfbfd]"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-[#34c759]" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              {/* Code Box */}
              <div className="overflow-hidden rounded-2xl border border-black/[0.08] bg-[#fbfbfd]">
                <div className="flex items-center justify-between border-b border-black/[0.06] bg-[#f5f5f7] px-4 py-2 text-[11px] font-mono text-[#6e6e73]">
                  <span>{finding.filePath}</span>
                  <span className="text-[#d70015] font-semibold">
                    Lines {finding.lineNumber}–{finding.endLineNumber || finding.lineNumber}
                  </span>
                </div>
                <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-[#1d1d1f]">
                  <code>{finding.vulnerableCode}</code>
                </pre>
              </div>

              {/* Summary Callout */}
              <div className="rounded-xl border border-red-200 bg-red-50/40 p-4">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="h-4 w-4 text-[#d70015] shrink-0 mt-0.5" />
                  <div className="text-xs text-[#1d1d1f] leading-relaxed">
                    <strong>Vulnerability Statement: </strong>
                    {finding.description}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: AI EXPLANATION */}
          {activeTab === 'ai' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between rounded-xl border border-black/[0.06] bg-[#fbfbfd] p-3 text-xs">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[#0071e3]" />
                  <span className="font-semibold text-[#1d1d1f]">
                    Generated by {finding.aiExplanation.suggestedByModel}
                  </span>
                </div>
                <span className="text-[11px] text-[#86868b]">Local inference · Zero cloud transfer</span>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider">
                  Executive Summary
                </h3>
                <p className="mt-1 text-sm text-[#1d1d1f] leading-relaxed">
                  {finding.aiExplanation.summary}
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-black/[0.06] p-4 bg-[#fbfbfd]">
                  <h4 className="text-xs font-semibold text-[#1d1d1f] mb-1">
                    Root Cause Analysis
                  </h4>
                  <p className="text-xs text-[#6e6e73] leading-relaxed">
                    {finding.aiExplanation.rootCause}
                  </p>
                </div>

                <div className="rounded-xl border border-black/[0.06] p-4 bg-[#fbfbfd]">
                  <h4 className="text-xs font-semibold text-[#1d1d1f] mb-1">
                    Security Impact
                  </h4>
                  <p className="text-xs text-[#6e6e73] leading-relaxed">
                    {finding.aiExplanation.impact}
                  </p>
                </div>
              </div>

              <div className="rounded-xl border border-black/[0.06] p-4 bg-[#fbfbfd]">
                <h4 className="text-xs font-semibold text-[#1d1d1f] mb-1">
                  Attack Vector & Proof of Concept Scenario
                </h4>
                <p className="text-xs text-[#6e6e73] leading-relaxed">
                  {finding.aiExplanation.attackVector}
                </p>
              </div>
            </div>
          )}

          {/* TAB 3: SUGGESTED REMEDIATION */}
          {activeTab === 'fix' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-[#1d1d1f]">
                    Remediated Source Code Implementation
                  </h3>
                  <p className="text-[11px] text-[#86868b]">
                    AST-verified patch preserving type contracts and parameter bounds
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleDownloadPatch}
                    className="inline-flex items-center gap-1 rounded-lg border border-black/[0.08] bg-white px-2.5 py-1 text-xs text-[#424245] hover:bg-[#fbfbfd]"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>Download .diff</span>
                  </button>
                  <button
                    onClick={() => handleCopyCode(finding.remediatedCode)}
                    className="inline-flex items-center gap-1 rounded-lg border border-black/[0.08] bg-white px-2.5 py-1 text-xs text-[#424245] hover:bg-[#fbfbfd]"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-[#34c759]" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>

              {/* Remediated Code box */}
              <div className="overflow-hidden rounded-2xl border border-emerald-200 bg-[#fbfbfd]">
                <div className="flex items-center justify-between border-b border-emerald-100 bg-emerald-50/50 px-4 py-2 text-[11px] font-mono text-emerald-800">
                  <span>{finding.filePath} (Remediated)</span>
                  <span className="font-semibold text-[#34c759]">Ready to Apply</span>
                </div>
                <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-[#1d1d1f]">
                  <code>{finding.remediatedCode}</code>
                </pre>
              </div>

              {/* Diff Snippet */}
              <div>
                <h4 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider mb-2">
                  Unified Git Diff
                </h4>
                <div className="rounded-xl border border-black/[0.08] bg-[#1d1d1f] p-4 text-white font-mono text-xs">
                  <pre className="overflow-x-auto whitespace-pre leading-relaxed text-[#f5f5f7]">
                    {finding.patchDiff}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PYTEST VERIFICATION */}
          {activeTab === 'test' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-[#1d1d1f]">
                    Adversarial Pytest Security Suite
                  </h3>
                  <p className="text-[11px] text-[#86868b]">
Tests have not been executed for this uploaded project. A real verification backend is not connected yet.
                  </p>
                </div>

                <button
                  onClick={handleRunVerification}
                  
                  className="inline-flex items-center gap-1.5 rounded-full bg-[#0071e3] px-3.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed] active:scale-[0.98] disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Request Verification (not connected)</span>
                </button>
              </div>

              {/* Test Code */}
              <div className="overflow-hidden rounded-2xl border border-black/[0.08] bg-[#fbfbfd]">
                <div className="flex items-center justify-between border-b border-black/[0.06] bg-[#f5f5f7] px-4 py-2 text-[11px] font-mono text-[#6e6e73]">
                  <span>{finding.testVerification.testFile}</span>
                  <span className="text-[#0071e3] font-semibold">
                    {finding.testVerification.testFunction}
                  </span>
                </div>
                <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-[#1d1d1f]">
                  <code>{finding.testVerification.code}</code>
                </pre>
              </div>

              {/* Execution Log */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider">
                    Pytest Execution Log
                  </h4>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-[#86868b]">Execution Time:</span>
                    <span className="font-mono font-semibold text-[#1d1d1f]">
                      {finding.testVerification.executionTimeMs}ms
                    </span>
                  </div>
                </div>

                <div className="rounded-xl border border-black/[0.08] bg-[#1d1d1f] p-4 text-white font-mono text-xs">
                  <div className="flex items-center gap-2 mb-2 pb-2 border-b border-white/10 text-[11px] text-[#86868b]">
                    <ShieldCheck className="h-3.5 w-3.5 text-[#34c759]" />
                    <span>Pytest 8.2 Runner Result</span>
                  </div>
                  <pre className="overflow-x-auto whitespace-pre leading-relaxed text-[#34c759]">
                    {finding.testVerification.outputLog}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer / Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-black/[0.06] bg-[#fbfbfd] p-4 sm:px-6">
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#86868b]">
              Verification:
            </span>
            <span className="text-xs font-semibold text-[#1d1d1f]">
              {finding.verificationStatus}
            </span>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadPatch}
              className="rounded-full border border-black/[0.1] bg-white px-4 py-2 text-xs font-medium text-[#1d1d1f] hover:bg-[#f5f5f7] transition-colors"
            >
              Export Patch (.diff)
            </button>

            {finding.verificationStatus !== 'Verified Fixed' ? (
              <button
                onClick={() => {
                  onApplyFix(finding.id);
                  onClose();
                }}
                className="inline-flex items-center gap-1.5 rounded-full bg-[#34c759] px-5 py-2 text-xs font-medium text-white shadow-sm hover:bg-[#30b753] active:scale-[0.98] transition-all"
              >
                <CheckCircle2 className="h-4 w-4" />
                <span>Apply Remediation (not connected)</span>
              </button>
            ) : (
              <button
                onClick={onClose}
                className="rounded-full bg-[#1d1d1f] px-5 py-2 text-xs font-medium text-white shadow-sm hover:bg-black transition-colors"
              >
                Done
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
