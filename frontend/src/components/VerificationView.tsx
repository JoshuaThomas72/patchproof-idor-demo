import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode, 
  Clock, 
  Cpu, 
  Terminal,
  RefreshCw
} from 'lucide-react';
import { SecurityFinding } from '../types';

interface VerificationViewProps {
  findings: SecurityFinding[];
  onRunSingleTest: (findingId: string) => void;
  onRunAllTests: () => void;
}

export const VerificationView: React.FC<VerificationViewProps> = ({
  findings,
  onRunSingleTest,
  onRunAllTests,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding>(findings[0]);
  const [activeTestLog, setActiveTestLog] = useState<string | null>(null);

  const verifiedCount = findings.filter((f) => f.verificationStatus === 'Verified Fixed').length;
  const passRate = ((verifiedCount / findings.length) * 100).toFixed(0);

  const handleRunAll = () => {
    onRunAllTests();
  };

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="rounded-3xl border border-black/[0.06] bg-white p-6 sm:p-8 shadow-[0_2px_16px_rgba(0,0,0,0.02)]">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 text-xs font-semibold text-[#0071e3] mb-2">
              <ShieldCheck className="h-4 w-4" />
              <span>Mathematical Invariant Assurance</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#1d1d1f]">
              Verification Status
            </h2>
            <p className="mt-2 text-sm text-[#6e6e73] leading-relaxed">
Verification status is shown here, but executing tests against uploaded projects is not connected yet. PatchProof does not mark tests as passed unless a real test execution result is returned by the backend.
            </p>
          </div>

          <div className="flex flex-col items-start sm:items-end gap-3 shrink-0">
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-semibold text-[#1d1d1f] tabular-nums">
                {passRate}%
              </span>
              <span className="text-xs text-[#86868b]">pass rate</span>
            </div>
            <span className="text-xs text-[#6e6e73]">
              {verifiedCount} of {findings.length} findings marked verified fixed
            </span>
            <button
              onClick={handleRunAll}
              className="inline-flex items-center gap-2 rounded-full border border-black/[0.1] bg-white px-5 py-2.5 text-xs font-medium text-[#1d1d1f] shadow-sm hover:bg-[#f5f5f7] active:scale-[0.98] transition-all"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Request Verification (not connected)</span>
            </button>
          </div>
        </div>
      </div>

      {/* Verification Pipeline Diagram */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#1d1d1f] mb-1">
            <span className="flex h-5 w-5 items-center justify-center rounded-md bg-[#f5f5f7] text-[11px] font-mono">1</span>
            <span>Bandit AST Detection</span>
          </div>
          <p className="text-xs text-[#6e6e73] leading-relaxed">
            Parses Python syntax trees to isolate raw string queries, unsafe pickle calls, and subprocess execution.
          </p>
        </div>

        <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#1d1d1f] mb-1">
            <span className="flex h-5 w-5 items-center justify-center rounded-md bg-[#f5f5f7] text-[11px] font-mono">2</span>
            <span>AI Finding Analysis</span>
          </div>
          <p className="text-xs text-[#6e6e73] leading-relaxed">
The configured local Ollama model reviews scanner findings and produces evidence-based explanations and suggested fixes.
          </p>
        </div>

        <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#1d1d1f] mb-1">
            <span className="flex h-5 w-5 items-center justify-center rounded-md bg-[#f5f5f7] text-[11px] font-mono">3</span>
            <span>Test Verification</span>
          </div>
          <p className="text-xs text-[#6e6e73] leading-relaxed">
Not yet connected for uploaded targets. Findings remain unverified until a real test run is integrated.
          </p>
        </div>
      </div>

      {/* Two-Column Suite Inspector */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: Test Suites List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between px-1">
            <h3 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider">
              Verification Test Suites ({findings.length})
            </h3>
            <span className="text-[11px] text-[#86868b]">Select to inspect</span>
          </div>

          <div className="space-y-2">
            {findings.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              const isPassed = f.verificationStatus === 'Verified Fixed';
              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`cursor-pointer rounded-2xl border p-4 transition-all ${
                    isSelected
                      ? 'border-[#0071e3] bg-[#0071e3]/[0.03] shadow-sm'
                      : 'border-black/[0.06] bg-white hover:border-black/[0.12] hover:bg-[#fbfbfd]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {isPassed ? (
                        <CheckCircle2 className="h-4 w-4 text-[#34c759] shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-[#d70015] shrink-0" />
                      )}
                      <span className="font-semibold text-xs text-[#1d1d1f]">
                        {f.testVerification.testFunction}
                      </span>
                    </div>
                    <span className="font-mono text-[11px] text-[#86868b] tabular-nums shrink-0">
                      {f.testVerification.executionTimeMs}ms
                    </span>
                  </div>

                  <div className="mt-2 flex items-center gap-2 text-[11px] text-[#6e6e73] pl-6 font-mono truncate">
                    <span>{f.testVerification.testFile}</span>
                  </div>

                  <div className="mt-2 flex items-center justify-between pl-6 text-[11px]">
                    <span className="text-[#86868b]">
                      Target: {f.title}
                    </span>
                    <span className={isPassed ? 'text-[#34c759] font-medium' : 'text-[#d70015] font-medium'}>
                      {isPassed ? 'PASSED' : 'ACTION REQUIRED'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Selected Test Suite Viewer */}
        <div className="lg:col-span-7">
          {selectedFinding && (
            <div className="rounded-3xl border border-black/[0.06] bg-white p-6 shadow-[0_2px_16px_rgba(0,0,0,0.02)] space-y-5">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 text-xs text-[#86868b] mb-1 font-mono">
                    <span>{selectedFinding.testVerification.testFile}</span>
                    <span>·</span>
                    <span>{selectedFinding.testVerification.assertionsCount} assertions</span>
                  </div>
                  <h3 className="text-base font-semibold text-[#1d1d1f]">
                    {selectedFinding.testVerification.testFunction}
                  </h3>
                </div>

                <button
                  onClick={() => onRunSingleTest(selectedFinding.id)}
                  className="inline-flex items-center gap-1.5 rounded-full border border-black/[0.1] bg-white px-3 py-1.5 text-xs font-medium text-[#1d1d1f] hover:bg-[#f5f5f7] transition-colors shadow-sm"
                >
                  <RefreshCw className="h-3 w-3 text-[#0071e3]" />
                  <span>Re-test Invariant</span>
                </button>
              </div>

              {/* Pytest Code Block */}
              <div>
                <h4 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider mb-2">
                  Pytest Source Code
                </h4>
                <div className="overflow-hidden rounded-2xl border border-black/[0.08] bg-[#fbfbfd]">
                  <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-[#1d1d1f]">
                    <code>{selectedFinding.testVerification.code}</code>
                  </pre>
                </div>
              </div>

              {/* Pytest Execution Output */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-semibold text-[#86868b] uppercase tracking-wider">
                    Pytest Standard Output & Assertions
                  </h4>
                  <span className="font-mono text-xs text-[#86868b]">
                    {selectedFinding.testVerification.executionTimeMs}ms execution
                  </span>
                </div>
                <div className="rounded-2xl border border-black/[0.08] bg-[#1d1d1f] p-4 text-white font-mono text-xs">
                  <pre className="overflow-x-auto whitespace-pre leading-relaxed text-[#34c759]">
                    {selectedFinding.testVerification.outputLog}
                  </pre>
                </div>
              </div>

              {/* Invariant Explanation */}
              <div className="rounded-2xl border border-black/[0.06] bg-[#fbfbfd] p-4 text-xs">
                <span className="font-semibold text-[#1d1d1f]">Verified Security Invariant:</span>
                <p className="mt-1 text-[#6e6e73] leading-relaxed">
                  The test executes against the remediated implementation to confirm that injection syntax (e.g. quotes, brackets, commands, or pickle byte sequences) fails safely or raises proper HTTP exceptions, while valid authorized requests continue to process normally.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
