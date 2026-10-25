import React, { useState, useRef, useEffect } from 'react';
import { 
  X, 
  Upload, 
  FileArchive, 
  CheckCircle2, 
  Sliders, 
  Terminal, 
  Cpu, 
  ShieldCheck, 
  Loader2, 
  FileCode,
  ArrowRight,
  AlertCircle
} from 'lucide-react';
import { RecentScan } from '../types';

const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://127.0.0.1:8765';

interface ScanUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanCompleted: (newScan: RecentScan, findings: any[]) => void;
  initialPreset?: string;
}

type ScanStage = 'idle' | 'uploading' | 'bandit' | 'qwen' | 'pytest' | 'completed';

export const ScanUploadModal: React.FC<ScanUploadModalProps> = ({
  isOpen,
  onClose,
  onScanCompleted,
  initialPreset,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [scanStage, setScanStage] = useState<ScanStage>('idle');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  if (!isOpen) return null;

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.zip')) {
        setSelectedFile(file);
      }
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
    }
  };

  const startScan = async () => {
    if (!selectedFile) {
      alert('Please select a ZIP file to scan.');
      return;
    }

    setScanStage('uploading');
    setProgress(10);
    setLogs([`Uploading ${selectedFile.name} to PatchProof...`]);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      setScanStage('bandit');
      const response = await fetch(
        `${API_BASE_URL}/api/scan-zip`,
        {
         method: 'POST',
         body: formData,
        }
      );

      if (!response.ok) {
        throw new Error(await response.text());
      }

      const report = await response.json();
      const findings = report.findings ?? [];
      const total = report.total_findings ?? findings.length;
      if (report.ai_analysis_status === 'completed') {
        setScanStage('qwen');
        setLogs((current) => [...current, `AI analysis completed${report.ai_model ? ` (${report.ai_model})` : ''}.`]);
      } else {
        setLogs((current) => [...current, 'AI analysis unavailable; showing static scanner findings.']);
      }
      if (report.tests_executed === false) {
        setLogs((current) => [...current, 'Uploaded project tests were not executed for safety.']);
      }

      setProgress(100);
      setScanStage('completed');
      setLogs([
        `ZIP uploaded: ${report.filename}`,
        `Real scan completed: ${total} finding(s).`,
        ...findings.map((f: any) => {
          const original = Array.isArray(f.original_records) ? f.original_records[0] : undefined;
          const message = original?.finding?.message ?? original?.message ?? f.category ?? 'Security finding';
          const classification = f.classification ? ` [${f.classification}]` : '';
          return `[${f.severity ?? 'UNKNOWN'}] ${f.file ?? 'unknown file'}:${f.line ?? 0}${classification} — ${message}`;
        }),
        ...(report.errors ?? []).map((e: string) => `Warning: ${e}`),
      ]);

      onScanCompleted({
        id: `SCAN-${Date.now()}`,
        projectName: report.filename,
        branch: 'uploaded ZIP',
        commitHash: 'local',
        scanDate: new Date().toISOString().replace('T', ' ').substring(0, 16),
        durationSeconds: 0,
        filesScanned: Number(report.files_scanned ?? 0),
        linesOfCode: 0,
        findingsCount: {
          critical: findings.filter((f: any) => String(f.severity).toUpperCase() === 'CRITICAL').length,
          high: findings.filter((f: any) => String(f.severity).toUpperCase() === 'HIGH').length,
          medium: findings.filter((f: any) => String(f.severity).toUpperCase() === 'MEDIUM').length,
          low: findings.filter((f: any) => ['LOW', 'INFO', 'INFORMATIONAL'].includes(String(f.severity).toUpperCase())).length,
          total,
        },
        verifiedFixes: 0,
        status: 'Completed',
        scannerEngines: report.ai_analysis_status === 'completed'
          ? ['PatchProof IDOR Scanner', 'Bandit', report.ai_model || 'Local AI Analyzer']
          : ['PatchProof IDOR Scanner', 'Bandit'],
      }, findings);
    } catch (error) {
      setScanStage('idle');
      setLogs([]);
      alert(
        `Scan failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    };

  const resetScan = () => {
    setScanStage('idle');
    setProgress(0);
    setLogs([]);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/40 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl rounded-3xl border border-black/[0.08] bg-white p-6 sm:p-8 shadow-[0_20px_60px_rgba(0,0,0,0.12)] max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-5 border-b border-black/[0.06]">
          <div>
            <h2 className="text-xl font-semibold tracking-tight text-[#1d1d1f]">
              Scan Python Project
            </h2>
            <p className="mt-0.5 text-xs text-[#6e6e73]">
              Upload a source archive for static analysis and local AI review. Uploaded project tests are not executed automatically.
            </p>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-full text-[#86868b] hover:bg-black/[0.05] hover:text-[#1d1d1f] transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {scanStage === 'idle' ? (
          <div className="mt-6 space-y-6">
            {/* Upload Area */}
            <div>
              <label className="block text-xs font-medium text-[#1d1d1f] mb-2">
                Source ZIP Archive
              </label>
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center cursor-pointer transition-all ${
                  isDragging
                    ? 'border-[#0071e3] bg-[#0071e3]/[0.02]'
                    : selectedFile
                    ? 'border-[#34c759] bg-[#34c759]/[0.02]'
                    : 'border-black/[0.12] bg-[#fbfbfd] hover:border-black/[0.2] hover:bg-white'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  onChange={handleFileInputChange}
                  className="hidden"
                />

                {selectedFile ? (
                  <div className="flex flex-col items-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[#34c759]/10 text-[#34c759] mb-3">
                      <FileArchive className="h-6 w-6" />
                    </div>
                    <span className="text-sm font-semibold text-[#1d1d1f]">
                      {selectedFile.name}
                    </span>
                    <span className="mt-1 text-xs text-[#86868b]">
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB · Ready to scan
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFile(null);
                      }}
                      className="mt-3 text-xs text-[#0071e3] hover:underline"
                    >
                      Remove file
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-col items-center">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-black/[0.04] text-[#1d1d1f] mb-3">
                      <Upload className="h-5 w-5 text-[#6e6e73]" />
                    </div>
                    <p className="text-sm font-medium text-[#1d1d1f]">
                      Drag and drop your project ZIP here, or <span className="text-[#0071e3]">browse</span>
                    </p>
                    <p className="mt-1 text-xs text-[#86868b]">
                      Supports Python repositories containing FastAPI, Flask, Django, or Celery.
                    </p>
                  </div>
                )}
              </div>
            </div>


<div className="flex flex-col gap-4 pt-2">
  <p className="text-xs text-[#6e6e73]">
    Upload a ZIP archive to run a real scan. Demo presets are not connected to the backend.
  </p>

  <div className="flex justify-end">
    <button
      type="button"
      onClick={startScan}
      disabled={!selectedFile}
      className="inline-flex items-center gap-2 rounded-full bg-[#0071e3] px-6 py-3 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#0077ed] disabled:cursor-not-allowed disabled:opacity-40"
    >
      <ShieldCheck className="h-4 w-4" />
      Start Scan
      <ArrowRight className="h-4 w-4" />
    </button>
  </div>
</div>
          </div>
        ) : (
          /* Live Scanning State */
          <div className="mt-6 space-y-6">
            {/* Stage Progress Pills */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {scanStage !== 'completed' ? (
                  <Loader2 className="h-4 w-4 animate-spin text-[#0071e3]" />
                ) : (
                  <CheckCircle2 className="h-4 w-4 text-[#34c759]" />
                )}
                <span className="text-sm font-semibold text-[#1d1d1f]">
                  {scanStage === 'uploading' && 'Uploading ZIP and preparing the scan...'}
                  {scanStage === 'bandit' && 'Running static security analysis...'}
                  {scanStage === 'qwen' && 'Analyzing findings with the configured local Ollama model...'}
                  {scanStage === 'pytest' && 'Verification is not run for uploaded projects.'}
                  {scanStage === 'completed' && 'Security scan completed!'}
                </span>
              </div>
              <span className="text-xs font-semibold text-[#1d1d1f] font-mono tabular-nums">
                {progress}%
              </span>
            </div>

            {/* Apple-style Progress bar */}
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-black/[0.06]">
              <div
                className="h-full bg-[#0071e3] transition-all duration-300 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Stages Grid */}
            <div className="grid grid-cols-4 gap-2 text-center text-xs">
              <div className={`p-2.5 rounded-xl border ${scanStage === 'uploading' || progress > 25 ? 'bg-white border-black/[0.1] text-[#1d1d1f]' : 'bg-[#fbfbfd] border-transparent text-[#86868b]'}`}>
                <span className="block font-medium">1. Unpack</span>
                <span className="text-[10px] text-[#86868b]">AST Parsing</span>
              </div>
              <div className={`p-2.5 rounded-xl border ${scanStage === 'bandit' || progress > 55 ? 'bg-white border-black/[0.1] text-[#1d1d1f]' : 'bg-[#fbfbfd] border-transparent text-[#86868b]'}`}>
                <span className="block font-medium">2. Bandit</span>
                <span className="text-[10px] text-[#86868b]">Static Rules</span>
              </div>
              <div className={`p-2.5 rounded-xl border ${scanStage === 'qwen' || progress > 85 ? 'bg-white border-black/[0.1] text-[#1d1d1f]' : 'bg-[#fbfbfd] border-transparent text-[#86868b]'}`}>
                <span className="block font-medium">3. Qwen</span>
                <span className="text-[10px] text-[#86868b]">Local LLM</span>
              </div>
              <div className={`p-2.5 rounded-xl border ${scanStage === 'completed' || progress === 100 ? 'bg-white border-black/[0.1] text-[#1d1d1f]' : 'bg-[#fbfbfd] border-transparent text-[#86868b]'}`}>
                <span className="block font-medium">4. Tests</span>
                <span className="text-[10px] text-[#86868b]">Not executed</span>
              </div>
            </div>

            {/* Live Terminal Log Stream */}
            <div className="rounded-2xl border border-black/[0.08] bg-[#1d1d1f] p-4 text-white shadow-inner">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-white/10 text-[11px] text-[#86868b]">
                <div className="flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-[#34c759]" />
                  <span>patchproof-engine.log</span>
                </div>
                <span className="font-mono text-[10px]">STDOUT / STDERR</span>
              </div>
              <div
                ref={logContainerRef}
                className="h-44 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#f5f5f7] space-y-1"
              >
                {logs.map((log, idx) => (
                  <div key={idx} className="flex gap-2">
                    <span className="text-[#86868b] select-none">{'>'}</span>
                    <span className={log.includes('PASSED') ? 'text-[#34c759]' : log.includes('Bandit') ? 'text-sky-300' : 'text-[#f5f5f7]'}>
                      {log}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Finished Action */}
            {scanStage === 'completed' && (
              <div className="flex items-center justify-between pt-2">
                <div className="flex items-center gap-2 text-xs text-[#34c759]">
                  <CheckCircle2 className="h-4 w-4" />
                  <span className="font-medium">Scan completed. Review classifications; uploaded code tests were not run.</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={resetScan}
                    className="rounded-full px-4 py-2 text-xs font-medium text-[#6e6e73] hover:text-[#1d1d1f] hover:bg-black/[0.04]"
                  >
                    Scan Another Project
                  </button>
                  <button
                    onClick={onClose}
                    className="inline-flex items-center gap-1.5 rounded-full bg-[#0071e3] px-5 py-2 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed]"
                  >
                    <span>Inspect Findings</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
