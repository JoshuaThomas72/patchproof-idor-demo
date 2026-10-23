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
import { DEMO_PROJECT_PRESETS } from '../data/mockData';
import { RecentScan } from '../types';

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
  const [selectedPreset, setSelectedPreset] = useState<string>(
    initialPreset || DEMO_PROJECT_PRESETS[0].name
  );
  const [isDragging, setIsDragging] = useState(false);
  const [scanStage, setScanStage] = useState<ScanStage>('idle');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState('qwen2.5-coder:14b');
  const [enablePytest, setEnablePytest] = useState(true);
  const [banditStrictness, setBanditStrictness] = useState<'standard' | 'high'>('high');

  const fileInputRef = useRef<HTMLInputElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialPreset) {
      setSelectedPreset(initialPreset);
      setSelectedFile(null);
    }
  }, [initialPreset]);

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
        setSelectedPreset('');
      }
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setSelectedPreset('');
    }
  };

  const handleSelectPreset = (presetName: string) => {
    setSelectedPreset(presetName);
    setSelectedFile(null);
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

      const response = await fetch(
        'http://127.0.0.1:8765/api/scan-zip',
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

      setProgress(100);
      setScanStage('completed');
      setLogs([
        `ZIP uploaded: ${report.filename}`,
        `Real scan completed: ${total} finding(s).`,
        ...findings.map(
          (f: { severity: string; file: string; line: number; message: string }) =>
            `[${f.severity}] ${f.file}:${f.line} — ${f.message}`
        ),
        ...(report.errors ?? []).map((e: string) => `Warning: ${e}`),
      ]);

      onScanCompleted({
        id: `SCAN-${Date.now()}`,
        projectName: report.filename,
        branch: 'local ZIP',
        commitHash: 'local',
        scanDate: new Date().toISOString().replace('T', ' ').substring(0, 16),
        durationSeconds: 0,
        filesScanned: 0,
        linesOfCode: 0,
        findingsCount: {
          critical: 0,
          high: 0,
          medium: total,
          low: 0,
          total,
        },
        verifiedFixes: 0,
        status: 'Completed',
        scannerEngines: ['PatchProof IDOR Scanner', 'Bandit'],
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
              Upload a source archive to perform Bandit AST analysis, local Qwen reasoning, and Pytest verification.
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
                        setSelectedPreset(DEMO_PROJECT_PRESETS[0].name);
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

            {/* Demo Presets (for instant testing without needing an external zip) */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-[#1d1d1f]">
                  Or choose a realistic Demo Project Preset:
                </label>
                <span className="text-[11px] text-[#86868b]">Fast simulated run</span>
              </div>

              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                {DEMO_PROJECT_PRESETS.map((preset) => {
                  const isSelected = selectedPreset === preset.name && !selectedFile;
                  return (
                    <button
                      key={preset.name}
                      type="button"
                      onClick={() => handleSelectPreset(preset.name)}
                      className={`flex flex-col rounded-xl border p-3 text-left transition-all ${
                        isSelected
                          ? 'border-[#0071e3] bg-[#0071e3]/[0.04] shadow-sm'
                          : 'border-black/[0.06] bg-white hover:border-black/[0.14] hover:bg-[#fbfbfd]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <FileCode className={`h-4 w-4 ${isSelected ? 'text-[#0071e3]' : 'text-[#86868b]'}`} />
                        {isSelected && <CheckCircle2 className="h-3.5 w-3.5 text-[#0071e3]" />}
                      </div>
                      <span className="mt-2 text-xs font-semibold text-[#1d1d1f] truncate">
                        {preset.name}
                      </span>
                      <p className="mt-1 text-[11px] text-[#6e6e73] line-clamp-2 leading-snug">
                        {preset.description}
                      </p>
                      <span className="mt-2 text-[10px] text-[#86868b] font-mono">
                        {preset.language}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Pipeline Configuration Accordion */}
            <div className="rounded-2xl border border-black/[0.06] bg-[#fbfbfd] p-4">
              <div className="flex items-center gap-2 mb-3">
                <Sliders className="h-4 w-4 text-[#0071e3]" />
                <span className="text-xs font-semibold text-[#1d1d1f]">
                  Scanner & Local AI Engine Configuration
                </span>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 text-xs">
                <div>
                  <label className="block text-[#6e6e73] mb-1 font-medium">AST Rule Engine</label>
                  <select
                    value={banditStrictness}
                    onChange={(e) => setBanditStrictness(e.target.value as 'standard' | 'high')}
                    className="w-full rounded-lg border border-black/[0.1] bg-white px-2.5 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
                  >
                    <option value="high">Bandit v1.8 (High Confidence)</option>
                    <option value="standard">Bandit v1.8 (All Confidence)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#6e6e73] mb-1 font-medium">Local Ollama Model</label>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="w-full rounded-lg border border-black/[0.1] bg-white px-2.5 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
                  >
                    <option value="qwen2.5-coder:14b">Qwen 2.5 Coder (14B)</option>
                    <option value="qwen2.5-coder:7b">Qwen 2.5 Coder (7B)</option>
                    <option value="qwen2.5:32b">Qwen 2.5 Instruct (32B)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#6e6e73] mb-1 font-medium">Pytest Verification</label>
                  <label className="flex items-center gap-2 mt-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={enablePytest}
                      onChange={(e) => setEnablePytest(e.target.checked)}
                      className="rounded border-gray-300 text-[#0071e3] focus:ring-[#0071e3]"
                    />
                    <span className="text-[#1d1d1f]">Generate & run invariant tests</span>
                  </label>
                </div>
              </div>
            </div>

            {/* Bottom Actions */}
            <div className="flex items-center justify-between pt-3">
              <span className="text-[11px] text-[#86868b]">
                Target: {selectedFile ? selectedFile.name : selectedPreset}
              </span>
              <div className="flex items-center gap-2.5">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-full px-4 py-2 text-xs font-medium text-[#6e6e73] hover:text-[#1d1d1f] hover:bg-black/[0.04] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={startScan}
                  className="inline-flex items-center gap-1.5 rounded-full bg-[#0071e3] px-5 py-2 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed] active:scale-[0.98] transition-all"
                >
                  <span>Execute Security Scan</span>
                  <ArrowRight className="h-3.5 w-3.5" />
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
                  {scanStage === 'uploading' && 'Unpacking archive and building Python AST...'}
                  {scanStage === 'bandit' && 'Running Bandit AST static security rules...'}
                  {scanStage === 'qwen' && `Synthesizing code reasoning with local ${selectedModel}...`}
                  {scanStage === 'pytest' && 'Executing automated adversarial Pytest harness...'}
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
                <span className="block font-medium">4. Pytest</span>
                <span className="text-[10px] text-[#86868b]">Verification</span>
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
                  <span className="font-medium">Scan completed with 7 verified findings.</span>
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
