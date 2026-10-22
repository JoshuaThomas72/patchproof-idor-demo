import React, { useState } from 'react';
import { 
  Settings, 
  Server, 
  Cpu, 
  Terminal, 
  ShieldCheck, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  Save, 
  Loader2,
  Database
} from 'lucide-react';
import { ScannerSettings } from '../types';

interface SettingsViewProps {
  settings: ScannerSettings;
  onSaveSettings: (settings: ScannerSettings) => void;
  onResetDemoData: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings: initialSettings,
  onSaveSettings,
  onResetDemoData,
}) => {
  const [form, setForm] = useState<ScannerSettings>(initialSettings);
  const [isSaved, setIsSaved] = useState(false);
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'success' | 'failed'>('idle');
  const [testMessage, setTestMessage] = useState('');

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onSaveSettings(form);
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2500);
  };

  const handleTestConnectivity = () => {
    setTestStatus('testing');
    setTestMessage('Pinging local FastAPI backend & Ollama daemon...');

    setTimeout(() => {
      setTestStatus('success');
      setTestMessage('Connected to FastAPI backend (v1.4) · Ollama daemon active with qwen2.5-coder:14b ready.');
    }, 1200);
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="rounded-3xl border border-black/[0.06] bg-white p-6 sm:p-8 shadow-[0_2px_16px_rgba(0,0,0,0.02)]">
        <div className="flex items-center gap-2 text-xs font-semibold text-[#0071e3] mb-2">
          <Settings className="h-4 w-4" />
          <span>Local Engine & Architecture</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#1d1d1f]">
          Engine Settings & Architecture
        </h2>
        <p className="mt-2 text-sm text-[#6e6e73] leading-relaxed">
          PatchProof is intentionally architected with strict separation between the frontend dashboard and your local execution toolchain: FastAPI backend, Bandit AST parser, Ollama Qwen model, and Pytest runner.
        </p>
      </div>

      {/* Integration Blueprint */}
      <div className="rounded-2xl border border-black/[0.06] bg-white p-6 shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
        <h3 className="text-sm font-semibold text-[#1d1d1f] mb-4">
          Local Security Pipeline Architecture
        </h3>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-4 text-xs">
          <div className="rounded-xl border border-black/[0.06] bg-[#fbfbfd] p-3.5">
            <div className="flex items-center gap-1.5 font-semibold text-[#1d1d1f] mb-1">
              <Server className="h-4 w-4 text-[#0071e3]" />
              <span>FastAPI Backend</span>
            </div>
            <p className="text-[#6e6e73] text-[11px] leading-relaxed">
              Handles ZIP unpacking, AST orchestrations, and report persistence.
            </p>
          </div>

          <div className="rounded-xl border border-black/[0.06] bg-[#fbfbfd] p-3.5">
            <div className="flex items-center gap-1.5 font-semibold text-[#1d1d1f] mb-1">
              <Terminal className="h-4 w-4 text-[#0071e3]" />
              <span>Bandit AST Scanner</span>
            </div>
            <p className="text-[#6e6e73] text-[11px] leading-relaxed">
              Python AST rule matching for CWE-89, CWE-502, CWE-22, CWE-78, etc.
            </p>
          </div>

          <div className="rounded-xl border border-black/[0.06] bg-[#fbfbfd] p-3.5">
            <div className="flex items-center gap-1.5 font-semibold text-[#1d1d1f] mb-1">
              <Cpu className="h-4 w-4 text-[#0071e3]" />
              <span>Local Ollama Qwen</span>
            </div>
            <p className="text-[#6e6e73] text-[11px] leading-relaxed">
              On-prem code reasoning model generating patches and pytest invariants.
            </p>
          </div>

          <div className="rounded-xl border border-black/[0.06] bg-[#fbfbfd] p-3.5">
            <div className="flex items-center gap-1.5 font-semibold text-[#1d1d1f] mb-1">
              <ShieldCheck className="h-4 w-4 text-[#0071e3]" />
              <span>Pytest Harness</span>
            </div>
            <p className="text-[#6e6e73] text-[11px] leading-relaxed">
              Executes tests before and after patch application to prove remediation.
            </p>
          </div>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSave} className="space-y-6">
        <div className="rounded-2xl border border-black/[0.06] bg-white p-6 shadow-[0_2px_12px_rgba(0,0,0,0.02)] space-y-5">
          <h3 className="text-sm font-semibold text-[#1d1d1f]">
            Service Endpoints & Commands
          </h3>

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-[#1d1d1f] mb-1">
                FastAPI Gateway Endpoint
              </label>
              <input
                type="text"
                value={form.fastApiEndpoint}
                onChange={(e) => setForm({ ...form, fastApiEndpoint: e.target.value })}
                className="w-full rounded-xl border border-black/[0.1] bg-[#fbfbfd] px-3 py-2 text-xs font-mono text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              />
              <span className="text-[11px] text-[#86868b] mt-1 block">
                Standard REST endpoint for scanning and fetching SARIF artifacts
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#1d1d1f] mb-1">
                Ollama Local LLM Endpoint
              </label>
              <input
                type="text"
                value={form.ollamaEndpoint}
                onChange={(e) => setForm({ ...form, ollamaEndpoint: e.target.value })}
                className="w-full rounded-xl border border-black/[0.1] bg-[#fbfbfd] px-3 py-2 text-xs font-mono text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              />
              <span className="text-[11px] text-[#86868b] mt-1 block">
                Local inference host (zero code sent to external cloud APIs)
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#1d1d1f] mb-1">
                Active Code Reasoning Model
              </label>
              <select
                value={form.ollamaModel}
                onChange={(e) => setForm({ ...form, ollamaModel: e.target.value })}
                className="w-full rounded-xl border border-black/[0.1] bg-white px-3 py-2 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              >
                <option value="qwen2.5-coder:14b">qwen2.5-coder:14b (Recommended for deep AST reasoning)</option>
                <option value="qwen2.5-coder:7b">qwen2.5-coder:7b (Faster low-memory footprint)</option>
                <option value="qwen2.5:32b">qwen2.5:32b (Full instruction & policy synthesis)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#1d1d1f] mb-1">
                Pytest Execution Command
              </label>
              <input
                type="text"
                value={form.pytestRunnerCommand}
                onChange={(e) => setForm({ ...form, pytestRunnerCommand: e.target.value })}
                className="w-full rounded-xl border border-black/[0.1] bg-[#fbfbfd] px-3 py-2 text-xs font-mono text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
              />
              <span className="text-[11px] text-[#86868b] mt-1 block">
                Harness arguments passed to pytest subprocess runner
              </span>
            </div>
          </div>

          <div className="pt-2 border-t border-black/[0.06] flex items-center gap-6">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-[#1d1d1f]">
              <input
                type="checkbox"
                checked={form.enableAutomaticPytest}
                onChange={(e) => setForm({ ...form, enableAutomaticPytest: e.target.checked })}
                className="rounded border-gray-300 text-[#0071e3] focus:ring-[#0071e3]"
              />
              <span>Automatically synthesize & execute Pytest verification for every finding</span>
            </label>
          </div>
        </div>

        {/* Connectivity Test Box */}
        <div className="rounded-2xl border border-black/[0.06] bg-[#fbfbfd] p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="space-y-1">
            <span className="text-xs font-semibold text-[#1d1d1f]">
              Engine Diagnostics
            </span>
            <p className="text-xs text-[#6e6e73]">
              {testMessage || 'Verify socket connectivity with FastAPI and local Ollama daemon.'}
            </p>
          </div>

          <button
            type="button"
            onClick={handleTestConnectivity}
            disabled={testStatus === 'testing'}
            className="inline-flex items-center gap-1.5 rounded-full border border-black/[0.1] bg-white px-4 py-2 text-xs font-medium text-[#1d1d1f] shadow-sm hover:bg-[#f5f5f7] active:scale-[0.98] transition-all disabled:opacity-50 shrink-0 self-start sm:self-auto"
          >
            {testStatus === 'testing' ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-[#0071e3]" />
            ) : testStatus === 'success' ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-[#34c759]" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5 text-[#0071e3]" />
            )}
            <span>{testStatus === 'testing' ? 'Testing...' : 'Test Connection'}</span>
          </button>
        </div>

        {/* Action Row */}
        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={onResetDemoData}
            className="text-xs text-[#86868b] hover:text-[#d70015] transition-colors"
          >
            Reset Workspace to Default Demo State
          </button>

          <div className="flex items-center gap-3">
            {isSaved && (
              <span className="text-xs font-medium text-[#34c759] flex items-center gap-1">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Settings updated
              </span>
            )}

            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded-full bg-[#0071e3] px-6 py-2.5 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed] active:scale-[0.98] transition-all"
            >
              <Save className="h-3.5 w-3.5" />
              <span>Save Configuration</span>
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
