import React from 'react';
import { ArrowRight, ShieldCheck, Terminal, Cpu, CheckCircle2, Upload } from 'lucide-react';

interface HeroSectionProps {
  onStartScan: () => void;
  onExploreFindings: () => void;
  onSelectSamplePreset: (presetName: string) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onStartScan,
  onExploreFindings,
  onSelectSamplePreset,
}) => {
  return (
    <section className="relative overflow-hidden pt-12 pb-14 text-center sm:pt-16 sm:pb-20">
      {/* Subtle Apple-style diffuse ambient glow */}
      <div 
        aria-hidden="true" 
        className="pointer-events-none absolute inset-x-0 -top-24 mx-auto h-72 max-w-4xl opacity-35 blur-3xl bg-gradient-to-b from-[#0071e3]/20 via-sky-100/30 to-transparent" 
      />

      <div className="relative mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        {/* Subtle pill kicker */}
        <div className="inline-flex items-center gap-2 rounded-full border border-black/[0.08] bg-white px-3.5 py-1 text-xs font-medium text-[#424245] shadow-[0_1px_3px_rgba(0,0,0,0.03)] mb-6 transition-transform hover:scale-[1.01]">
          <span className="flex h-2 w-2 rounded-full bg-[#34c759]" />
          <span>Local Engine Active</span>
          <span className="text-[#86868b]">·</span>
          <span className="text-[#6e6e73]">Bandit + Qwen 2.5 Coder + Pytest</span>
        </div>

        {/* Hero Headline */}
        <h1 className="text-4xl font-semibold tracking-tight text-[#1d1d1f] sm:text-5xl md:text-6xl lg:text-[68px] lg:leading-[1.08] text-balance">
          Security, made clear.
        </h1>

        {/* Description */}
        <p className="mx-auto mt-5 max-w-2xl text-base text-[#6e6e73] sm:text-lg md:text-xl font-normal leading-relaxed text-balance">
          Autonomous code vulnerability detection, precision AI explanations, and verified test-backed remediation — engineered for Python services.
        </p>

        {/* Action Buttons */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3 sm:gap-4">
          <button
            onClick={onStartScan}
            className="inline-flex items-center justify-center gap-2 rounded-full bg-[#0071e3] px-6 py-3 text-sm font-medium text-white shadow-sm transition-all hover:bg-[#0077ed] active:scale-[0.98]"
          >
            <Upload className="h-4 w-4" />
            <span>Start a Scan</span>
          </button>

          <button
            onClick={onExploreFindings}
            className="inline-flex items-center justify-center gap-2 rounded-full border border-black/[0.12] bg-white px-6 py-3 text-sm font-medium text-[#1d1d1f] shadow-sm transition-all hover:bg-[#f5f5f7] active:scale-[0.98]"
          >
            <span>Explore Findings</span>
            <ArrowRight className="h-4 w-4 text-[#86868b]" />
          </button>
        </div>

        {/* Quick sample loader prompt */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-2 text-xs text-[#86868b]">
          <span>Try realistic sample bundles:</span>
          <button
            onClick={() => onSelectSamplePreset('fastapi-auth-service.zip')}
            className="font-medium text-[#0071e3] hover:underline"
          >
            fastapi-auth-service.zip
          </button>
          <span>·</span>
          <button
            onClick={() => onSelectSamplePreset('payment-webhook-worker.zip')}
            className="font-medium text-[#0071e3] hover:underline"
          >
            payment-webhook-worker.zip
          </button>
          <span>·</span>
          <button
            onClick={() => onSelectSamplePreset('flask-data-pipeline.zip')}
            className="font-medium text-[#0071e3] hover:underline"
          >
            flask-data-pipeline.zip
          </button>
        </div>

        {/* Core Principles / Architecture Strip */}
        <div className="mt-14 grid grid-cols-1 gap-4 sm:grid-cols-3 text-left">
          <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] transition-all hover:border-black/[0.12] hover:shadow-[0_4px_16px_rgba(0,0,0,0.04)]">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#f5f5f7] text-[#1d1d1f] mb-3">
              <Terminal className="h-4 w-4 text-[#0071e3]" />
            </div>
            <h2 className="text-sm font-semibold text-[#1d1d1f]">AST Static Detection</h2>
            <p className="mt-1 text-xs text-[#6e6e73] leading-relaxed">
              Deterministic Bandit rule matching on Python Abstract Syntax Trees for zero false positives on common CWEs.
            </p>
          </div>

          <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] transition-all hover:border-black/[0.12] hover:shadow-[0_4px_16px_rgba(0,0,0,0.04)]">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#f5f5f7] text-[#1d1d1f] mb-3">
              <Cpu className="h-4 w-4 text-[#0071e3]" />
            </div>
            <h2 className="text-sm font-semibold text-[#1d1d1f]">Local Qwen Reasoning</h2>
            <p className="mt-1 text-xs text-[#6e6e73] leading-relaxed">
              Synthesizes secure context-aware remediations via local Ollama inference without leaking proprietary source code.
            </p>
          </div>

          <div className="rounded-2xl border border-black/[0.06] bg-white p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] transition-all hover:border-black/[0.12] hover:shadow-[0_4px_16px_rgba(0,0,0,0.04)]">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#f5f5f7] text-[#1d1d1f] mb-3">
              <ShieldCheck className="h-4 w-4 text-[#0071e3]" />
            </div>
            <h2 className="text-sm font-semibold text-[#1d1d1f]">Pytest Verification</h2>
            <p className="mt-1 text-xs text-[#6e6e73] leading-relaxed">
              Every synthesized fix is backed by an automated adversarial test case executed before and after patching.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
