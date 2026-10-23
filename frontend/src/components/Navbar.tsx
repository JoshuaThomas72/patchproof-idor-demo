import React, { useState } from 'react';
import { Shield, Sparkles, Menu, X, ArrowUpRight, CheckCircle2 } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenScanModal: () => void;
  findingsCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onOpenScanModal,
  findingsCount,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Overview' },
    { id: 'scan', label: 'Scan Project' },
    { id: 'findings', label: `Findings (${findingsCount})` },
    { id: 'verification', label: 'Verification' },
    { id: 'reports', label: 'Reports' },
    { id: 'settings', label: 'Settings' },
  ];

  const handleNavClick = (id: string) => {
    if (id === 'scan') {
      onOpenScanModal();
    } else {
      setActiveTab(id);
    }
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-black/[0.06] bg-[#fbfbfd]/85 backdrop-blur-xl transition-all">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand Zone */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTab('overview')}
            className="group flex items-center gap-2.5 text-left focus:outline-none"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#1d1d1f] text-white shadow-sm transition-transform duration-200 group-hover:scale-105">
              <Shield className="h-4 w-4 text-white" strokeWidth={2.2} />
            </div>
            <div className="flex flex-col">
              <span className="text-base font-semibold tracking-tight text-[#1d1d1f]">
                PatchProof
              </span>
            </div>
          </button>

          {/* Demo Data indicator */}
          <div className="hidden lg:flex items-center gap-1.5 rounded-full border border-black/[0.06] bg-black/[0.02] px-2.5 py-0.5 text-[11px] font-medium text-[#6e6e73]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#0071e3]" />
            <span>Demo Workspace</span>
          </div>
        </div>

        {/* Desktop Nav Links */}
        <nav className="hidden md:flex items-center gap-1 text-[13px] font-medium text-[#6e6e73]">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`rounded-md px-3 py-1.5 transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-black/[0.04] text-[#1d1d1f] font-semibold'
                    : 'text-[#6e6e73] hover:text-[#1d1d1f] hover:bg-black/[0.02]'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Action Zone */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onOpenScanModal}
            className="inline-flex items-center justify-center gap-1.5 rounded-full bg-[#0071e3] px-3.5 py-1.5 text-[13px] font-medium text-white shadow-sm transition-all hover:bg-[#0077ed] active:scale-[0.98] whitespace-nowrap"
          >
            <span>Start a Scan</span>
          </button>

          {/* Mobile hamburger */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="flex h-8 w-8 items-center justify-center rounded-md text-[#6e6e73] hover:bg-black/[0.04] hover:text-[#1d1d1f] md:hidden"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="border-b border-black/[0.06] bg-[#fbfbfd] px-4 py-3 md:hidden">
          <div className="flex flex-col gap-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`flex items-center justify-between rounded-lg px-3 py-2 text-sm font-medium text-left ${
                  activeTab === item.id
                    ? 'bg-black/[0.05] text-[#1d1d1f] font-semibold'
                    : 'text-[#6e6e73] hover:bg-black/[0.02] hover:text-[#1d1d1f]'
                }`}
              >
                <span>{item.label}</span>
                {activeTab === item.id && <CheckCircle2 className="h-4 w-4 text-[#0071e3]" />}
              </button>
            ))}
            <div className="mt-2 pt-2 border-t border-black/[0.06] text-xs text-[#86868b] px-3">
              Connected to Simulated Engine (Bandit + Qwen + Pytest)
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
