import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  ChevronRight, 
  CheckCircle2, 
  Clock, 
  AlertOctagon, 
  Sparkles,
  ExternalLink,
  Shield,
  FileCode,
  ArrowUpDown,
  Download
} from 'lucide-react';
import { SecurityFinding, SeverityLevel, VerificationStatus } from '../types';

interface FindingsTableProps {
  findings: SecurityFinding[];
  onSelectFinding: (finding: SecurityFinding) => void;
  selectedFindingId?: string;
  onExportSarif: () => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  selectedFindingId,
  onExportSarif,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [sortBy, setSortBy] = useState<'severity' | 'line' | 'rule'>('severity');

  // Filtered & sorted list
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        const matchesSearch = 
          f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          f.filePath.toLowerCase().includes(searchTerm.toLowerCase()) ||
          f.ruleId.toLowerCase().includes(searchTerm.toLowerCase()) ||
          f.cwe.toLowerCase().includes(searchTerm.toLowerCase());
        
        const matchesSeverity = 
          severityFilter === 'All' || f.severity === severityFilter;

        const matchesStatus = 
          statusFilter === 'All' || f.verificationStatus === statusFilter;

        return matchesSearch && matchesSeverity && matchesStatus;
      })
      .sort((a, b) => {
        if (sortBy === 'severity') {
          const rank: Record<SeverityLevel, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
          return rank[b.severity] - rank[a.severity];
        }
        if (sortBy === 'line') {
          return a.lineNumber - b.lineNumber;
        }
        return a.ruleId.localeCompare(b.ruleId);
      });
  }, [findings, searchTerm, severityFilter, statusFilter, sortBy]);

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'Critical':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-[#ff3b30]/10 px-2 py-0.5 text-xs font-semibold text-[#d70015]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#d70015]" />
            Critical
          </span>
        );
      case 'High':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-[#ff9500]/10 px-2 py-0.5 text-xs font-semibold text-[#c96000]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#ff9500]" />
            High
          </span>
        );
      case 'Medium':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-[#ffcc00]/15 px-2 py-0.5 text-xs font-semibold text-[#8f6b00]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#ffcc00]" />
            Medium
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-black/[0.05] px-2 py-0.5 text-xs font-medium text-[#6e6e73]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#86868b]" />
            Low
          </span>
        );
    }
  };

  const getStatusBadge = (status: VerificationStatus) => {
    switch (status) {
      case 'Verified Fixed':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#34c759]">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Verified Fixed</span>
          </span>
        );
      case 'Needs Review':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#c96000]">
            <Clock className="h-3.5 w-3.5" />
            <span>Needs Review</span>
          </span>
        );
      case 'Pytest Failing':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#d70015]">
            <AlertOctagon className="h-3.5 w-3.5" />
            <span>Pytest Failing</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#0071e3]">
            <Sparkles className="h-3.5 w-3.5" />
            <span>Patch Ready</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Demo Data Label Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-black/[0.06] bg-[#f5f5f7]/60 px-4 py-3 sm:px-5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-[#0071e3]/10 text-[#0071e3]">
            <Shield className="h-3 w-3" />
          </div>
          <span className="text-xs font-medium text-[#1d1d1f]">
            Demo Dataset: Python Web Application Security Audit
          </span>
          <span className="text-[#86868b]">·</span>
          <span className="text-xs text-[#6e6e73]">
            7 realistic vulnerabilities discovered via Bandit AST & Qwen Reasoning
          </span>
        </div>
        <button
          onClick={onExportSarif}
          className="inline-flex items-center gap-1.5 rounded-lg border border-black/[0.08] bg-white px-3 py-1 text-xs font-medium text-[#1d1d1f] shadow-sm hover:bg-[#fbfbfd] transition-colors"
        >
          <Download className="h-3.5 w-3.5 text-[#6e6e73]" />
          <span>Export SARIF Report</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[#86868b]" />
          <input
            type="text"
            placeholder="Search vulnerabilities, files, CWEs, or rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full rounded-xl border border-black/[0.08] bg-white py-2 pl-9 pr-4 text-xs text-[#1d1d1f] placeholder-[#86868b] shadow-[0_1px_2px_rgba(0,0,0,0.02)] focus:border-[#0071e3] focus:outline-none focus:ring-1 focus:ring-[#0071e3]"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-[#86868b] hover:text-[#1d1d1f]"
            >
              Clear
            </button>
          )}
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Segmented buttons */}
          <div className="inline-flex items-center rounded-xl border border-black/[0.06] bg-black/[0.02] p-1">
            {['All', 'Critical', 'High', 'Medium'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-all ${
                  severityFilter === sev
                    ? 'bg-white text-[#1d1d1f] shadow-sm'
                    : 'text-[#6e6e73] hover:text-[#1d1d1f]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Verification Status selector */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-xl border border-black/[0.08] bg-white px-3 py-1.5 text-xs text-[#1d1d1f] focus:outline-none focus:border-[#0071e3]"
          >
            <option value="All">All Statuses</option>
            <option value="Verified Fixed">Verified Fixed</option>
            <option value="Needs Review">Needs Review</option>
            <option value="Pytest Failing">Pytest Failing</option>
            <option value="Patch Available">Patch Available</option>
          </select>
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-hidden rounded-2xl border border-black/[0.06] bg-white shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-black/[0.06] bg-[#fbfbfd] text-[11px] font-semibold text-[#86868b] tracking-wider uppercase">
                <th className="py-3 px-4 sm:px-6">Vulnerability & Rule</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-4">File Path & Line</th>
                <th className="py-3 px-4">Verification Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/[0.04] text-xs">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[#86868b]">
                    No security findings matching the current filters.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => {
                  const isSelected = selectedFindingId === finding.id;
                  return (
                    <tr
                      key={finding.id}
                      onClick={() => onSelectFinding(finding)}
                      className={`group cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-[#0071e3]/[0.04]'
                          : 'hover:bg-[#fbfbfd]'
                      }`}
                    >
                      {/* Title & Rule */}
                      <td className="py-3.5 px-4 sm:px-6">
                        <div className="flex flex-col">
                          <span className="font-semibold text-[#1d1d1f] group-hover:text-[#0071e3] transition-colors">
                            {finding.title}
                          </span>
                          <div className="mt-1 flex items-center gap-2 text-[11px] text-[#86868b]">
                            <span className="font-mono text-[#6e6e73]">
                              {finding.ruleId.split(':')[0]}
                            </span>
                            <span>·</span>
                            <span>{finding.cwe}</span>
                            <span>·</span>
                            <span className="text-[#86868b]">{finding.category}</span>
                          </div>
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3.5 px-3 whitespace-nowrap">
                        {getSeverityBadge(finding.severity)}
                      </td>

                      {/* File Path & Line */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono text-[11px] text-[#424245]">
                          <FileCode className="h-3.5 w-3.5 text-[#86868b]" />
                          <span className="font-medium text-[#1d1d1f]">
                            {finding.filePath}
                          </span>
                          <span className="text-[#86868b] tabular-nums">
                            :{finding.lineNumber}
                          </span>
                        </div>
                      </td>

                      {/* Verification Status */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getStatusBadge(finding.verificationStatus)}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectFinding(finding);
                          }}
                          className="inline-flex items-center gap-1 rounded-lg border border-black/[0.08] bg-white px-2.5 py-1 text-xs font-medium text-[#1d1d1f] shadow-sm transition-all hover:bg-[#f5f5f7] hover:border-black/[0.16]"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="h-3 w-3 text-[#86868b]" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer */}
        <div className="flex items-center justify-between border-t border-black/[0.06] bg-[#fbfbfd] px-4 py-2.5 sm:px-6 text-xs text-[#86868b]">
          <span>
            Showing <strong className="font-semibold text-[#1d1d1f]">{filteredFindings.length}</strong> of{' '}
            {findings.length} findings
          </span>
          <span className="hidden sm:inline">
            Click any row to view code evidence, Qwen AI explanation & Pytest verification
          </span>
        </div>
      </div>
    </div>
  );
};
