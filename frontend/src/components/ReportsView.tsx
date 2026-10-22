import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Eye, 
  CheckCircle2, 
  Clock, 
  Calendar, 
  Code, 
  ShieldCheck, 
  AlertTriangle,
  X
} from 'lucide-react';
import { RecentScan, SecurityFinding } from '../types';
import { generateSarifReport, downloadJsonFile } from '../utils/sarifExport';

interface ReportsViewProps {
  scans: RecentScan[];
  findings: SecurityFinding[];
  onOpenScanModal: () => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  scans,
  findings,
  onOpenScanModal,
}) => {
  const [inspectingReport, setInspectingReport] = useState<RecentScan | null>(null);

  const handleDownloadReport = (scan: RecentScan) => {
    const reportData = generateSarifReport(scan, findings);
    const filename = `patchproof-report-${scan.projectName.replace('.zip', '')}-${scan.commitHash}.sarif.json`;
    downloadJsonFile(filename, reportData);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="rounded-3xl border border-black/[0.06] bg-white p-6 sm:p-8 shadow-[0_2px_16px_rgba(0,0,0,0.02)]">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div>
            <div className="inline-flex items-center gap-2 text-xs font-semibold text-[#0071e3] mb-2">
              <FileText className="h-4 w-4" />
              <span>Audit & Compliance Logs</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#1d1d1f]">
              Security Scans & JSON Reports
            </h2>
            <p className="mt-2 text-sm text-[#6e6e73] max-w-2xl leading-relaxed">
              Export standardized SARIF 2.1.0 and PatchProof JSON reports for CI/CD pipelines, compliance audits, and engineering issue trackers.
            </p>
          </div>

          <button
            onClick={() => handleDownloadReport(scans[0])}
            className="inline-flex items-center gap-2 rounded-full bg-[#0071e3] px-5 py-2.5 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed] active:scale-[0.98] transition-all whitespace-nowrap self-start sm:self-auto"
          >
            <Download className="h-4 w-4" />
            <span>Download Latest SARIF (JSON)</span>
          </button>
        </div>
      </div>

      {/* Scans Table */}
      <div className="overflow-hidden rounded-2xl border border-black/[0.06] bg-white shadow-[0_2px_12px_rgba(0,0,0,0.02)]">
        <div className="border-b border-black/[0.06] bg-[#fbfbfd] px-6 py-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-[#1d1d1f]">
            Historical Scan Runs ({scans.length})
          </h3>
          <span className="text-xs text-[#86868b]">
            Standardized SARIF v2.1.0 output
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-black/[0.06] bg-[#fbfbfd] text-[11px] font-semibold text-[#86868b] uppercase tracking-wider">
                <th className="py-3 px-6">Repository / Project</th>
                <th className="py-3 px-4">Date & Time</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Files / LOC</th>
                <th className="py-3 px-4">Findings Found</th>
                <th className="py-3 px-4">Verification</th>
                <th className="py-3 px-6 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/[0.04] text-xs">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-[#fbfbfd] transition-colors">
                  {/* Name & Branch */}
                  <td className="py-4 px-6">
                    <div className="flex flex-col">
                      <span className="font-semibold text-[#1d1d1f]">
                        {scan.projectName}
                      </span>
                      <div className="flex items-center gap-1.5 text-[11px] text-[#86868b] mt-0.5">
                        <span className="font-mono">{scan.branch}</span>
                        <span>·</span>
                        <span className="font-mono">{scan.commitHash}</span>
                      </div>
                    </div>
                  </td>

                  {/* Date */}
                  <td className="py-4 px-4 whitespace-nowrap text-[#6e6e73]">
                    <div className="flex items-center gap-1.5">
                      <Calendar className="h-3.5 w-3.5 text-[#86868b]" />
                      <span className="tabular-nums">{scan.scanDate}</span>
                    </div>
                  </td>

                  {/* Duration */}
                  <td className="py-4 px-4 whitespace-nowrap text-[#424245] tabular-nums">
                    <div className="flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-[#86868b]" />
                      <span>{scan.durationSeconds}s</span>
                    </div>
                  </td>

                  {/* Files / LOC */}
                  <td className="py-4 px-4 whitespace-nowrap text-[#6e6e73] font-mono tabular-nums">
                    {scan.filesScanned} files / {scan.linesOfCode.toLocaleString()} LOC
                  </td>

                  {/* Findings */}
                  <td className="py-4 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      {scan.findingsCount.critical > 0 && (
                        <span className="inline-flex rounded-md bg-red-100/70 px-1.5 py-0.5 text-[11px] font-semibold text-[#d70015]">
                          {scan.findingsCount.critical} crit
                        </span>
                      )}
                      {scan.findingsCount.high > 0 && (
                        <span className="inline-flex rounded-md bg-orange-100/70 px-1.5 py-0.5 text-[11px] font-semibold text-[#c96000]">
                          {scan.findingsCount.high} high
                        </span>
                      )}
                      <span className="text-[#86868b] text-[11px]">
                        ({scan.findingsCount.total} total)
                      </span>
                    </div>
                  </td>

                  {/* Verification */}
                  <td className="py-4 px-4 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1 text-[#34c759] font-medium text-xs">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      <span>{scan.verifiedFixes} verified</span>
                    </span>
                  </td>

                  {/* Actions */}
                  <td className="py-4 px-6 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setInspectingReport(scan)}
                        className="inline-flex items-center gap-1 rounded-lg border border-black/[0.08] bg-white px-2.5 py-1 text-xs font-medium text-[#1d1d1f] hover:bg-[#f5f5f7] transition-colors"
                        title="View JSON Payload"
                      >
                        <Eye className="h-3 w-3 text-[#6e6e73]" />
                        <span>Preview JSON</span>
                      </button>

                      <button
                        onClick={() => handleDownloadReport(scan)}
                        className="inline-flex items-center gap-1 rounded-lg bg-[#0071e3] px-2.5 py-1 text-xs font-medium text-white hover:bg-[#0077ed] transition-colors shadow-sm"
                        title="Download JSON Report"
                      >
                        <Download className="h-3 w-3" />
                        <span>Download</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Report Inspector Modal */}
      {inspectingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="relative flex flex-col w-full max-w-3xl max-h-[85vh] rounded-3xl border border-black/[0.08] bg-white shadow-[0_24px_70px_rgba(0,0,0,0.14)] overflow-hidden">
            <div className="flex items-center justify-between border-b border-black/[0.06] bg-[#fbfbfd] p-5">
              <div>
                <h3 className="text-base font-semibold text-[#1d1d1f]">
                  SARIF 2.1.0 Report Preview
                </h3>
                <p className="text-xs text-[#6e6e73]">
                  {inspectingReport.projectName} · {inspectingReport.commitHash}
                </p>
              </div>
              <button
                onClick={() => setInspectingReport(null)}
                className="flex h-8 w-8 items-center justify-center rounded-full text-[#86868b] hover:bg-black/[0.05]"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 bg-[#1d1d1f] text-white">
              <pre className="font-mono text-xs leading-relaxed text-[#f5f5f7] overflow-x-auto">
                {JSON.stringify(generateSarifReport(inspectingReport, findings), null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between border-t border-black/[0.06] bg-[#fbfbfd] p-4">
              <span className="text-xs text-[#86868b]">
                Schema: oasis-tcs/sarif-spec v2.1.0
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setInspectingReport(null)}
                  className="rounded-full px-4 py-1.5 text-xs font-medium text-[#6e6e73] hover:text-[#1d1d1f]"
                >
                  Close
                </button>
                <button
                  onClick={() => {
                    handleDownloadReport(inspectingReport);
                    setInspectingReport(null);
                  }}
                  className="inline-flex items-center gap-1.5 rounded-full bg-[#0071e3] px-4 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-[#0077ed]"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download File</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
