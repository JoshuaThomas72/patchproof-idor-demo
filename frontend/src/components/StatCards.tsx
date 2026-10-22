import React from 'react';
import { AlertTriangle, CheckCircle, ShieldAlert, History } from 'lucide-react';
import { SecurityFinding, RecentScan } from '../types';

interface StatCardsProps {
  findings: SecurityFinding[];
  scans: RecentScan[];
  onFilterSeverity?: (severity: string) => void;
}

export const StatCards: React.FC<StatCardsProps> = ({ findings, scans, onFilterSeverity }) => {
  const totalFindings = findings.length;
  const highSeverityCount = findings.filter(
    (f) => f.severity === 'Critical' || f.severity === 'High'
  ).length;
  const criticalCount = findings.filter((f) => f.severity === 'Critical').length;
  const totalScans = scans.length;
  
  // Calculate verified tests percentage
  const verifiedCount = findings.filter((f) => f.verificationStatus === 'Verified Fixed').length;
  const passRate = totalFindings > 0 ? ((verifiedCount / totalFindings) * 100).toFixed(1) : '100';

  const stats = [
    {
      id: 'findings',
      title: 'Total Findings',
      value: totalFindings,
      secondary: `${criticalCount} critical · ${highSeverityCount - criticalCount} high`,
      icon: AlertTriangle,
      color: 'text-[#1d1d1f]',
      iconColor: 'text-[#0071e3]',
      actionLabel: 'View all findings',
      onClick: () => onFilterSeverity && onFilterSeverity('All'),
    },
    {
      id: 'high-severity',
      title: 'High-Severity Issues',
      value: highSeverityCount,
      secondary: 'Requires immediate engineering remediation',
      icon: ShieldAlert,
      color: 'text-[#d70015]', // Apple system red
      iconColor: 'text-[#d70015]',
      actionLabel: 'Filter critical & high',
      onClick: () => onFilterSeverity && onFilterSeverity('High'),
    },
    {
      id: 'scans',
      title: 'Scans Completed',
      value: totalScans,
      secondary: 'Average scan latency 12.4s',
      icon: History,
      color: 'text-[#1d1d1f]',
      iconColor: 'text-[#86868b]',
      actionLabel: 'View scan log',
    },
    {
      id: 'tests-passed',
      title: 'Tests Passed',
      value: `${passRate}%`,
      secondary: `${verifiedCount} of ${totalFindings} invariants verified`,
      icon: CheckCircle,
      color: 'text-[#34c759]', // Apple system green
      iconColor: 'text-[#34c759]',
      actionLabel: 'Inspect verification',
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <div
            key={stat.id}
            onClick={stat.onClick}
            className={`group relative rounded-2xl border border-black/[0.06] bg-white p-6 shadow-[0_2px_12px_rgba(0,0,0,0.02)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_8px_24px_rgba(0,0,0,0.05)] ${
              stat.onClick ? 'cursor-pointer' : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-[#86868b] tracking-wide">
                {stat.title}
              </span>
              <Icon className={`h-4 w-4 ${stat.iconColor} transition-transform group-hover:scale-110`} />
            </div>

            <div className="mt-3 flex items-baseline gap-2">
              <span className={`text-3xl font-semibold tracking-tight tabular-nums ${stat.color}`}>
                {stat.value}
              </span>
            </div>

            <p className="mt-2 text-xs text-[#6e6e73] leading-relaxed">
              {stat.secondary}
            </p>

            {stat.actionLabel && (
              <div className="mt-4 flex items-center gap-1 text-[11px] font-medium text-[#0071e3] opacity-0 group-hover:opacity-100 transition-opacity">
                <span>{stat.actionLabel}</span>
                <span>→</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
