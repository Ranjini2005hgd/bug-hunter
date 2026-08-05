import { ShieldCheck, ShieldX, ShieldAlert, CircleDot } from 'lucide-react';
import type { ComplianceReport, ComplianceItem } from '@/lib/types';

interface CompliancePanelProps {
  report: ComplianceReport;
}

const FRAMEWORKS: { key: keyof ComplianceReport; label: string; full: string }[] = [
  { key: 'gdpr', label: 'GDPR', full: 'General Data Protection Regulation' },
  { key: 'pciDss', label: 'PCI DSS', full: 'Payment Card Industry Data Security Standard' },
  { key: 'hipaa', label: 'HIPAA', full: 'Health Insurance Portability and Accountability Act' },
  { key: 'iso27001', label: 'ISO 27001', full: 'Information Security Management' },
];

export function CompliancePanel({ report }: CompliancePanelProps) {
  const summary = FRAMEWORKS.map((f) => {
    const items = report[f.key];
    const fails = items.filter((i) => i.status === 'fail').length;
    const warnings = items.filter((i) => i.status === 'warning').length;
    const passes = items.filter((i) => i.status === 'pass').length;
    return { ...f, fails, warnings, passes, items, total: items.length };
  });

  return (
    <div className="space-y-4">
      {summary.map((fw) => {
        const overallStatus = fw.fails > 0 ? 'fail' : fw.warnings > 0 ? 'warning' : 'pass';
        const Icon = overallStatus === 'pass' ? ShieldCheck : overallStatus === 'fail' ? ShieldX : ShieldAlert;
        const color = overallStatus === 'pass' ? 'text-emerald-400' : overallStatus === 'fail' ? 'text-red-400' : 'text-yellow-400';
        const bgColor = overallStatus === 'pass' ? 'bg-emerald-500/10' : overallStatus === 'fail' ? 'bg-red-500/10' : 'bg-yellow-500/10';
        const borderColor = overallStatus === 'pass' ? 'border-emerald-500/30' : overallStatus === 'fail' ? 'border-red-500/30' : 'border-yellow-500/30';

        return (
          <div key={fw.key} className={`bg-slate-900/60 border ${borderColor} rounded-2xl p-5 backdrop-blur`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className={`w-9 h-9 rounded-lg ${bgColor} flex items-center justify-center ${color}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-200">{fw.label}</h3>
                  <p className="text-[10px] text-slate-500">{fw.full}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-emerald-400">{fw.passes} pass</span>
                {fw.warnings > 0 && <span className="text-yellow-400">{fw.warnings} warn</span>}
                {fw.fails > 0 && <span className="text-red-400">{fw.fails} fail</span>}
              </div>
            </div>
            <div className="space-y-2">
              {fw.items.map((item, i) => (
                <ComplianceRow key={i} item={item} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ComplianceRow({ item }: { item: ComplianceItem }) {
  const Icon = item.status === 'pass' ? ShieldCheck : item.status === 'fail' ? ShieldX : item.status === 'warning' ? ShieldAlert : CircleDot;
  const color = item.status === 'pass' ? 'text-emerald-400' : item.status === 'fail' ? 'text-red-400' : item.status === 'warning' ? 'text-yellow-400' : 'text-slate-500';
  return (
    <div className="flex items-start gap-2.5 py-1.5">
      <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${color}`} />
      <div className="flex-1 min-w-0">
        <div className="text-sm text-slate-300 font-medium">{item.control}</div>
        <div className="text-xs text-slate-500 mt-0.5">{item.description}</div>
        {item.finding && <div className={`text-xs mt-1 ${color}`}>Finding: {item.finding}</div>}
      </div>
      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${color} bg-slate-800/50 flex-shrink-0`}>{item.status}</span>
    </div>
  );
}
