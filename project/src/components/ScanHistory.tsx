import { History, Clock, Trash2, ChevronRight, Cpu, Zap } from 'lucide-react';
import type { Assessment } from '@/lib/types';

interface ScanHistoryProps {
  scans: Assessment[];
  currentId: string | null;
  onSelect: (result: Assessment) => void;
  onClear: () => void;
}

export function ScanHistory({ scans, currentId, onSelect, onClear }: ScanHistoryProps) {
  if (scans.length === 0) return null;

  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wide">
          <History className="w-3.5 h-3.5" />
          Recent Assessments
        </div>
        <button onClick={onClear} className="text-slate-600 hover:text-red-400 transition" title="Clear history">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
        {scans.map((scan) => {
          const isActive = scan.id === currentId;
          const gradeColor = scan.score >= 80 ? 'text-emerald-400' : scan.score >= 60 ? 'text-yellow-400' : 'text-red-400';
          const time = new Date(scan.scannedAt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
          let host = scan.url;
          try { host = new URL(scan.url).hostname; } catch { /* keep raw */ }
          const cvssMax = Math.max(0, ...scan.findings.map((f) => f.cvss?.score || 0));
          return (
            <button
              key={scan.id}
              onClick={() => onSelect(scan)}
              className={`w-full flex items-center gap-2.5 p-2.5 rounded-lg text-left transition ${isActive ? 'bg-cyan-500/10 border border-cyan-500/30' : 'bg-slate-800/30 hover:bg-slate-800/60 border border-transparent'}`}
            >
              <div className={`flex-shrink-0 w-9 h-9 rounded-lg bg-slate-900/60 flex items-center justify-center font-bold text-sm ${gradeColor}`}>
                {scan.grade}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-slate-300 truncate font-mono">{host}</div>
                <div className="flex items-center gap-2 text-[10px] text-slate-500">
                  <Clock className="w-2.5 h-2.5" />
                  {time}
                  <span className="text-slate-700">|</span>
                  <span>{scan.totalIssues} issues</span>
                  {scan.recon?.technologies?.length > 0 && (<><span className="text-slate-700">|</span><Cpu className="w-2.5 h-2.5" /><span>{scan.recon.technologies.length} tech</span></>)}
                  {cvssMax > 0 && (<><span className="text-slate-700">|</span><Zap className="w-2.5 h-2.5 text-orange-400" /><span className="text-orange-400">{cvssMax.toFixed(1)}</span></>)}
                </div>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-600 flex-shrink-0" />
            </button>
          );
        })}
      </div>
    </div>
  );
}
