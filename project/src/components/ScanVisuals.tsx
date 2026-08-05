import { Shield, AlertTriangle, Eye, Search, Zap, Sparkles, Smartphone, Bug, Code2 } from 'lucide-react';
import type { CategoryCount } from '@/lib/types';

const CATEGORY_META = {
  security: { label: 'Security', icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' },
  accessibility: { label: 'Accessibility', icon: Eye, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
  seo: { label: 'SEO', icon: Search, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
  performance: { label: 'Performance', icon: Zap, color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/30' },
  'best-practices': { label: 'Best Practices', icon: Sparkles, color: 'text-violet-400', bg: 'bg-violet-500/10', border: 'border-violet-500/30' },
  pwa: { label: 'PWA', icon: Smartphone, color: 'text-pink-400', bg: 'bg-pink-500/10', border: 'border-pink-500/30' },
  code: { label: 'Code', icon: Code2, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
} as const;

interface ScanProgressProps {
  stage: string;
  url: string;
}

export function ScanProgress({ stage, url }: ScanProgressProps) {
  return (
    <div className="w-full max-w-2xl mx-auto py-16 text-center">
      <div className="relative inline-block mb-8">
        <div className="relative w-28 h-28 mx-auto">
          <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
          <div className="absolute inset-0 rounded-full border-t-2 border-cyan-400 animate-spin-slow" />
          <div className="absolute inset-2 rounded-full border-2 border-blue-500/10" />
          <div className="absolute inset-2 rounded-full border-b-2 border-blue-400 animate-spin-slow" style={{ animationDirection: 'reverse', animationDuration: '6s' }} />
          <div className="absolute inset-0 flex items-center justify-center">
            <Bug className="w-10 h-10 text-cyan-400 animate-pulse" />
          </div>
        </div>
      </div>
      <div className="font-mono text-sm text-slate-500 mb-2">Scanning</div>
      <div className="text-lg text-slate-200 font-mono mb-6 truncate px-4">{url}</div>
      <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-slate-800/60 border border-slate-700/50 text-cyan-300 text-sm font-mono">
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
        {stage}
      </div>
      <div className="mt-8 max-w-xs mx-auto h-1 rounded-full bg-slate-800 overflow-hidden">
        <div className="h-full w-1/3 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full animate-pulse" style={{ animation: 'scan-line 1.5s ease-in-out infinite alternate' }} />
      </div>
    </div>
  );
}

interface CategoryBreakdownProps {
  counts: CategoryCount;
}

export function CategoryBreakdown({ counts }: CategoryBreakdownProps) {
  const entries = Object.entries(counts) as [keyof CategoryCount, number][];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
      {entries.map(([key, count]) => {
        const meta = CATEGORY_META[key];
        const Icon = meta.icon;
        return (
          <div key={key} className={`${meta.bg} ${meta.border} border rounded-xl p-4 flex items-center gap-3`}>
            <div className={`w-10 h-10 rounded-lg ${meta.bg} flex items-center justify-center ${meta.color}`}>
              <Icon className="w-5 h-5" />
            </div>
            <div>
              <div className={`text-2xl font-bold ${meta.color}`}>{count}</div>
              <div className="text-xs text-slate-400">{meta.label}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md';
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/40',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
    info: 'bg-slate-500/20 text-slate-400 border-slate-500/40',
  };
  const sizes = size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-2.5 py-1';
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border font-semibold uppercase tracking-wide ${styles[severity]} ${sizes}`}>
      {severity}
    </span>
  );
}

export { CATEGORY_META };
