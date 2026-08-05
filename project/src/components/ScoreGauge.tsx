import type { ScanResult, SeverityCount } from '@/lib/types';

interface ScoreGaugeProps {
  score: number;
  grade: string;
  size?: number;
}

export function ScoreGauge({ score, grade, size = 160 }: ScoreGaugeProps) {
  const radius = size / 2 - 12;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s ease-out, stroke 0.5s' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-extrabold" style={{ color }}>{grade}</span>
        <span className="text-sm text-slate-400 font-mono">{score}/100</span>
      </div>
    </div>
  );
}

interface SeverityBarProps {
  counts: SeverityCount;
}

export function SeverityBar({ counts }: SeverityBarProps) {
  const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
  if (total === 0) {
    return <div className="text-slate-500 text-sm">No issues found.</div>;
  }
  const segments = [
    { key: 'critical', count: counts.critical, color: 'bg-red-500', label: 'Critical' },
    { key: 'high', count: counts.high, color: 'bg-orange-500', label: 'High' },
    { key: 'medium', count: counts.medium, color: 'bg-yellow-500', label: 'Medium' },
    { key: 'low', count: counts.low, color: 'bg-blue-500', label: 'Low' },
    { key: 'info', count: counts.info, color: 'bg-slate-500', label: 'Info' },
  ].filter((s) => s.count > 0);

  return (
    <div>
      <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-800">
        {segments.map((s) => (
          <div
            key={s.key}
            className={s.color}
            style={{ width: `${(s.count / total) * 100}%`, transition: 'width 0.8s ease-out' }}
          />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs">
        {segments.map((s) => (
          <div key={s.key} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-sm ${s.color}`} />
            <span className="text-slate-400">{s.label}</span>
            <span className="text-slate-200 font-semibold">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
}

export function StatCard({ label, value, icon }: StatCardProps) {
  return (
    <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl p-3">
      <div className="text-xs text-slate-500 mb-1 flex items-center gap-1.5">
        {icon}
        {label}
      </div>
      <div className="text-base font-semibold text-slate-200 font-mono">{value}</div>
    </div>
  );
}

interface PageStatsGridProps {
  result: ScanResult;
}

export function PageStatsGrid({ result }: PageStatsGridProps) {
  const stats = result.pageStats;
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <StatCard label="HTML Size" value={`${(stats.htmlSizeBytes / 1024).toFixed(1)} KB`} />
      <StatCard label="Load Time" value={`${stats.loadTimeMs} ms`} />
      <StatCard label="Scripts" value={stats.numScripts} />
      <StatCard label="Stylesheets" value={stats.numStylesheets} />
      <StatCard label="Images" value={stats.numImages} />
      <StatCard label="Links" value={stats.numLinks} />
      <StatCard label="Forms" value={stats.numForms} />
      <StatCard label="Protocol" value={stats.protocol.toUpperCase()} />
    </div>
  );
}
