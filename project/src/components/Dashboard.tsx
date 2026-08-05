import { useState, useEffect, useCallback } from 'react';
import { Activity, Bug, TrendingUp, AlertTriangle, Shield, Clock, Target, Zap, Download, FileText, BarChart3, Globe, Eye, Camera, Video, Database, ChevronRight } from 'lucide-react';
import type { Assessment, Severity } from '@/lib/types';
import { loadRecentScans } from '@/lib/fetcher';
import { loadBugRecords } from '@/lib/bugDb';
import type { BugRecord } from '@/lib/types';
import { exportHackerOneCsv, exportBugcrowdCsv, exportJsonReport } from '@/lib/reportGenerator';

interface DashboardProps {
  onScanAgain?: () => void;
}

export function Dashboard({ onScanAgain }: DashboardProps) {
  const [scans, setScans] = useState<Assessment[]>([]);
  const [bugs, setBugs] = useState<BugRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<Assessment | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    const [recentScans, bugRecords] = await Promise.all([
      loadRecentScans(20).catch(() => []),
      loadBugRecords(50).catch(() => []),
    ]);
    setScans(recentScans);
    setBugs(bugRecords);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Aggregate stats
  const totalScans = scans.length;
  const totalFindings = scans.reduce((sum, s) => sum + s.findings.length, 0);
  const criticalCount = scans.reduce((sum, s) => sum + s.severityCounts.critical, 0);
  const highCount = scans.reduce((sum, s) => sum + s.severityCounts.high, 0);
  const avgScore = scans.length > 0 ? Math.round(scans.reduce((sum, s) => sum + s.score, 0) / scans.length) : 0;
  const uniqueTargets = new Set(scans.map((s) => s.finalUrl)).size;
  const totalBugs = bugs.length;
  const openBugs = bugs.filter((b) => b.status === 'open').length;

  // Severity distribution across all scans
  const severityDist: Record<Severity, number> = {
    critical: criticalCount,
    high: highCount,
    medium: scans.reduce((sum, s) => sum + s.severityCounts.medium, 0),
    low: scans.reduce((sum, s) => sum + s.severityCounts.low, 0),
    info: scans.reduce((sum, s) => sum + s.severityCounts.info, 0),
  };
  const maxSev = Math.max(1, ...Object.values(severityDist));

  // Top vulnerable targets
  const targetStats = new Map<string, { count: number; critical: number; url: string; lastScanned: string }>();
  for (const scan of scans) {
    const existing = targetStats.get(scan.finalUrl);
    if (existing) {
      existing.count += scan.findings.length;
      existing.critical += scan.severityCounts.critical;
      if (scan.scannedAt > existing.lastScanned) existing.lastScanned = scan.scannedAt;
    } else {
      targetStats.set(scan.finalUrl, {
        count: scan.findings.length,
        critical: scan.severityCounts.critical,
        url: scan.finalUrl,
        lastScanned: scan.scannedAt,
      });
    }
  }
  const topTargets = Array.from(targetStats.values()).sort((a, b) => b.critical - a.critical || b.count - a.count).slice(0, 5);

  if (loading) {
    return (
      <div className="text-center py-16 text-slate-500">
        <Activity className="w-8 h-8 mx-auto mb-3 animate-spin text-slate-600" />
        <p className="text-sm">Loading dashboard...</p>
      </div>
    );
  }

  if (totalScans === 0 && totalBugs === 0) {
    return (
      <div className="text-center py-16 text-slate-500">
        <BarChart3 className="w-12 h-12 mx-auto mb-4 text-slate-700" />
        <p className="text-lg text-slate-400">No data yet</p>
        <p className="text-sm mt-1">Run a website scan or record a bug to see dashboard analytics.</p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white mb-1">Dashboard</h2>
        <p className="text-sm text-slate-500">Overview of all security assessments and bug recordings</p>
      </div>

      {/* Stat cards */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard icon={<Globe className="w-5 h-5" />} label="Total Scans" value={totalScans} sub={`${uniqueTargets} unique targets`} color="text-cyan-400" bg="bg-cyan-500/10" />
        <StatCard icon={<Bug className="w-5 h-5" />} label="Total Findings" value={totalFindings} sub={`${criticalCount} critical, ${highCount} high`} color="text-red-400" bg="bg-red-500/10" />
        <StatCard icon={<TrendingUp className="w-5 h-5" />} label="Average Score" value={avgScore} sub="across all scans" color="text-amber-400" bg="bg-amber-500/10" />
        <StatCard icon={<Video className="w-5 h-5" />} label="Recorded Bugs" value={totalBugs} sub={`${openBugs} open`} color="text-violet-400" bg="bg-violet-500/10" />
      </div>

      {/* Severity distribution + Top targets */}
      <div className="grid lg:grid-cols-2 gap-6 mb-8">
        {/* Severity Distribution */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Severity Distribution
          </h3>
          <div className="space-y-3">
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
              const count = severityDist[sev];
              const pct = (count / maxSev) * 100;
              const colors: Record<Severity, string> = {
                critical: 'bg-red-500',
                high: 'bg-orange-500',
                medium: 'bg-amber-500',
                low: 'bg-cyan-500',
                info: 'bg-slate-500',
              };
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="text-xs text-slate-400 capitalize w-16">{sev}</span>
                  <div className="flex-1 h-6 bg-slate-800/50 rounded-full overflow-hidden">
                    <div className={`h-full ${colors[sev]} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-sm text-slate-300 font-mono w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Vulnerable Targets */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" />
            Top Vulnerable Targets
          </h3>
          {topTargets.length === 0 ? (
            <p className="text-sm text-slate-500">No targets scanned yet.</p>
          ) : (
            <div className="space-y-2">
              {topTargets.map((t, i) => (
                <div key={t.url} className="flex items-center gap-3 bg-slate-800/30 rounded-lg p-3">
                  <span className="text-xs font-mono text-slate-600 w-5">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-300 truncate">{t.url}</p>
                    <p className="text-[10px] text-slate-600">{t.count} findings · {t.critical} critical · {new Date(t.lastScanned).toLocaleDateString()}</p>
                  </div>
                  {t.critical > 0 && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 font-mono">{t.critical} crit</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur mb-8">
        <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          Recent Scans
        </h3>
        {scans.length === 0 ? (
          <p className="text-sm text-slate-500">No scans yet. Run a website scan to see results here.</p>
        ) : (
          <div className="space-y-2">
            {scans.slice(0, 10).map((scan) => (
              <div
                key={scan.id}
                className={`flex items-center gap-3 rounded-lg p-3 cursor-pointer transition ${selectedScan?.id === scan.id ? 'bg-cyan-500/10 border border-cyan-500/30' : 'bg-slate-800/30 hover:bg-slate-800/50 border border-transparent'}`}
                onClick={() => setSelectedScan(selectedScan?.id === scan.id ? null : scan)}
              >
                <div className="w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-sm flex-shrink-0" style={{ background: gradeColor(scan.grade) }}>
                  {scan.grade}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-300 truncate">{scan.finalUrl}</p>
                  <p className="text-[10px] text-slate-600">
                    {scan.findings.length} findings · {scan.severityCounts.critical} critical · {new Date(scan.scannedAt).toLocaleString()}
                  </p>
                </div>
                <ChevronRight className={`w-4 h-4 text-slate-600 transition ${selectedScan?.id === scan.id ? 'rotate-90' : ''}`} />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Export panel for selected scan */}
      {selectedScan && (
        <div className="bg-slate-900/40 border border-cyan-500/30 rounded-2xl p-6 backdrop-blur mb-8 animate-slide-down">
          <h3 className="text-sm font-bold text-slate-300 mb-1 flex items-center gap-2">
            <Download className="w-4 h-4 text-cyan-400" />
            Export — {selectedScan.finalUrl}
          </h3>
          <p className="text-xs text-slate-500 mb-4">Download findings in platform-specific formats for bug bounty submission.</p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => exportHackerOneCsv(selectedScan)}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-sm font-medium rounded-lg border border-cyan-500/20 transition"
            >
              <FileText className="w-4 h-4" />
              HackerOne CSV
            </button>
            <button
              onClick={() => exportBugcrowdCsv(selectedScan)}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-sm font-medium rounded-lg border border-amber-500/20 transition"
            >
              <FileText className="w-4 h-4" />
              Bugcrowd CSV
            </button>
            <button
              onClick={() => exportJsonReport(selectedScan)}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 text-sm font-medium rounded-lg border border-violet-500/20 transition"
            >
              <Database className="w-4 h-4" />
              JSON Export
            </button>
          </div>
        </div>
      )}

      {/* Quick stats footer */}
      <div className="grid sm:grid-cols-3 gap-4">
        <MiniStat icon={<Shield className="w-4 h-4" />} label="Compliance Mapped" value={`${scans.length} scans`} color="text-emerald-400" />
        <MiniStat icon={<Eye className="w-4 h-4" />} label="Avg Findings/Scan" value={totalScans > 0 ? String(Math.round(totalFindings / totalScans)) : '0'} color="text-cyan-400" />
        <MiniStat icon={<Camera className="w-4 h-4" />} label="Bug Evidence Packages" value={String(totalBugs)} color="text-violet-400" />
      </div>

      {onScanAgain && (
        <div className="text-center mt-8">
          <button
            onClick={onScanAgain}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-semibold rounded-xl transition glow-blue"
          >
            <Zap className="w-4 h-4" />
            New Scan
          </button>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, sub, color, bg }: { icon: React.ReactNode; label: string; value: number; sub: string; color: string; bg: string }) {
  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-5 backdrop-blur">
      <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center ${color} mb-3`}>{icon}</div>
      <div className="text-3xl font-extrabold text-white tabular-nums">{value}</div>
      <div className="text-sm text-slate-400 mt-1">{label}</div>
      <div className="text-[10px] text-slate-600 mt-0.5">{sub}</div>
    </div>
  );
}

function MiniStat({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-xl p-4 flex items-center gap-3">
      <div className={`${color}`}>{icon}</div>
      <div>
        <div className="text-sm font-bold text-slate-200">{value}</div>
        <div className="text-[10px] text-slate-500">{label}</div>
      </div>
    </div>
  );
}

function gradeColor(grade: string): string {
  if (grade.startsWith('A')) return '#10b981';
  if (grade.startsWith('B')) return '#84cc16';
  if (grade.startsWith('C')) return '#eab308';
  if (grade.startsWith('D')) return '#f97316';
  return '#dc2626';
}
