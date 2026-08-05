import { useState, useEffect, useCallback } from 'react';
import { Bug, Download, Trash2, ChevronDown, Clock, Activity, Camera, Video, FileText, RefreshCw } from 'lucide-react';
import type { BugRecord, BugStatus } from '@/lib/types';
import { loadBugRecords, deleteBugRecord, updateBugRecordStatus } from '@/lib/bugDb';
import { downloadReportPdf } from '@/lib/bugRecorder';

const STATUS_COLORS: Record<BugStatus, string> = {
  open: 'bg-red-500/15 text-red-300 border-red-500/30',
  triaged: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  fixed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  duplicate: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-cyan-400',
  info: 'text-slate-400',
};

export function BugGallery() {
  const [bugs, setBugs] = useState<BugRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | BugStatus>('all');

  const refresh = useCallback(async () => {
    setLoading(true);
    const records = await loadBugRecords(50);
    setBugs(records);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleDelete = useCallback(async (id: string) => {
    const ok = await deleteBugRecord(id);
    if (ok) {
      setBugs((prev) => prev.filter((b) => b.id !== id));
    }
  }, []);

  const handleStatusChange = useCallback(async (id: string, status: BugStatus) => {
    const ok = await updateBugRecordStatus(id, status);
    if (ok) {
      setBugs((prev) => prev.map((b) => (b.id === id ? { ...b, status } : b)));
    }
  }, []);

  const filtered = filter === 'all' ? bugs : bugs.filter((b) => b.status === filter);

  if (loading) {
    return (
      <div className="text-center py-16 text-slate-500">
        <RefreshCw className="w-8 h-8 mx-auto mb-3 animate-spin text-slate-600" />
        <p className="text-sm">Loading saved bugs...</p>
      </div>
    );
  }

  if (bugs.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500">
        <Bug className="w-12 h-12 mx-auto mb-4 text-slate-700" />
        <p className="text-lg text-slate-400">No bugs recorded yet</p>
        <p className="text-sm mt-1">Use the Bug Recorder to capture and document vulnerabilities.</p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">Saved Bugs</h2>
          <p className="text-sm text-slate-500 mt-0.5">{bugs.length} bug{bugs.length === 1 ? '' : 's'} documented and ready for submission</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs rounded-lg border border-slate-700/50 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2 mb-4">
        {(['all', 'open', 'triaged', 'fixed', 'duplicate'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition capitalize ${
              filter === f
                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                : 'bg-slate-800/40 text-slate-500 border-slate-700/30 hover:text-slate-300'
            }`}
          >
            {f}
            {f !== 'all' && <span className="ml-1.5 text-slate-600">{bugs.filter((b) => b.status === f).length}</span>}
          </button>
        ))}
      </div>

      {/* Bug list */}
      <div className="space-y-3">
        {filtered.map((bug) => (
          <div
            key={bug.id}
            className={`bg-slate-800/30 border rounded-xl overflow-hidden transition ${
              expandedId === bug.id ? 'border-cyan-500/40' : 'border-slate-700/40 hover:border-slate-600/60'
            }`}
          >
            <button
              onClick={() => setExpandedId(expandedId === bug.id ? null : bug.id)}
              className="w-full flex items-start gap-3 p-4 text-left"
            >
              <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400 flex-shrink-0 mt-0.5">
                <Bug className="w-4 h-4" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-xs font-mono text-slate-600">{bug.bugId}</span>
                  <span className={`text-xs font-semibold uppercase ${SEVERITY_COLORS[bug.severity] || 'text-slate-400'}`}>{bug.severity}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border ${STATUS_COLORS[bug.status]}`}>{bug.status}</span>
                  {bug.vulnerabilityClass && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-cyan-900/40">
                      {bug.vulnerabilityClass}
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-semibold text-slate-200">{bug.title}</h3>
                <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-600">
                  <span><Clock className="w-2.5 h-2.5 inline mr-0.5" />{new Date(bug.createdAt).toLocaleString()}</span>
                  <span><Video className="w-2.5 h-2.5 inline mr-0.5" />{bug.recordingDuration}s</span>
                  <span><Activity className="w-2.5 h-2.5 inline mr-0.5" />{bug.steps.length} steps</span>
                  <span><Camera className="w-2.5 h-2.5 inline mr-0.5" />{bug.screenshotCount}</span>
                  <span className="truncate"><FileText className="w-2.5 h-2.5 inline mr-0.5" />{bug.httpEntries.length} HTTP</span>
                </div>
              </div>
              <ChevronDown className={`w-5 h-5 text-slate-500 flex-shrink-0 transition-transform ${expandedId === bug.id ? 'rotate-180' : ''}`} />
            </button>

            {expandedId === bug.id && (
              <div className="px-4 pb-4 pt-1 space-y-4 animate-slide-down">
                {/* Metadata table */}
                <div className="grid sm:grid-cols-2 gap-3 text-xs">
                  <div className="bg-slate-950/40 rounded-lg p-3">
                    <div className="text-slate-500 uppercase tracking-wide mb-1">Target URL</div>
                    <div className="text-slate-300 font-mono truncate">{bug.targetUrl}</div>
                  </div>
                  <div className="bg-slate-950/40 rounded-lg p-3">
                    <div className="text-slate-500 uppercase tracking-wide mb-1">Bug ID</div>
                    <div className="text-slate-300 font-mono">{bug.bugId}</div>
                  </div>
                </div>

                {/* Notes */}
                {bug.notes && (
                  <div>
                    <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1.5">Notes</div>
                    <p className="text-sm text-slate-300 bg-slate-950/40 rounded-lg p-3">{bug.notes}</p>
                  </div>
                )}

                {/* Steps */}
                {bug.steps.length > 0 && (
                  <div>
                    <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1.5">Reproduction Steps</div>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {bug.steps.map((step, i) => (
                        <div key={step.id} className="flex items-start gap-2 text-xs bg-slate-950/30 rounded-lg p-2">
                          <span className="text-slate-600 font-mono w-5 text-right">{i + 1}</span>
                          <span className="text-cyan-400 font-mono">+{(step.relativeTime / 1000).toFixed(1)}s</span>
                          <span className="text-slate-400 capitalize">{step.action}</span>
                          <span className="text-slate-300 flex-1">{step.description}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* HTTP entries */}
                {bug.httpEntries.length > 0 && (
                  <div>
                    <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1.5">HTTP Traffic ({bug.httpEntries.length})</div>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {bug.httpEntries.slice(0, 20).map((entry) => (
                        <div key={entry.id} className="flex items-center gap-2 text-[10px] font-mono bg-slate-950/30 rounded p-1.5">
                          <span className="text-amber-400">{entry.initiatorType}</span>
                          <span className="text-slate-500">{entry.duration}ms</span>
                          <span className="text-slate-400 truncate flex-1">{entry.url}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800">
                  <button
                    onClick={() => downloadReportPdf(bug.bugId, bug.reportMarkdown)}
                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs font-medium rounded-lg border border-cyan-500/20 transition"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download Report
                  </button>
                  <select
                    value={bug.status}
                    onChange={(e) => handleStatusChange(bug.id, e.target.value as BugStatus)}
                    className="text-xs bg-slate-800 border border-slate-700/50 rounded-lg px-3 py-2 text-slate-300 focus:outline-none focus:border-cyan-500/50"
                  >
                    <option value="open">Open</option>
                    <option value="triaged">Triaged</option>
                    <option value="fixed">Fixed</option>
                    <option value="duplicate">Duplicate</option>
                  </select>
                  <button
                    onClick={() => handleDelete(bug.id)}
                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs font-medium rounded-lg border border-red-500/20 transition ml-auto"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    Delete
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
