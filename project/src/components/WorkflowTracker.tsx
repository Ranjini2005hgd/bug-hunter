import { CheckCircle2, Circle, Loader2, SkipForward } from 'lucide-react';
import type { WorkflowState } from '@/lib/types';
import { WORKFLOW_STEPS, getProgressPercent } from '@/lib/workflow';

interface WorkflowTrackerProps {
  state: WorkflowState;
  compact?: boolean;
}

export function WorkflowTracker({ state, compact = false }: WorkflowTrackerProps) {
  const progress = getProgressPercent(state);

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
          <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-700" style={{ width: `${progress}%` }} />
        </div>
        <span className="text-xs text-slate-500 font-mono">{progress}%</span>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Assessment Workflow</h3>
        <span className="text-xs font-mono text-cyan-400">{progress}% complete</span>
      </div>
      <div className="space-y-1">
        {WORKFLOW_STEPS.map((item, i) => {
          const status = state.stepStatus[item.step];
          const Icon = status === 'completed' ? CheckCircle2 : status === 'in-progress' ? Loader2 : status === 'skipped' ? SkipForward : Circle;
          const iconClass = status === 'completed' ? 'text-emerald-400' : status === 'in-progress' ? 'text-cyan-400 animate-spin' : 'text-slate-600';
          return (
            <div key={item.step} className="flex items-center gap-3 py-1.5 group">
              <div className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800/60 text-[10px] font-mono text-slate-500 flex-shrink-0">
                {i + 1}
              </div>
              <Icon className={`w-4 h-4 flex-shrink-0 ${iconClass}`} />
              <div className="flex-1 min-w-0">
                <div className={`text-sm font-medium ${status === 'completed' ? 'text-slate-300' : status === 'in-progress' ? 'text-cyan-300' : 'text-slate-500'}`}>
                  {item.label}
                </div>
                {!compact && <div className="text-xs text-slate-600">{item.description}</div>}
              </div>
              {status === 'completed' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400/60" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
