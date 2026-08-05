import { useState } from 'react';
import { FileText, Wrench, Download, RotateCcw, ExternalLink, Calendar, Hash, Cpu, ShieldCheck, Network, Activity, Code2, Send } from 'lucide-react';
import type { Assessment, Finding } from '@/lib/types';
import { ScoreGauge, SeverityBar, PageStatsGrid } from './ScoreGauge';
import { CategoryBreakdown } from './ScanVisuals';
import { FindingsList } from './FindingsList';
import { WorkflowTracker } from './WorkflowTracker';
import { ReconPanel } from './ReconPanel';
import { CompliancePanel } from './CompliancePanel';
import { generateFormalBugReport, generateSolutionReport, generateFormalSubmissionReport } from '@/lib/reportGenerator';

type Tab = 'overview' | 'findings' | 'recon' | 'compliance' | 'workflow';

interface ResultsDashboardProps {
  result: Assessment;
  onScanAgain: () => void;
  onRecordEvidence?: (finding: Finding) => void;
}

export function ResultsDashboard({ result: initialResult, onScanAgain, onRecordEvidence }: ResultsDashboardProps) {
  const [result, setResult] = useState<Assessment>(initialResult);
  const [tab, setTab] = useState<Tab>('overview');
  const formattedDate = new Date(result.scannedAt).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const cvssMax = Math.max(0, ...result.findings.map((f) => f.cvss?.score || 0));

  const tabs: { key: Tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { key: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
    { key: 'findings', label: 'Findings', icon: <FileText className="w-4 h-4" />, count: result.totalIssues },
    { key: 'recon', label: 'Recon & Assets', icon: <Cpu className="w-4 h-4" />, count: result.recon.technologies.length },
    { key: 'compliance', label: 'Compliance', icon: <ShieldCheck className="w-4 h-4" /> },
    { key: 'workflow', label: 'Workflow', icon: <Network className="w-4 h-4" /> },
  ];

  return (
    <div className="w-full max-w-5xl mx-auto animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
            <Calendar className="w-3.5 h-3.5" />
            {formattedDate}
            <span className="text-slate-700">|</span>
            <Hash className="w-3.5 h-3.5" />
            <span className="font-mono">{result.id.slice(0, 8)}</span>
            {cvssMax > 0 && (<><span className="text-slate-700">|</span><span className="text-cyan-400 font-mono">Max CVSS {cvssMax.toFixed(1)}</span></>)}
          </div>
          <h2 className="text-xl font-bold text-slate-100 truncate flex items-center gap-2">
            Assessment Results
            <a href={result.finalUrl} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300 transition">
              <ExternalLink className="w-4 h-4" />
            </a>
          </h2>
          <a href={result.finalUrl} target="_blank" rel="noopener noreferrer" className="text-sm text-slate-400 hover:text-cyan-300 transition font-mono truncate block max-w-full">
            {result.finalUrl}
          </a>
        </div>
        <button onClick={onScanAgain} className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-xl border border-slate-700/50 transition text-sm font-medium whitespace-nowrap">
          <RotateCcw className="w-4 h-4" />
          New Assessment
        </button>
      </div>

      {/* Download reports */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <DownloadCard icon={<FileText className="w-6 h-6" />} title="Formal Bug Report" subtitle="Full security assessment documentation" description="Professional report with scope, recon, CVSS scores, evidence packages, PoC, compliance mapping, and the 10-step workflow. For internal use." buttonLabel="Download Bug Report" accent="from-red-500/20 to-orange-500/20 border-red-500/30" iconColor="text-red-400" onDownload={() => generateFormalBugReport(result)} />
        <DownloadCard icon={<Wrench className="w-6 h-6" />} title="Solution Guide" subtitle="Developer remediation documentation" description="Step-by-step fix instructions with before/after code examples, compliance-critical fix prioritization, and verification steps." buttonLabel="Download Solution Guide" accent="from-cyan-500/20 to-blue-500/20 border-cyan-500/30" iconColor="text-cyan-400" onDownload={() => generateSolutionReport(result)} />
        <DownloadCard icon={<Send className="w-6 h-6" />} title="Formal Submission" subtitle="Submit directly to organizations" description="A formal bug bounty submission document with all required fields: vulnerability title, CVSS, CWE, OWASP, PoC, reproduction steps, evidence, and disclosure terms. Ready to submit." buttonLabel="Download Submission Report" accent="from-violet-500/20 to-purple-500/20 border-violet-500/30" iconColor="text-violet-400" onDownload={() => generateFormalSubmissionReport(result)} />
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6 bg-slate-900/40 border border-slate-700/30 rounded-xl p-1 overflow-x-auto">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition whitespace-nowrap ${tab === t.key ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
          >
            {t.icon}
            {t.label}
            {t.count !== undefined && t.count > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-700/60 text-slate-300">{t.count}</span>}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && (
        <div className="space-y-6 animate-fade-in">
          <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-6 backdrop-blur">
            <div className="flex flex-col md:flex-row items-center gap-8">
              <div className="flex-shrink-0">
                <ScoreGauge score={result.score} grade={result.grade} />
              </div>
              <div className="flex-1 w-full">
                <div className="mb-5">
                  <div className="text-sm text-slate-400 mb-2">Severity Distribution</div>
                  <SeverityBar counts={result.severityCounts} />
                </div>
                <div className="grid grid-cols-3 gap-3 text-center">
                  <StatBox value={result.totalIssues} label="Total Issues" />
                  <StatBox value={result.severityCounts.critical + result.severityCounts.high} label="Critical + High" color="text-red-400" />
                  <StatBox value={result.status} label="HTTP Status" />
                  <StatBox value={result.recon.technologies.length} label="Technologies" color="text-cyan-400" />
                  <StatBox value={result.recon.endpoints.length} label="Endpoints" color="text-cyan-400" />
                  <StatBox value={cvssMax.toFixed(1)} label="Max CVSS" color="text-orange-400" />
                </div>
              </div>
            </div>
          </div>
          <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-6 backdrop-blur">
            <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Issues by Category</h3>
            <CategoryBreakdown counts={result.categoryCounts} />
          </div>
          <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-6 backdrop-blur">
            <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Page Statistics</h3>
            <PageStatsGrid result={result} />
          </div>
          <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
            <WorkflowTracker state={result.workflow} compact />
          </div>
        </div>
      )}

      {tab === 'findings' && (
        <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-6 backdrop-blur animate-fade-in">
          <h3 className="text-sm font-semibold text-slate-300 mb-5 uppercase tracking-wide">All Findings ({result.totalIssues})</h3>
          <FindingsList
            findings={result.findings}
            assessment={result}
            onFindingsChange={(findings) => setResult({ ...result, findings })}
            onRecordEvidence={onRecordEvidence}
          />
        </div>
      )}

      {tab === 'recon' && (
        <div className="animate-fade-in">
          <ReconPanel recon={result.recon} />
        </div>
      )}

      {tab === 'compliance' && (
        <div className="animate-fade-in">
          <CompliancePanel report={result.compliance} />
        </div>
      )}

      {tab === 'workflow' && (
        <div className="animate-fade-in max-w-2xl mx-auto">
          <WorkflowTracker state={result.workflow} />
        </div>
      )}
    </div>
  );
}

function StatBox({ value, label, color = 'text-slate-100' }: { value: string | number; label: string; color?: string }) {
  return (
    <div className="bg-slate-800/40 rounded-xl p-3">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}

interface DownloadCardProps {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  description: string;
  buttonLabel: string;
  accent: string;
  iconColor: string;
  onDownload: () => void;
}

function DownloadCard({ icon, title, subtitle, description, buttonLabel, accent, iconColor, onDownload }: DownloadCardProps) {
  return (
    <div className={`bg-gradient-to-br ${accent} border rounded-2xl p-5 backdrop-blur`}>
      <div className="flex items-start gap-3 mb-3">
        <div className={`w-11 h-11 rounded-xl bg-slate-900/60 flex items-center justify-center ${iconColor}`}>{icon}</div>
        <div>
          <h3 className="text-base font-bold text-slate-100">{title}</h3>
          <p className="text-xs text-slate-400">{subtitle}</p>
        </div>
      </div>
      <p className="text-sm text-slate-400 leading-relaxed mb-4">{description}</p>
      <button onClick={onDownload} className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900/80 hover:bg-slate-900 text-slate-100 hover:text-white rounded-xl border border-slate-700/50 transition text-sm font-semibold">
        <Download className="w-4 h-4" />
        {buttonLabel}
      </button>
      <p className="text-[10px] text-slate-500 mt-2 text-center">Downloads as a Word document (.doc)</p>
    </div>
  );
}
