import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Shield, Globe, Lock, Target, Radio, Camera, Film, Network, Terminal, Database,
  Package, FileText, Download, CheckCircle, AlertCircle, Activity, Clock, Zap,
  ChevronDown, ChevronRight, Cpu, Eye, Layers, Crosshair, ScanLine, FileBarChart,
  RefreshCw, FolderArchive, Play, Square, Settings, Monitor, Cookie, KeyRound,
  ListChecks,
} from 'lucide-react';
import {
  runSecuritySuite, downloadBlob,
  type SuiteConfig, type SuiteProgress, type SuiteResult,
} from '@/lib/securitySuiteEngine';
import type { ReproductionResult } from '@/lib/reproductionEngine';
import {
  generateFormalBugReport, generateSolutionReport, generateFormalSubmissionReport,
  exportHackerOneCsv, exportBugcrowdCsv, exportJsonReport,
} from '@/lib/reportGenerator';
import type { Assessment } from '@/lib/types';

type SuiteState = 'config' | 'running' | 'complete' | 'error';

const DEFAULT_CONFIG: SuiteConfig = {
  targetUrl: '',
  scanType: 'comprehensive',
  authentication: 'none',
  authValue: '',
  scanScope: 'active-safe',
  enableRecording: true,
  enableScreenshots: true,
  enableHarExport: true,
  enableVideoEvidence: true,
  enableNetworkCapture: true,
  enableConsoleCapture: true,
  enableStorageCapture: true,
  enablePayloadCapture: true,
};

export function SecuritySuite() {
  const [state, setState] = useState<SuiteState>('config');
  const [config, setConfig] = useState<SuiteConfig>(DEFAULT_CONFIG);
  const [progress, setProgress] = useState<SuiteProgress | null>(null);
  const [result, setResult] = useState<SuiteResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollTop = logEndRef.current.scrollHeight;
    }
  }, [progress?.logs.length]);

  const handleStart = useCallback(async () => {
    if (!config.targetUrl.trim()) {
      setError('Please enter a target URL.');
      return;
    }
    setState('running');
    setError(null);
    setProgress(null);
    setResult(null);

    try {
      const res = await runSecuritySuite(config, setProgress);
      setResult(res);
      setState('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Security Suite failed.');
      setState('error');
    }
  }, [config]);

  const handleReset = useCallback(() => {
    setState('config');
    setProgress(null);
    setResult(null);
    setError(null);
  }, []);

  // --- CONFIG VIEW ---
  if (state === 'config') {
    return (
      <div className="animate-fade-in max-w-5xl mx-auto">
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium mb-6">
            <Shield className="w-3.5 h-3.5" />
            Fully Autonomous Security Assessment
          </div>
          <h2 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight mb-4 leading-tight">
            Security <span className="gradient-text">Suite</span>
          </h2>
          <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-2xl mx-auto">
            Enter a target, choose your scan type, and click Start. The suite runs the entire
            14-step workflow autonomously — reconnaissance, vulnerability testing, evidence
            capture, per-finding video reproduction, scoring, report generation, and ZIP packaging.
          </p>
        </div>

        {/* Main config card */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur space-y-6">
          {/* Target URL */}
          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5" /> Target URL
            </label>
            <input
              type="url"
              value={config.targetUrl}
              onChange={(e) => setConfig({ ...config, targetUrl: e.target.value })}
              placeholder="https://example.com"
              className="w-full bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
            />
          </div>

          {/* Scan Type + Scope */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2 flex items-center gap-1.5">
                <ScanLine className="w-3.5 h-3.5" /> Scan Type
              </label>
              <div className="grid grid-cols-2 gap-2">
                {([
                  { v: 'quick', label: 'Quick', desc: 'Fast checks' },
                  { v: 'standard', label: 'Standard', desc: 'Balanced' },
                  { v: 'deep', label: 'Deep', desc: 'Thorough' },
                  { v: 'comprehensive', label: 'Full', desc: 'Everything' },
                ] as const).map((opt) => (
                  <button
                    key={opt.v}
                    onClick={() => setConfig({ ...config, scanType: opt.v })}
                    className={`px-3 py-2.5 rounded-xl text-left border transition ${
                      config.scanType === opt.v
                        ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                        : 'bg-slate-800/40 text-slate-400 border-slate-700/30 hover:text-slate-300'
                    }`}
                  >
                    <div className="text-sm font-semibold">{opt.label}</div>
                    <div className="text-[10px] opacity-70">{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2 flex items-center gap-1.5">
                <Crosshair className="w-3.5 h-3.5" /> Scan Scope
              </label>
              <div className="grid grid-cols-1 gap-2">
                {([
                  { v: 'passive', label: 'Passive — observe only, no payloads' },
                  { v: 'active-safe', label: 'Active (Safe) — safe payloads, no destructive' },
                  { v: 'active-full', label: 'Active (Full) — all authorized tests' },
                ] as const).map((opt) => (
                  <button
                    key={opt.v}
                    onClick={() => setConfig({ ...config, scanScope: opt.v })}
                    className={`px-3 py-2.5 rounded-xl text-left text-sm border transition ${
                      config.scanScope === opt.v
                        ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                        : 'bg-slate-800/40 text-slate-400 border-slate-700/30 hover:text-slate-300'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Authentication */}
          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" /> Authentication (Optional)
            </label>
            <div className="flex gap-3 flex-wrap">
              {(['none', 'basic', 'bearer', 'cookie', 'session'] as const).map((auth) => (
                <button
                  key={auth}
                  onClick={() => setConfig({ ...config, authentication: auth })}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border transition capitalize ${
                    config.authentication === auth
                      ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                      : 'bg-slate-800/40 text-slate-500 border-slate-700/30 hover:text-slate-300'
                  }`}
                >
                  {auth === 'none' ? 'No Auth' : auth}
                </button>
              ))}
            </div>
            {config.authentication !== 'none' && (
              <input
                type="password"
                value={config.authValue}
                onChange={(e) => setConfig({ ...config, authValue: e.target.value })}
                placeholder={`${config.authentication} token / cookie value`}
                className="w-full mt-3 bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
              />
            )}
          </div>

          {/* Advanced toggle */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition"
          >
            {showAdvanced ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            Advanced — Evidence Capture Options
          </button>

          {showAdvanced && (
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 animate-slide-down">
              <ToggleChip icon={<Film className="w-3.5 h-3.5" />} label="Video Recording" enabled={config.enableRecording} onClick={() => setConfig({ ...config, enableRecording: !config.enableRecording })} />
              <ToggleChip icon={<Camera className="w-3.5 h-3.5" />} label="Screenshots" enabled={config.enableScreenshots} onClick={() => setConfig({ ...config, enableScreenshots: !config.enableScreenshots })} />
              <ToggleChip icon={<Network className="w-3.5 h-3.5" />} label="Network Capture" enabled={config.enableNetworkCapture} onClick={() => setConfig({ ...config, enableNetworkCapture: !config.enableNetworkCapture })} />
              <ToggleChip icon={<Terminal className="w-3.5 h-3.5" />} label="Console Logs" enabled={config.enableConsoleCapture} onClick={() => setConfig({ ...config, enableConsoleCapture: !config.enableConsoleCapture })} />
              <ToggleChip icon={<Cookie className="w-3.5 h-3.5" />} label="Storage/Cookies" enabled={config.enableStorageCapture} onClick={() => setConfig({ ...config, enableStorageCapture: !config.enableStorageCapture })} />
              <ToggleChip icon={<KeyRound className="w-3.5 h-3.5" />} label="Payload Capture" enabled={config.enablePayloadCapture} onClick={() => setConfig({ ...config, enablePayloadCapture: !config.enablePayloadCapture })} />
              <ToggleChip icon={<FileText className="w-3.5 h-3.5" />} label="HAR Export" enabled={config.enableHarExport} onClick={() => setConfig({ ...config, enableHarExport: !config.enableHarExport })} />
              <ToggleChip icon={<Monitor className="w-3.5 h-3.5" />} label="Video Evidence" enabled={config.enableVideoEvidence} onClick={() => setConfig({ ...config, enableVideoEvidence: !config.enableVideoEvidence })} />
            </div>
          )}

          {/* Start button */}
          <button
            onClick={handleStart}
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-400 hover:to-orange-400 text-white font-bold rounded-xl transition glow-blue text-lg"
          >
            <Play className="w-5 h-5 fill-current" />
            Start Scan
          </button>
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}
        </div>

        {/* Workflow overview */}
        <div className="mt-8 grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {WORKFLOW_STEPS.map((step, i) => (
            <div key={i} className="bg-slate-900/40 border border-slate-700/30 rounded-xl p-4 flex items-start gap-3">
              <span className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center text-xs font-mono text-cyan-400 flex-shrink-0">{i + 1}</span>
              <div>
                <h4 className="text-sm font-semibold text-slate-200">{step.title}</h4>
                <p className="text-xs text-slate-500 mt-0.5">{step.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // --- RUNNING VIEW ---
  if (state === 'running') {
    const p = progress;
    return (
      <div className="animate-fade-in max-w-5xl mx-auto">
        {/* Progress header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
            Scan In Progress
          </div>
          <h2 className="text-3xl font-extrabold text-white mb-2">
            {p?.label ?? 'Initializing...'}
          </h2>
          <p className="text-sm text-slate-400">{p?.detail ?? 'Preparing security suite'}</p>
        </div>

        {/* Progress bar */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur mb-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">
              Step {p?.stepNumber ?? 0} of {p?.totalSteps ?? 13}
            </span>
            <span className="text-sm font-mono text-cyan-400 tabular-nums">{p?.percent ?? 0}%</span>
          </div>
          <div className="h-3 bg-slate-800/50 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${p?.percent ?? 0}%` }}
            />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5">
            <ProgressStat icon={<Clock className="w-4 h-4" />} label="Elapsed" value={p ? formatElapsed(p.elapsedMs) : '0:00'} color="text-cyan-400" />
            <ProgressStat icon={<CheckCircle className="w-4 h-4" />} label="Findings" value={String(p?.findingsConfirmed ?? 0)} color="text-red-400" />
            <ProgressStat icon={<Camera className="w-4 h-4" />} label="Screenshots" value={String(p?.screenshotsCaptured ?? 0)} color="text-violet-400" />
            <ProgressStat icon={<Network className="w-4 h-4" />} label="HTTP Logged" value={String(p?.httpRequestsLogged ?? 0)} color="text-amber-400" />
          </div>
          {p?.videoRecording && (
            <div className="mt-3 flex items-center gap-2 text-xs text-red-400">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
              Recording screen
            </div>
          )}
          {p?.currentFinding && (
            <div className="mt-2 text-xs text-slate-500 truncate">
              <Eye className="w-3 h-3 inline mr-1" />
              {p.currentFinding}
            </div>
          )}
          {p?.reproductionProgress && (
            <div className="mt-2 text-xs text-amber-400">
              <Film className="w-3 h-3 inline mr-1" />
              Reproducing finding {p.reproductionProgress.current}/{p.reproductionProgress.total} — {p.reproductionProgress.status}
            </div>
          )}
        </div>

        {/* Step list */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl backdrop-blur mb-6">
          <div className="px-5 py-3 border-b border-slate-800/50">
            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              14-Step Automated Workflow
            </h3>
          </div>
          <div className="p-4 grid sm:grid-cols-2 gap-2">
            {WORKFLOW_STEPS.map((step, i) => {
              const stepNum = i + 1;
              const isDone = p && p.stepNumber > stepNum;
              const isCurrent = p && p.stepNumber === stepNum;
              return (
                <div
                  key={i}
                  className={`flex items-center gap-3 rounded-lg p-2.5 transition ${
                    isCurrent ? 'bg-cyan-500/10 border border-cyan-500/30' :
                    isDone ? 'bg-emerald-500/5' : 'bg-slate-800/20'
                  }`}
                >
                  <span className={`w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-mono flex-shrink-0 ${
                    isDone ? 'bg-emerald-500/20 text-emerald-400' :
                    isCurrent ? 'bg-cyan-500/20 text-cyan-400 animate-pulse' :
                    'bg-slate-800 text-slate-600'
                  }`}>
                    {isDone ? <CheckCircle className="w-3.5 h-3.5" /> : stepNum}
                  </span>
                  <span className={`text-xs ${isDone ? 'text-slate-400' : isCurrent ? 'text-cyan-300 font-medium' : 'text-slate-600'}`}>
                    {step.title}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live log */}
        <div className="bg-slate-950/60 border border-slate-700/30 rounded-2xl backdrop-blur overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800/50">
            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Live Activity Log
            </h3>
          </div>
          <div ref={logEndRef} className="p-4 max-h-64 overflow-y-auto font-mono text-xs space-y-1">
            {(p?.logs ?? []).map((entry, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="text-slate-600 flex-shrink-0">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                <span className={`flex-shrink-0 ${
                  entry.level === 'success' ? 'text-emerald-400' :
                  entry.level === 'warning' ? 'text-amber-400' :
                  entry.level === 'error' ? 'text-red-400' : 'text-cyan-400'
                }`}>
                  {entry.level === 'success' ? '[OK]' : entry.level === 'warning' ? '[WARN]' : entry.level === 'error' ? '[ERR]' : '[INFO]'}
                </span>
                <span className="text-slate-400">{entry.message}</span>
              </div>
            ))}
            {!p?.logs.length && <div className="text-slate-600">Waiting for scan to start...</div>}
          </div>
        </div>
      </div>
    );
  }

  // --- ERROR VIEW ---
  if (state === 'error') {
    return (
      <div className="animate-fade-in max-w-2xl mx-auto text-center py-16">
        <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-4">
          <AlertCircle className="w-8 h-8 text-red-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-2">Scan Failed</h2>
        <p className="text-slate-400 mb-6">{error}</p>
        <button onClick={handleReset} className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-semibold rounded-xl transition">
          <RefreshCw className="w-4 h-4" /> Try Again
        </button>
      </div>
    );
  }

  // --- COMPLETE VIEW ---
  if (state === 'complete' && result) {
    return <SuiteResults result={result} onReset={handleReset} />;
  }

  return null;
}

// --- Results sub-component ---

function SuiteResults({ result, onReset }: { result: SuiteResult; onReset: () => void }) {
  const { assessment, packageBlob, videoBlob, videoMimeType, screenshots, harJson, duration, reproductionResults } = result;
  const [videoUrl, setVideoUrl] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'reports' | 'evidence' | 'reproduction'>('overview');

  useEffect(() => {
    if (videoBlob) {
      const url = URL.createObjectURL(videoBlob);
      setVideoUrl(url);
      return () => URL.revokeObjectURL(url);
    }
  }, [videoBlob]);

  const handleDownloadZip = useCallback(() => {
    if (packageBlob) downloadBlob(packageBlob, 'Assessment.zip');
  }, [packageBlob]);

  const handleDownloadVideo = useCallback(() => {
    if (videoBlob) {
      const ext = videoMimeType.includes('mp4') ? 'mp4' : 'webm';
      downloadBlob(videoBlob, `Assessment-video.${ext}`);
    }
  }, [videoBlob, videoMimeType]);

  const handleDownloadHar = useCallback(() => {
    if (harJson) {
      const blob = new Blob([harJson], { type: 'application/json' });
      downloadBlob(blob, 'network.har');
    }
  }, [harJson]);

  return (
    <div className="animate-fade-in max-w-6xl mx-auto">
      {/* Success header */}
      <div className="text-center mb-8">
        <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
          <CheckCircle className="w-8 h-8 text-emerald-400" />
        </div>
        <h2 className="text-3xl font-extrabold text-white mb-2">Assessment Complete</h2>
        <p className="text-sm text-slate-400">
          {assessment.findings.length} findings in {duration}s — Grade {assessment.grade} ({assessment.score}/100)
        </p>
      </div>

      {/* Quick download bar */}
      <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-2xl p-5 mb-6 flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/20 flex items-center justify-center">
            <FolderArchive className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Assessment Package Ready</h3>
            <p className="text-xs text-slate-400">
              {packageBlob ? `${(packageBlob.size / 1024).toFixed(0)} KB` : '—'} — Reports, evidence, screenshots, video, HAR
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={handleDownloadZip} className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-semibold rounded-xl transition">
            <Download className="w-4 h-4" /> Download Assessment.zip
          </button>
          {videoBlob && (
            <button onClick={handleDownloadVideo} className="inline-flex items-center gap-2 px-4 py-2.5 bg-red-500/15 hover:bg-red-500/25 text-red-300 font-medium rounded-xl border border-red-500/20 transition">
              <Film className="w-4 h-4" /> Video
            </button>
          )}
          {harJson && (
            <button onClick={handleDownloadHar} className="inline-flex items-center gap-2 px-4 py-2.5 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 font-medium rounded-xl border border-amber-500/20 transition">
              <Network className="w-4 h-4" /> HAR
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {([
          { v: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
          { v: 'findings', label: `Findings (${assessment.findings.length})`, icon: <Shield className="w-4 h-4" /> },
          { v: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
          { v: 'evidence', label: 'Evidence', icon: <Camera className="w-4 h-4" /> },
          { v: 'reproduction', label: `Reproduction (${reproductionResults.length})`, icon: <Film className="w-4 h-4" /> },
        ] as const).map((tab) => (
          <button
            key={tab.v}
            onClick={() => setActiveTab(tab.v)}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${
              activeTab === tab.v ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'overview' && <OverviewTab assessment={assessment} />}
      {activeTab === 'findings' && <FindingsTab assessment={assessment} />}
      {activeTab === 'reports' && <ReportsTab assessment={assessment} onDownloadZip={handleDownloadZip} />}
      {activeTab === 'evidence' && <EvidenceTab videoUrl={videoUrl} screenshots={screenshots} harJson={harJson} assessment={assessment} />}
      {activeTab === 'reproduction' && <ReproductionTab results={reproductionResults} />}

      <div className="text-center mt-8">
        <button onClick={onReset} className="inline-flex items-center gap-2 px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium rounded-xl border border-slate-700/50 transition">
          <RefreshCw className="w-4 h-4" /> New Scan
        </button>
      </div>
    </div>
  );
}

function OverviewTab({ assessment }: { assessment: Assessment }) {
  return (
    <div className="space-y-6">
      {/* Score + severity */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur text-center">
          <div className="w-20 h-20 rounded-full mx-auto flex items-center justify-center text-3xl font-extrabold text-white mb-2"
            style={{ background: assessment.grade.startsWith('A') ? '#10b981' : assessment.grade.startsWith('B') ? '#84cc16' : assessment.grade.startsWith('C') ? '#eab308' : assessment.grade.startsWith('D') ? '#f97316' : '#dc2626' }}>
            {assessment.grade}
          </div>
          <p className="text-2xl font-bold text-white">{assessment.score}/100</p>
          <p className="text-xs text-slate-500 mt-1">Health Score</p>
        </div>

        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur lg:col-span-2">
          <h3 className="text-sm font-bold text-slate-300 mb-4">Severity Distribution</h3>
          <div className="space-y-2.5">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
              const count = assessment.severityCounts[sev];
              const max = Math.max(1, ...Object.values(assessment.severityCounts));
              const pct = (count / max) * 100;
              const colors: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-cyan-500', info: 'bg-slate-500' };
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="text-xs text-slate-400 capitalize w-16">{sev}</span>
                  <div className="flex-1 h-5 bg-slate-800/50 rounded-full overflow-hidden">
                    <div className={`h-full ${colors[sev]} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-sm text-slate-300 font-mono w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Key metrics */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard icon={<Globe className="w-5 h-5" />} label="Target" value={shortenUrl(assessment.finalUrl)} color="text-cyan-400" bg="bg-cyan-500/10" />
        <MetricCard icon={<Cpu className="w-5 h-5" />} label="Technologies" value={String(assessment.recon.technologies.length)} color="text-amber-400" bg="bg-amber-500/10" />
        <MetricCard icon={<Network className="w-5 h-5" />} label="Endpoints" value={String(assessment.recon.endpoints.length)} color="text-violet-400" bg="bg-violet-500/10" />
        <MetricCard icon={<Target className="w-5 h-5" />} label="Total Issues" value={String(assessment.totalIssues)} color="text-red-400" bg="bg-red-500/10" />
      </div>

      {/* Compliance summary */}
      <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur">
        <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
          <FileBarChart className="w-4 h-4 text-emerald-400" />
          Compliance Mapping
        </h3>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {(['gdpr', 'pciDss', 'hipaa', 'iso27001'] as const).map((framework) => {
            const items = assessment.compliance[framework];
            const passed = items.filter((i) => i.status === 'pass').length;
            const failed = items.filter((i) => i.status === 'fail').length;
            return (
              <div key={framework} className="bg-slate-800/30 rounded-xl p-4">
                <div className="text-sm font-semibold text-slate-200 mb-2">{framework.toUpperCase()}</div>
                <div className="flex items-center gap-3 text-xs">
                  <span className="text-emerald-400">{passed} pass</span>
                  <span className="text-red-400">{failed} fail</span>
                  <span className="text-slate-500">{items.length - passed - failed} other</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function FindingsTab({ assessment }: { assessment: Assessment }) {
  return (
    <div className="space-y-3">
      {assessment.findings.map((f, i) => (
        <div key={f.id} className="bg-slate-900/40 border border-slate-700/30 rounded-xl p-4 hover:border-slate-600/50 transition">
          <div className="flex items-start gap-3">
            <span className={`w-9 h-9 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0 ${
              f.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
              f.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
              f.severity === 'medium' ? 'bg-amber-500/15 text-amber-400' :
              f.severity === 'low' ? 'bg-cyan-500/15 text-cyan-400' :
              'bg-slate-500/15 text-slate-400'
            }`}>
              {String(i + 1).padStart(2, '0')}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className={`text-xs font-semibold uppercase ${
                  f.severity === 'critical' ? 'text-red-400' :
                  f.severity === 'high' ? 'text-orange-400' :
                  f.severity === 'medium' ? 'text-amber-400' :
                  f.severity === 'low' ? 'text-cyan-400' : 'text-slate-400'
                }`}>{f.severity}</span>
                {f.cvss && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400">CVSS {f.cvss.score.toFixed(1)}</span>}
                {f.cweId && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-amber-400">{f.cweId}</span>}
                {f.owaspCategory && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-violet-400">{f.owaspCategory}</span>}
                <span className="text-[10px] text-slate-600 capitalize">{f.confidence}</span>
              </div>
              <h4 className="text-sm font-semibold text-slate-200">{f.title}</h4>
              <p className="text-xs text-slate-500 mt-1 line-clamp-2">{f.description}</p>
              <p className="text-xs text-slate-400 mt-1.5"><strong className="text-slate-500">Fix:</strong> {f.recommendation}</p>
            </div>
          </div>
        </div>
      ))}
      {assessment.findings.length === 0 && (
        <div className="text-center py-12 text-slate-500">
          <Shield className="w-10 h-10 mx-auto mb-3 text-slate-700" />
          <p className="text-sm">No findings detected.</p>
        </div>
      )}
    </div>
  );
}

function ReportsTab({ assessment, onDownloadZip }: { assessment: Assessment; onDownloadZip: () => void }) {
  const reports = [
    { label: 'Formal Bug Report (DOC)', desc: 'Full assessment documentation', icon: <FileText className="w-4 h-4" />, action: () => generateFormalBugReport(assessment), color: 'text-cyan-400 bg-cyan-500/10' },
    { label: 'Solution & Remediation (DOC)', desc: 'Developer fix guide', icon: <FileText className="w-4 h-4" />, action: () => generateSolutionReport(assessment), color: 'text-emerald-400 bg-emerald-500/10' },
    { label: 'Vulnerability Submission (DOC)', desc: 'Bug bounty submission format', icon: <FileText className="w-4 h-4" />, action: () => generateFormalSubmissionReport(assessment), color: 'text-violet-400 bg-violet-500/10' },
    { label: 'HackerOne CSV', desc: 'Platform-specific export', icon: <Download className="w-4 h-4" />, action: () => exportHackerOneCsv(assessment), color: 'text-amber-400 bg-amber-500/10' },
    { label: 'Bugcrowd CSV', desc: 'Platform-specific export', icon: <Download className="w-4 h-4" />, action: () => exportBugcrowdCsv(assessment), color: 'text-orange-400 bg-orange-500/10' },
    { label: 'JSON Export', desc: 'Programmatic integration', icon: <Download className="w-4 h-4" />, action: () => exportJsonReport(assessment), color: 'text-blue-400 bg-blue-500/10' },
    { label: 'Assessment.zip', desc: 'Everything bundled (reports + evidence + video + HAR)', icon: <FolderArchive className="w-4 h-4" />, action: onDownloadZip, color: 'text-pink-400 bg-pink-500/10' },
  ];

  return (
    <div className="grid sm:grid-cols-2 gap-3">
      {reports.map((r, i) => (
        <button
          key={i}
          onClick={r.action}
          className="flex items-center gap-3 bg-slate-900/40 border border-slate-700/30 rounded-xl p-4 text-left hover:border-slate-600/50 transition"
        >
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${r.color} flex-shrink-0`}>
            {r.icon}
          </div>
          <div className="flex-1 min-w-0">
            <h4 className="text-sm font-semibold text-slate-200">{r.label}</h4>
            <p className="text-xs text-slate-500">{r.desc}</p>
          </div>
          <Download className="w-4 h-4 text-slate-600 flex-shrink-0" />
        </button>
      ))}
    </div>
  );
}

function EvidenceTab({ videoUrl, screenshots, harJson, assessment }: { videoUrl: string; screenshots: string[]; harJson: string; assessment: Assessment }) {
  return (
    <div className="space-y-6">
      {/* Video */}
      {videoUrl ? (
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
            <Film className="w-4 h-4 text-red-400" /> Screen Recording
          </h3>
          <video src={videoUrl} controls className="w-full rounded-xl border border-slate-700" style={{ maxHeight: '400px' }} />
        </div>
      ) : (
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 text-center text-slate-500">
          <Film className="w-8 h-8 mx-auto mb-2 text-slate-700" />
          <p className="text-sm">No video recording captured</p>
        </div>
      )}

      {/* Screenshots */}
      {screenshots.length > 0 ? (
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
            <Camera className="w-4 h-4 text-cyan-400" /> Screenshots ({screenshots.length})
          </h3>
          <div className="grid sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {screenshots.map((ss, i) => (
              <div key={i} className="rounded-lg border border-slate-700 overflow-hidden">
                <img src={ss} alt={`Screenshot ${i + 1}`} className="w-full h-32 object-cover" />
                <div className="px-2 py-1 text-[10px] text-slate-500 bg-slate-800/30">Finding-{String(i + 1).padStart(3, '0')}</div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 text-center text-slate-500">
          <Camera className="w-8 h-8 mx-auto mb-2 text-slate-700" />
          <p className="text-sm">No screenshots captured</p>
        </div>
      )}

      {/* HAR */}
      {harJson && (
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
            <Network className="w-4 h-4 text-amber-400" /> HAR Export
          </h3>
          <pre className="text-xs text-slate-400 font-mono max-h-48 overflow-y-auto bg-slate-950/40 rounded-lg p-3">{harJson.slice(0, 2000)}{harJson.length > 2000 ? '\n... (truncated)' : ''}</pre>
        </div>
      )}

      {/* Evidence per finding */}
      <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
        <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
          <Package className="w-4 h-4 text-violet-400" /> Evidence Per Finding
        </h3>
        <div className="space-y-2">
          {assessment.findings.filter((f) => f.evidencePackage?.httpRequests?.length || f.evidencePackage?.proofOfConcept).map((f, i) => (
            <div key={f.id} className="bg-slate-800/30 rounded-lg p-3">
              <div className="text-xs font-semibold text-slate-300 mb-1">Finding {String(i + 1).padStart(3, '0')}: {f.title}</div>
              <div className="flex flex-wrap gap-2">
                {f.evidencePackage?.httpRequests?.length && <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">HTTP Request</span>}
                {f.evidencePackage?.httpResponses?.length && <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">HTTP Response</span>}
                {f.evidencePackage?.proofOfConcept && <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">PoC</span>}
                {f.evidencePackage?.reproductionSteps?.length && <span className="text-[10px] px-2 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20">Repro Steps</span>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// --- Reproduction Tab ---

function ReproductionTab({ results }: { results: ReproductionResult[] }) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [videoUrls, setVideoUrls] = useState<Record<number, string>>({});

  useEffect(() => {
    const urls: Record<number, string> = {};
    for (const r of results) {
      if (r.videoBlob) {
        urls[r.findingIndex] = URL.createObjectURL(r.videoBlob);
      }
    }
    setVideoUrls(urls);
    return () => {
      for (const url of Object.values(urls)) URL.revokeObjectURL(url);
    };
  }, [results]);

  const handleDownloadVideo = (r: ReproductionResult) => {
    if (r.videoBlob) {
      const ext = r.videoMimeType.includes('mp4') ? 'mp4' : 'webm';
      downloadBlob(r.videoBlob, `Finding-${String(r.findingIndex + 1).padStart(3, '0')}.${ext}`);
    }
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-slate-500">
        <Film className="w-10 h-10 mx-auto mb-3 text-slate-700" />
        <p className="text-sm">No reproduction results — no findings were detected.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {results.map((r) => {
        const isExpanded = expandedIdx === r.findingIndex;
        const videoUrl = videoUrls[r.findingIndex];
        return (
          <div key={r.findingId} className="bg-slate-900/40 border border-slate-700/30 rounded-xl overflow-hidden">
            {/* Header row */}
            <button
              onClick={() => setExpandedIdx(isExpanded ? null : r.findingIndex)}
              className="w-full flex items-center gap-3 p-4 text-left hover:bg-slate-800/30 transition"
            >
              <span className={`w-9 h-9 rounded-lg flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                r.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
                r.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
                r.severity === 'medium' ? 'bg-amber-500/15 text-amber-400' :
                r.severity === 'low' ? 'bg-cyan-500/15 text-cyan-400' :
                'bg-slate-500/15 text-slate-400'
              }`}>
                {String(r.findingIndex + 1).padStart(2, '0')}
              </span>
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-semibold text-slate-200 truncate">{r.title}</h4>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  <span className={`text-[10px] font-semibold uppercase ${
                    r.severity === 'critical' ? 'text-red-400' :
                    r.severity === 'high' ? 'text-orange-400' :
                    r.severity === 'medium' ? 'text-amber-400' :
                    r.severity === 'low' ? 'text-cyan-400' : 'text-slate-400'
                  }`}>{r.severity}</span>
                  {r.videoBlob && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 flex items-center gap-1"><Film className="w-2.5 h-2.5" /> Video</span>}
                  {r.screenshots.length > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{r.screenshots.length} screenshots</span>}
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    r.success ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                  }`}>{r.success ? 'Reproduced' : 'Partial'}</span>
                  <span className="text-[10px] text-slate-600">{r.duration}s</span>
                </div>
              </div>
              {videoUrl && (
                <span
                  onClick={(e) => { e.stopPropagation(); handleDownloadVideo(r); }}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-red-500/15 hover:bg-red-500/25 text-red-300 text-xs font-medium rounded-lg border border-red-500/20 transition"
                >
                  <Download className="w-3 h-3" /> Video
                </span>
              )}
              {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />}
            </button>

            {/* Expanded content */}
            {isExpanded && (
              <div className="border-t border-slate-800/50 p-4 space-y-4 animate-slide-down">
                {/* Video player */}
                {videoUrl ? (
                  <div>
                    <h5 className="text-xs font-bold text-slate-300 mb-2 flex items-center gap-1.5">
                      <Film className="w-3.5 h-3.5 text-red-400" /> Reproduction Video
                    </h5>
                    <video src={videoUrl} controls className="w-full rounded-xl border border-slate-700" style={{ maxHeight: '360px' }} />
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 bg-slate-800/20 rounded-lg p-3">
                    No video captured for this finding. {r.notes}
                  </div>
                )}

                {/* Screenshots */}
                {r.screenshots.length > 0 && (
                  <div>
                    <h5 className="text-xs font-bold text-slate-300 mb-2 flex items-center gap-1.5">
                      <Camera className="w-3.5 h-3.5 text-cyan-400" /> Screenshots ({r.screenshots.length})
                    </h5>
                    <div className="grid sm:grid-cols-3 lg:grid-cols-4 gap-2">
                      {r.screenshots.map((ss, i) => (
                        <div key={i} className="rounded-lg border border-slate-700 overflow-hidden">
                          <img src={ss} alt={`Reproduction ${i + 1}`} className="w-full h-24 object-cover" />
                          <div className="px-1.5 py-0.5 text-[9px] text-slate-500 bg-slate-800/30">Step {i + 1}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Reproduction steps */}
                <div>
                  <h5 className="text-xs font-bold text-slate-300 mb-2 flex items-center gap-1.5">
                    <ListChecks className="w-3.5 h-3.5 text-emerald-400" /> Reproduction Steps
                  </h5>
                  <ol className="space-y-1.5">
                    {r.reproductionSteps.map((step, i) => (
                      <li key={i} className="text-xs text-slate-400 flex items-start gap-2">
                        <span className="text-slate-600 font-mono flex-shrink-0">{i + 1}.</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Payload used */}
                {r.payloadUsed && (
                  <div>
                    <h5 className="text-xs font-bold text-slate-300 mb-1.5 flex items-center gap-1.5">
                      <KeyRound className="w-3.5 h-3.5 text-amber-400" /> Payload Used
                    </h5>
                    <pre className="text-xs text-amber-300 font-mono bg-slate-950/40 rounded-lg p-3 overflow-x-auto">{r.payloadUsed}</pre>
                  </div>
                )}

                {/* Evidence metadata grid */}
                <div className="grid sm:grid-cols-2 gap-3">
                  {/* Console logs */}
                  {r.consoleLogs.length > 0 && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Terminal className="w-3 h-3 text-emerald-400" /> Console Logs
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">{r.consoleLogs.join('\n')}</pre>
                    </div>
                  )}

                  {/* Network log */}
                  {r.networkLog && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Network className="w-3 h-3 text-amber-400" /> Network Log
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">{r.networkLog}</pre>
                    </div>
                  )}

                  {/* Cookies */}
                  {r.cookies && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Cookie className="w-3 h-3 text-orange-400" /> Cookies
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">{r.cookies}</pre>
                    </div>
                  )}

                  {/* Storage */}
                  {(r.localStorage || r.sessionStorage) && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Database className="w-3 h-3 text-violet-400" /> Storage
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">LocalStorage:\n{r.localStorage}\n\nSessionStorage:\n{r.sessionStorage}</pre>
                    </div>
                  )}

                  {/* HTTP Request */}
                  {r.requestCapture && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Network className="w-3 h-3 text-cyan-400" /> HTTP Request
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">{r.requestCapture}</pre>
                    </div>
                  )}

                  {/* HTTP Response */}
                  {r.responseCapture && (
                    <div className="bg-slate-800/20 rounded-lg p-3">
                      <h5 className="text-[10px] font-bold text-slate-400 mb-1.5 flex items-center gap-1">
                        <Network className="w-3 h-3 text-amber-400" /> HTTP Response
                      </h5>
                      <pre className="text-[10px] text-slate-500 font-mono max-h-32 overflow-y-auto">{r.responseCapture}</pre>
                    </div>
                  )}
                </div>

                {/* Notes */}
                {r.notes && (
                  <div className="text-xs text-slate-500 bg-amber-500/5 border border-amber-500/10 rounded-lg p-3">
                    <strong className="text-amber-400">Notes:</strong> {r.notes}
                  </div>
                )}

                {/* Metadata */}
                <div className="flex items-center gap-4 text-[10px] text-slate-600 border-t border-slate-800/50 pt-3">
                  <span>Timestamp: {new Date(r.timestamp).toLocaleString()}</span>
                  <span>Duration: {r.duration}s</span>
                  <span>Confidence: {r.confidence}</span>
                  <span className={r.success ? 'text-emerald-400' : 'text-amber-400'}>
                    Status: {r.success ? 'Successfully Reproduced' : 'Partial Reproduction'}
                  </span>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// --- Helpers and small components ---

const WORKFLOW_STEPS = [
  { title: 'Validate Target', desc: 'URL format, protocol, reachability' },
  { title: 'Verify Scope', desc: 'Authorization and boundary check' },
  { title: 'Launch Browser Session', desc: 'Isolated capture context with media' },
  { title: 'Reconnaissance', desc: 'Tech fingerprint, DNS, headers, robots' },
  { title: 'Discover Attack Surface', desc: 'Endpoints, APIs, JS, forms, GraphQL' },
  { title: 'Security Tests', desc: 'OWASP Top 10, injection, XSS, CSRF' },
  { title: 'Evidence Capture', desc: 'Screenshots, video, HTTP, console, storage' },
  { title: 'Verify Findings', desc: 'False positive reduction' },
  { title: 'Reproduce Findings', desc: 'Per-finding video proof with payload replay' },
  { title: 'Scoring', desc: 'CVSS, CWE, OWASP, CAPEC, confidence' },
  { title: 'Remediation Advice', desc: 'Step-by-step fix recommendations' },
  { title: 'Executive Summary', desc: 'Business impact, risk matrix' },
  { title: 'Generate Reports', desc: 'DOC, HTML, CSV, JSON, Markdown, XLSX' },
  { title: 'Package ZIP', desc: 'Compress all artifacts into Assessment.zip' },
];

function ToggleChip({ icon, label, enabled, onClick }: { icon: React.ReactNode; label: string; enabled: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-2.5 rounded-xl text-xs font-medium border transition ${
        enabled ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30' : 'bg-slate-800/40 text-slate-500 border-slate-700/30 hover:text-slate-300'
      }`}
    >
      {icon}
      <span className="flex-1 text-left">{label}</span>
      <span className={`w-7 h-4 rounded-full relative transition ${enabled ? 'bg-cyan-500/40' : 'bg-slate-700'}`}>
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${enabled ? 'left-3.5' : 'left-0.5'}`} />
      </span>
    </button>
  );
}

function ProgressStat({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={color}>{icon}</span>
      <div>
        <div className="text-sm font-bold text-slate-200 tabular-nums">{value}</div>
        <div className="text-[10px] text-slate-500">{label}</div>
      </div>
    </div>
  );
}

function MetricCard({ icon, label, value, color, bg }: { icon: React.ReactNode; label: string; value: string; color: string; bg: string }) {
  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-5 backdrop-blur">
      <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center ${color} mb-3`}>{icon}</div>
      <div className="text-lg font-bold text-white truncate">{value}</div>
      <div className="text-xs text-slate-500 mt-0.5">{label}</div>
    </div>
  );
}

function formatElapsed(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

function shortenUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return url.length > 30 ? url.slice(0, 30) + '...' : url;
  }
}
