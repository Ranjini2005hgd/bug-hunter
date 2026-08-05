import { useState, useCallback, useEffect } from 'react';
import { Bug, ShieldCheck, Github, Zap, Gauge, Cpu, Network, Scale, GitBranch, Eye, ScanLine, FileText, Code2, Globe, Video, FolderOpen, LayoutDashboard, Shield } from 'lucide-react';
import type { Assessment, CodeAnalysisResult, Finding } from '@/lib/types';
import { fetchSite, runScanFlow, saveScan, loadRecentScans } from '@/lib/fetcher';
import { ScannerInput } from '@/components/ScannerInput';
import { ScanProgress } from '@/components/ScanVisuals';
import { ResultsDashboard } from '@/components/ResultsDashboard';
import { ScanHistory } from '@/components/ScanHistory';
import { CodeScannerPanel } from '@/components/CodeScannerPanel';
import { BugRecorder } from '@/components/BugRecorder';
import { BugGallery } from '@/components/BugGallery';
import { Dashboard } from '@/components/Dashboard';
import { SecuritySuite } from '@/components/SecuritySuite';

type AppState = 'idle' | 'scanning' | 'results' | 'error';

export default function App() {
  const [state, setState] = useState<AppState>('idle');
  const [result, setResult] = useState<Assessment | null>(null);
  const [scanStage, setScanStage] = useState('');
  const [scanningUrl, setScanningUrl] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<Assessment[]>([]);
  const [mode, setMode] = useState<'dashboard' | 'website' | 'code' | 'recorder' | 'gallery' | 'suite'>('dashboard');
  const [codeResult, setCodeResult] = useState<CodeAnalysisResult | null>(null);
  const [recordingFinding, setRecordingFinding] = useState<Finding | null>(null);

  useEffect(() => {
    loadRecentScans(10).then((scans) => setHistory(scans)).catch(() => {});
  }, []);

  const handleScan = useCallback(async (url: string) => {
    setState('scanning');
    setScanningUrl(url);
    setError(null);
    setScanStage('Step 1/10 — Validating scope and authorization...');

    try {
      const fetchResult = await fetchSite(url);
      const stages = [
        'Step 2/10 — Running reconnaissance & technology fingerprinting...',
        'Step 3/10 — Discovering assets and subdomains...',
        'Step 4/10 — Mapping endpoints and parameters...',
        'Step 5/10 — Testing OWASP Top 10 vulnerability classes...',
        'Step 6/10 — AI analysis: classifying findings by confidence...',
        'Step 7/10 — Collecting evidence (HTTP req/res, PoC)...',
        'Step 8/10 — Assessing severity with CVSS 3.1 scoring...',
        'Step 9/10 — Generating compliance mapping (GDPR, PCI, HIPAA, ISO)...',
        'Step 10/10 — Compiling findings and generating reports...',
      ];
      for (const stage of stages) {
        setScanStage(stage);
        await new Promise((r) => setTimeout(r, 350));
      }

      const assessment = await runScanFlow(fetchResult);
      saveScan(assessment).catch((e) => console.error('Failed to save assessment:', e));
      setResult(assessment);
      setHistory((prev) => [assessment, ...prev.filter((s) => s.id !== assessment.id)].slice(0, 10));
      setState('results');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The assessment failed unexpectedly.');
      setState('error');
    }
  }, []);

  const handleScanAgain = useCallback(() => {
    setResult(null);
    setError(null);
    setState('idle');
  }, []);

  const handleSelectHistory = useCallback((scan: Assessment) => {
    setResult(scan);
    setState('results');
  }, []);

  const handleClearHistory = useCallback(() => setHistory([]), []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 relative overflow-x-hidden">
      <div className="fixed inset-0 grid-bg pointer-events-none opacity-40" />
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-[120px] pointer-events-none" />

      <div className="relative z-10">
        <header className="border-b border-slate-800/50 backdrop-blur-md bg-slate-950/50 sticky top-0 z-20">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center glow-blue">
                <Bug className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-extrabold text-white tracking-tight leading-none">BugHunter <span className="text-cyan-400">Pro</span></h1>
                <p className="text-[11px] text-slate-500 leading-none mt-0.5">AI-Powered Security Assessment Platform</p>
              </div>
            </div>
            <div className="hidden sm:flex items-center gap-5 text-xs text-slate-500">
              <span className="flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5 text-cyan-400" /> OWASP Top 10</span>
              <span className="flex items-center gap-1.5"><Zap className="w-3.5 h-3.5 text-cyan-400" /> CVSS 3.1</span>
              <span className="flex items-center gap-1.5"><Scale className="w-3.5 h-3.5 text-cyan-400" /> GDPR / PCI / HIPAA</span>
            </div>
          </div>
        </header>

        <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-12">
          {/* Mode switcher */}
          <div className="flex items-center justify-center gap-2 mb-8">
            <button
              onClick={() => { setMode('dashboard'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'dashboard' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <LayoutDashboard className="w-4 h-4" />
              Dashboard
            </button>
            <button
              onClick={() => { setMode('suite'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'suite' ? 'bg-red-500/15 text-red-300 border border-red-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <Shield className="w-4 h-4" />
              Security Suite
            </button>
            <button
              onClick={() => { setMode('website'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'website' && state !== 'scanning' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <Globe className="w-4 h-4" />
              Website Scanner
            </button>
            <button
              onClick={() => { setMode('code'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'code' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <Code2 className="w-4 h-4" />
              Code Analyzer
            </button>
            <button
              onClick={() => { setMode('recorder'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'recorder' ? 'bg-red-500/15 text-red-300 border border-red-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <Video className="w-4 h-4" />
              Bug Recorder
            </button>
            <button
              onClick={() => { setMode('gallery'); setState('idle'); }}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition ${mode === 'gallery' ? 'bg-violet-500/15 text-violet-300 border border-violet-500/30' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'}`}
            >
              <FolderOpen className="w-4 h-4" />
              Saved Bugs
            </button>
          </div>

          {mode === 'code' && state !== 'scanning' && (
            <CodeScannerPanel onResult={setCodeResult} result={codeResult} />
          )}

          {mode === 'recorder' && (
            <BugRecorder
              prefilledFinding={recordingFinding}
              targetUrl={recordingFinding?.affectedEndpoint || result?.finalUrl}
              onClearFinding={() => setRecordingFinding(null)}
            />
          )}

          {mode === 'gallery' && (
            <BugGallery />
          )}

          {mode === 'suite' && (
            <SecuritySuite />
          )}

          {mode === 'dashboard' && (
            <Dashboard onScanAgain={() => setMode('website')} />
          )}

          {mode === 'website' && (
            <>
          {state === 'idle' && (
            <IdleView onScan={handleScan} scanning={false} scanStage={scanStage} history={history} currentId={null} onSelectHistory={handleSelectHistory} onClearHistory={handleClearHistory} />
          )}
          {state === 'scanning' && (
            <ScanProgress stage={scanStage} url={scanningUrl} />
          )}
          {state === 'error' && (
            <ErrorView message={error} onRetry={handleScanAgain} onScan={handleScan} scanning={false} scanStage={scanStage} history={history} currentId={null} onSelectHistory={handleSelectHistory} onClearHistory={handleClearHistory} />
          )}
          {state === 'results' && result && (
            <div className="grid lg:grid-cols-[1fr_280px] gap-8">
              <ResultsDashboard result={result} onScanAgain={handleScanAgain} onRecordEvidence={(finding) => { setRecordingFinding(finding); setMode('recorder'); }} />
              <aside className="lg:sticky lg:top-24 lg:self-start">
                <ScannerInput onScan={handleScan} scanning={false} scanStage={scanStage} />
                <div className="mt-6">
                  <ScanHistory scans={history} currentId={result.id} onSelect={handleSelectHistory} onClear={handleClearHistory} />
                </div>
              </aside>
            </div>
          )}
            </>
          )}
        </main>

        <footer className="border-t border-slate-800/50 mt-16">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-600">
            <p>BugHunter Pro — 10-step security assessment workflow | 65+ checks | CVSS 3.1 | GDPR, PCI DSS, HIPAA, ISO 27001 compliance mapping</p>
            <p className="flex items-center gap-1.5"><Github className="w-3.5 h-3.5" /> Authorized security testing only. Passive analysis — no active exploitation.</p>
          </div>
        </footer>
      </div>
    </div>
  );
}

interface IdleViewProps {
  onScan: (url: string) => Promise<void>;
  scanning: boolean;
  scanStage: string;
  history: Assessment[];
  currentId: string | null;
  onSelectHistory: (s: Assessment) => void;
  onClearHistory: () => void;
}

function IdleView({ onScan, scanning, scanStage, history, currentId, onSelectHistory, onClearHistory }: IdleViewProps) {
  return (
    <div className="animate-fade-in">
      <div className="text-center mb-12 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium mb-6 animate-fade-in">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          10-Step Bug Bounty Workflow | CVSS 3.1 | Evidence Packages | Compliance Mapping
        </div>
        <h2 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight mb-4 leading-tight">
          Find every bug in
          <br />
          <span className="gradient-text">any website</span>
        </h2>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-2xl mx-auto">
          BugHunter Pro runs a full security assessment — scope validation, reconnaissance, technology fingerprinting,
          endpoint mapping, OWASP Top 10 testing, CVSS scoring, evidence collection, and compliance mapping — then
          generates two downloadable professional reports.
        </p>
      </div>

      <ScannerInput onScan={onScan} scanning={scanning} scanStage={scanStage} />

      <div className="mt-16 grid sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-5xl mx-auto">
        <FeatureCard icon={<GitBranch className="w-5 h-5" />} title="10-Step Workflow" items={['Scope validation', 'Recon & asset discovery', 'Endpoint mapping', 'Vuln testing & AI analysis', 'Evidence & severity assessment']} color="text-cyan-400" bg="bg-cyan-500/10" />
        <FeatureCard icon={<ShieldCheck className="w-5 h-5" />} title="OWASP + CVSS" items={['OWASP Top 10 (2021)', 'CVSS 3.1 scoring', 'CWE classification', 'XSS, CSRF, SSRF detection', 'Cookie & header security']} color="text-red-400" bg="bg-red-500/10" />
        <FeatureCard icon={<Cpu className="w-5 h-5" />} title="Recon & Assets" items={['Technology fingerprinting', 'DNS resolution (DoH)', 'Endpoint discovery', 'JS resource mapping', 'robots.txt & sitemap']} color="text-amber-400" bg="bg-amber-500/10" />
        <FeatureCard icon={<Scale className="w-5 h-5" />} title="Compliance" items={['GDPR Article 32', 'PCI DSS Requirements', 'HIPAA Security Rule', 'ISO 27001 Controls', 'Pass/fail per control']} color="text-emerald-400" bg="bg-emerald-500/10" />
        <FeatureCard icon={<Eye className="w-5 h-5" />} title="Evidence Packages" items={['HTTP request captures', 'HTTP response captures', 'Proof of Concept', 'Reproduction steps', 'Finding timelines']} color="text-violet-400" bg="bg-violet-500/10" />
        <FeatureCard icon={<Gauge className="w-5 h-5" />} title="Accessibility" items={['WCAG 2.1 A & AA', 'Alt text & form labels', 'Heading hierarchy', 'Landmarks & skip links', 'Focus management']} color="text-amber-400" bg="bg-amber-500/10" />
        <FeatureCard icon={<Zap className="w-5 h-5" />} title="Performance" items={['Core Web Vitals', 'Render-blocking detection', 'Image optimization', 'Compression & caching', 'DOM size analysis']} color="text-cyan-400" bg="bg-cyan-500/10" />
        <FeatureCard icon={<FileTextIcon />} title="Reports" items={['Formal bug report (.doc)', 'Solution guide (.doc)', 'Executive summary', 'Compliance assessment', 'Evidence documentation']} color="text-pink-400" bg="bg-pink-500/10" />
      </div>

      <div className="mt-12 max-w-5xl mx-auto">
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur">
          <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2"><ScanLine className="w-4 h-4 text-cyan-400" /> The 10-Step Assessment Workflow</h3>
          <div className="grid sm:grid-cols-2 gap-x-6 gap-y-2">
            {[
              'Scope Validation', 'Reconnaissance', 'Asset Discovery', 'Endpoint Mapping',
              'Vulnerability Testing', 'AI Analysis', 'Evidence Collection', 'Severity Assessment',
              'Report Generation', 'Human Review',
            ].map((step, i) => (
              <div key={i} className="flex items-center gap-3 text-sm text-slate-400">
                <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-[10px] font-mono text-cyan-400 flex-shrink-0">{i + 1}</span>
                {step}
              </div>
            ))}
          </div>
        </div>
      </div>

      {history.length > 0 && (
        <div className="mt-12 max-w-5xl mx-auto">
          <ScanHistory scans={history} currentId={currentId} onSelect={onSelectHistory} onClear={onClearHistory} />
        </div>
      )}
    </div>
  );
}

function ErrorView({ message, onRetry, onScan, scanning, scanStage, history, currentId, onSelectHistory, onClearHistory }: IdleViewProps & { message: string | null; onRetry: () => void }) {
  return (
    <div className="animate-fade-in">
      <div className="text-center mb-10 max-w-2xl mx-auto">
        <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-4">
          <Bug className="w-8 h-8 text-red-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-2">Assessment could not complete</h2>
        <p className="text-slate-400">{message || 'Something went wrong while scanning the site.'}</p>
        <button onClick={onRetry} className="mt-6 inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-semibold rounded-xl transition">
          Try Again
        </button>
      </div>
      <ScannerInput onScan={onScan} scanning={scanning} scanStage={scanStage} />
      {history.length > 0 && (
        <div className="mt-12 max-w-5xl mx-auto">
          <ScanHistory scans={history} currentId={currentId} onSelect={onSelectHistory} onClear={onClearHistory} />
        </div>
      )}
    </div>
  );
}

function FeatureCard({ icon, title, items, color, bg }: { icon: React.ReactNode; title: string; items: string[]; color: string; bg: string }) {
  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-5 backdrop-blur hover:border-slate-600/50 transition">
      <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center ${color} mb-3`}>{icon}</div>
      <h3 className="text-sm font-bold text-slate-200 mb-2.5">{title}</h3>
      <ul className="space-y-1.5">
        {items.map((item, i) => (
          <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
            <span className={`mt-1 w-1 h-1 rounded-full ${color} opacity-60 flex-shrink-0`} />
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

function FileTextIcon() {
  return <FileText className="w-5 h-5" />;
}
