import { useState, useCallback } from 'react';
import { Code2, Loader2, AlertTriangle, Upload, FileCode, CheckCircle2 } from 'lucide-react';
import { analyzeCode, detectLanguage } from '@/lib/codeAnalyzer';
import type { CodeAnalysisResult } from '@/lib/types';
import { SeverityBadge } from './ScanVisuals';

interface CodeScannerPanelProps {
  onResult: (result: CodeAnalysisResult) => void;
  result: CodeAnalysisResult | null;
}

const EXAMPLE_CODE = `const API_KEY = "sk_live_abc123def456";
const dbPassword = "admin123";

function getUser(id) {
  db.query("SELECT * FROM users WHERE id = " + id);
}

function render(input) {
  document.getElementById("content").innerHTML = input;
}

const token = Math.random().toString(36);
exec("ls " + userInput);
eval(responseData);`;

export function CodeScannerPanel({ onResult, result }: CodeScannerPanelProps) {
  const [code, setCode] = useState('');
  const [scanning, setScanning] = useState(false);
  const [language, setLanguage] = useState<string>('auto');

  const handleScan = useCallback(() => {
    if (!code.trim()) return;
    setScanning(true);
    setTimeout(() => {
      const lang = language === 'auto' ? undefined : language as import('@/lib/types').CodeLanguage;
      const res = analyzeCode(code, lang);
      onResult(res);
      setScanning(false);
    }, 600);
  }, [code, language, onResult]);

  const handleExample = () => setCode(EXAMPLE_CODE);
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      setCode(text);
      if (language === 'auto') {
        const detected = detectLanguage(text);
        setLanguage(detected);
      }
    };
    reader.readAsText(file);
  };

  const detectedLang = code.trim() && language === 'auto' ? detectLanguage(code) : language;

  return (
    <div className="w-full max-w-5xl mx-auto">
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-4">
          <Code2 className="w-3.5 h-3.5" />
          Source Code Vulnerability Analyzer
        </div>
        <h2 className="text-3xl font-bold text-white mb-2">Scan source code for security bugs</h2>
        <p className="text-slate-400 text-sm max-w-2xl mx-auto">
          Paste code or upload a file. BugHunter analyzes it for SQL injection, XSS, command injection, hardcoded secrets, weak crypto, path traversal, SSRF, and 20+ more vulnerability patterns.
        </p>
      </div>

      <div className="grid lg:grid-cols-[1fr_300px] gap-6">
        {/* Code input */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="bg-slate-800 border border-slate-700/50 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/50"
              >
                <option value="auto">Auto-detect {code.trim() ? `(${detectedLang})` : ''}</option>
                <option value="javascript">JavaScript</option>
                <option value="typescript">TypeScript</option>
                <option value="python">Python</option>
                <option value="java">Java</option>
                <option value="php">PHP</option>
                <option value="go">Go</option>
                <option value="ruby">Ruby</option>
                <option value="csharp">C#</option>
              </select>
              <span className="text-xs text-slate-500">{code.split('\n').length} lines</span>
            </div>
            <div className="flex items-center gap-2">
              <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg border border-slate-700/50 transition text-xs">
                <Upload className="w-3.5 h-3.5" />
                Upload
                <input type="file" accept=".js,.ts,.jsx,.tsx,.py,.java,.php,.go,.rb,.cs,.txt" onChange={handleFileUpload} className="hidden" />
              </label>
              <button onClick={handleExample} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 rounded-lg border border-slate-700/50 transition text-xs">
                Example
              </button>
            </div>
          </div>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="// Paste your source code here..."
            spellCheck={false}
            className="w-full h-80 bg-slate-950/80 border border-slate-700/50 rounded-xl p-4 font-mono text-sm text-slate-300 focus:outline-none focus:border-cyan-500/50 resize-none"
          />
          <button
            onClick={handleScan}
            disabled={scanning || !code.trim()}
            className="mt-4 w-full inline-flex items-center justify-center gap-2 px-5 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 disabled:from-slate-700 disabled:to-slate-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition"
          >
            {scanning ? (<><Loader2 className="w-5 h-5 animate-spin" /> Analyzing...</>) : (<><AlertTriangle className="w-5 h-5" /> Analyze Code</>)}
          </button>
        </div>

        {/* Results sidebar */}
        <div>
          {result ? (
            <CodeResultsSidebar result={result} />
          ) : (
            <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-5 text-center">
              <FileCode className="w-10 h-10 text-slate-700 mx-auto mb-3" />
              <p className="text-sm text-slate-500">Results will appear here after scanning.</p>
            </div>
          )}
        </div>
      </div>

      {result && result.findings.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Code Findings ({result.findings.length})</h3>
          <div className="space-y-3">
            {result.findings.map((f, i) => (
              <CodeFindingCard key={f.id} finding={f} index={i + 1} />
            ))}
          </div>
        </div>
      )}

      {result && result.findings.length === 0 && (
        <div className="mt-8 text-center py-12 text-slate-500">
          <CheckCircle2 className="w-12 h-12 mx-auto mb-4 text-emerald-400/60" />
          <p className="text-lg">No vulnerabilities detected in this code.</p>
        </div>
      )}
    </div>
  );
}

function CodeResultsSidebar({ result }: { result: CodeAnalysisResult }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of result.findings) counts[f.severity as keyof typeof counts] = (counts[f.severity as keyof typeof counts] || 0) + 1;

  return (
    <div className="bg-slate-900/60 border border-slate-700/40 rounded-2xl p-5 backdrop-blur">
      <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Analysis Results</h3>
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-slate-800/40 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-slate-100">{result.findings.length}</div>
            <div className="text-xs text-slate-500">Findings</div>
          </div>
          <div className="bg-slate-800/40 rounded-lg p-3 text-center">
            <div className="text-2xl font-bold text-slate-100">{result.totalLines}</div>
            <div className="text-xs text-slate-500">Lines</div>
          </div>
        </div>
        <div className="space-y-1.5">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <div key={sev} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-800/30">
              <SeverityBadge severity={sev} size="sm" />
              <span className="text-sm font-semibold text-slate-300">{counts[sev] || 0}</span>
            </div>
          ))}
        </div>
        <div className="pt-2 border-t border-slate-800 text-xs text-slate-500">
          <div>Language: <span className="text-slate-300 font-mono">{result.language}</span></div>
          <div>Scan time: <span className="text-slate-300 font-mono">{result.scanDuration}ms</span></div>
        </div>
      </div>
    </div>
  );
}

function CodeFindingCard({ finding, index }: { finding: import('@/lib/types').CodeFinding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`bg-slate-800/30 border rounded-xl overflow-hidden transition ${expanded ? 'border-cyan-500/40' : 'border-slate-700/40 hover:border-slate-600/60'}`}>
      <button onClick={() => setExpanded(!expanded)} className="w-full flex items-start gap-3 p-4 text-left">
        <span className="text-xs text-slate-600 font-mono mt-1">#{index}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <SeverityBadge severity={finding.severity} size="sm" />
            {finding.cweId && <span className="text-[10px] text-slate-600 font-mono">{finding.cweId}</span>}
            {finding.owaspCategory && <span className="text-[10px] text-slate-600 font-mono">{finding.owaspCategory.split(':')[0]}</span>}
            <span className="text-[10px] text-slate-600">Line {finding.lineStart}</span>
          </div>
          <h4 className="text-sm font-semibold text-slate-200">{finding.title}</h4>
        </div>
      </button>
      {expanded && (
        <div className="px-4 pb-4 space-y-3 animate-slide-down">
          <p className="text-sm text-slate-400">{finding.description}</p>
          <pre className="text-xs text-slate-400 bg-slate-950/60 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre border border-slate-800">{finding.snippet}</pre>
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1">Impact</div>
            <p className="text-sm text-slate-400">{finding.impact}</p>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-cyan-400 font-semibold mb-1">Fix</div>
            <p className="text-sm text-slate-300">{finding.recommendation}</p>
            <ol className="mt-2 space-y-1">
              {finding.fixSteps.map((s, i) => (
                <li key={i} className="text-sm text-slate-400 flex gap-2"><span className="text-cyan-400 font-mono text-xs mt-0.5">{i + 1}.</span><span>{s}</span></li>
              ))}
            </ol>
          </div>
          {(finding.codeBefore || finding.codeAfter) && (
            <div className="grid sm:grid-cols-2 gap-3">
              {finding.codeBefore && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-red-400/70 mb-1 font-semibold">Before</div>
                  <pre className="text-xs text-red-300/80 bg-red-950/30 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-red-900/30">{finding.codeBefore}</pre>
                </div>
              )}
              {finding.codeAfter && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-emerald-400/70 mb-1 font-semibold">After</div>
                  <pre className="text-xs text-emerald-300/80 bg-emerald-950/30 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-emerald-900/30">{finding.codeAfter}</pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
