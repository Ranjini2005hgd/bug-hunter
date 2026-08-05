import { useState, useCallback } from 'react';
import { Shield, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react';
import { isValidUrl } from '@/lib/fetcher';

interface ScannerInputProps {
  onScan: (url: string) => Promise<void>;
  scanning: boolean;
  scanStage: string;
}

const EXAMPLE_SITES = ['example.com', 'wikipedia.org', 'news.ycombinator.com'];

export function ScannerInput({ onScan, scanning, scanStage }: ScannerInputProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      const trimmed = url.trim();
      if (!trimmed) {
        setError('Please enter a website URL to scan.');
        return;
      }
      if (!isValidUrl(trimmed)) {
        setError('That does not look like a valid URL. Try something like example.com');
        return;
      }
      try {
        await onScan(trimmed);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'The scan failed. Please try again.');
      }
    },
    [url, onScan],
  );

  return (
    <div className="w-full max-w-3xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative group">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-2xl opacity-30 group-hover:opacity-60 group-focus-within:opacity-60 transition duration-500 blur-sm" />
          <div className="relative flex items-center bg-slate-900/80 backdrop-blur-xl rounded-2xl border border-slate-700/50 overflow-hidden">
            <div className="pl-5 pr-3 text-slate-500">
              <Shield className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter a website URL to scan (e.g. example.com)"
              disabled={scanning}
              className="flex-1 bg-transparent py-4 pr-3 text-slate-100 placeholder-slate-500 focus:outline-none text-base sm:text-lg font-mono disabled:opacity-50"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
            />
            <button
              type="submit"
              disabled={scanning || !url.trim()}
              className="m-1.5 px-5 sm:px-7 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 disabled:from-slate-700 disabled:to-slate-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all duration-200 flex items-center gap-2 whitespace-nowrap"
            >
              {scanning ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span className="hidden sm:inline">Scanning</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-5 h-5" />
                  <span>Scan Now</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {error && (
        <div className="mt-4 flex items-start gap-2 text-red-400 text-sm bg-red-950/40 border border-red-900/50 rounded-lg px-4 py-3 animate-fade-in">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!scanning && !error && (
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2 text-sm text-slate-500 animate-fade-in delay-200">
          <span className="text-slate-600">Try:</span>
          {EXAMPLE_SITES.map((site) => (
            <button
              key={site}
              onClick={() => setUrl(site)}
              className="px-3 py-1 rounded-full bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700/50 text-slate-400 hover:text-cyan-300 transition font-mono text-xs"
            >
              {site}
            </button>
          ))}
        </div>
      )}

      {scanning && (
        <div className="mt-6 flex items-center justify-center gap-3 text-slate-400 text-sm animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="font-mono">{scanStage}</span>
        </div>
      )}
    </div>
  );
}
