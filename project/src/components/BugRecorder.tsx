import { useState, useRef, useEffect, useCallback } from 'react';
import { Video, Camera, Square, Plus, Check, Clock, Activity, AlertCircle, Download, FileText, X, Circle, StopCircle, Trash2, Globe, Film } from 'lucide-react';
import { BugRecorderEngine, formatDuration, formatRelativeTime, generateBugReportMarkdown, downloadBugPackage, downloadReportPdf } from '@/lib/bugRecorder';
import { generateBugId, saveBugRecord } from '@/lib/bugDb';
import type { RecordingStep, Severity, Finding } from '@/lib/types';

type RecorderState = 'idle' | 'recording' | 'finalizing' | 'done';

interface BugRecorderProps {
  prefilledFinding?: Finding | null;
  targetUrl?: string;
  onClearFinding?: () => void;
}

export function BugRecorder({ prefilledFinding, targetUrl, onClearFinding }: BugRecorderProps) {
  const [recorderState, setRecorderState] = useState<RecorderState>('idle');
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<Severity>('high');
  const [targetUrlState, setTargetUrlState] = useState('');
  const [notes, setNotes] = useState('');
  const [vulnClass, setVulnClass] = useState('');
  const [steps, setSteps] = useState<RecordingStep[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [screenshotCount, setScreenshotCount] = useState(0);
  const [httpCount, setHttpCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [savedBugId, setSavedBugId] = useState<string | null>(null);
  const [savedReport, setSavedReport] = useState<string>('');
  const [noteInput, setNoteInput] = useState('');

  const engineRef = useRef<BugRecorderEngine | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const savedBugIdRef = useRef<string | null>(null);

  // Auto-populate from a scan finding when provided
  useEffect(() => {
    if (prefilledFinding && recorderState === 'idle') {
      setTitle(prefilledFinding.title || '');
      setSeverity(prefilledFinding.severity || 'high');
      setVulnClass(
        prefilledFinding.vulnerabilityClass ||
        prefilledFinding.owaspCategory?.split(':')[0] ||
        prefilledFinding.cweId ||
        ''
      );
      const findingNotes = [
        prefilledFinding.description,
        prefilledFinding.impact ? `Impact: ${prefilledFinding.impact}` : '',
        prefilledFinding.evidencePackage?.proofOfConcept ? `PoC: ${prefilledFinding.evidencePackage.proofOfConcept}` : '',
        prefilledFinding.aiExplanation?.attackScenario ? `AI Attack Scenario: ${prefilledFinding.aiExplanation.attackScenario}` : '',
      ].filter(Boolean).join('\n\n');
      setNotes(findingNotes);
    }
  }, [prefilledFinding, recorderState]);

  // Auto-populate target URL if provided
  useEffect(() => {
    if (targetUrl && recorderState === 'idle') {
      setTargetUrlState(targetUrl);
    }
  }, [targetUrl, recorderState]);

  const stopTimer = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const startTimer = useCallback(() => {
    stopTimer();
    timerRef.current = setInterval(() => {
      if (engineRef.current) {
        setElapsed(engineRef.current.elapsedMs);
        setSteps(engineRef.current.getSteps());
        setHttpCount(engineRef.current.httpCount);
        setScreenshotCount(engineRef.current.screenshotCount);
      }
    }, 500);
  }, [stopTimer]);

  const handleStart = useCallback(async () => {
    setError(null);
    setSavedBugId(null);
    setSavedReport('');
    setSteps([]);
    setElapsed(0);
    setScreenshotCount(0);
    setHttpCount(0);

    const engine = new BugRecorderEngine();
    engineRef.current = engine;

    try {
      await engine.startRecording();
      setRecorderState('recording');
      startTimer();
      engine.addStep('navigate', 'Screen recording started', targetUrlState || 'desktop');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start screen recording. Please grant screen capture permission.');
      engine.cancel();
      engineRef.current = null;
    }
  }, [targetUrlState, startTimer]);

  const handleScreenshot = useCallback(async () => {
    if (!engineRef.current) return;
    const dataUrl = await engineRef.current.captureScreenshot();
    if (dataUrl) {
      engineRef.current.addStep('screenshot', 'Screenshot captured', targetUrlState || 'desktop', dataUrl);
      setSteps(engineRef.current.getSteps());
      setScreenshotCount(engineRef.current.screenshotCount);
    }
  }, [targetUrlState]);

  const handleAddNote = useCallback(() => {
    if (!engineRef.current || !noteInput.trim()) return;
    engineRef.current.addNote(noteInput.trim(), targetUrlState || 'desktop');
    setSteps(engineRef.current.getSteps());
    setNoteInput('');
  }, [noteInput, targetUrlState]);

  const handleStop = useCallback(async () => {
    if (!engineRef.current) return;
    setRecorderState('finalizing');
    stopTimer();

    const engine = engineRef.current;
    await engine.stopRecording();

    const duration = engine.getRecordingDuration();
    const allSteps = engine.getSteps();
    const allHttp = engine.getHttpEntries();
    const allScreenshots = engine.getScreenshots();
    const bugId = generateBugId();
    savedBugIdRef.current = bugId;

    const report = generateBugReportMarkdown({
      bugId,
      title: title || 'Untitled Bug',
      severity,
      targetUrl: targetUrlState || 'N/A',
      notes,
      vulnerabilityClass: vulnClass || undefined,
      steps: allSteps,
      httpEntries: allHttp,
      recordingDuration: duration,
      screenshotCount: allScreenshots.length,
      createdAt: new Date().toISOString(),
    });

    setSavedReport(report);
    setSavedBugId(bugId);
    setSteps(allSteps);

    await saveBugRecord({
      bugId,
      title: title || 'Untitled Bug',
      severity,
      status: 'open',
      targetUrl: targetUrlState || 'N/A',
      notes,
      vulnerabilityClass: vulnClass || undefined,
      steps: allSteps,
      httpEntries: allHttp,
      recordingDuration: duration,
      screenshotCount: allScreenshots.length,
      screenshots: [],
      reportMarkdown: report,
    });

    setRecorderState('done');
  }, [title, severity, targetUrlState, notes, vulnClass, stopTimer]);

  const handleDownloadZip = useCallback(async () => {
    if (!engineRef.current || !savedBugIdRef.current) return;
    await downloadBugPackage({
      bugId: savedBugIdRef.current,
      title: title || 'Untitled Bug',
      reportMarkdown: savedReport,
      recordingBlob: engineRef.current.getRecordingBlob(),
      screenshots: engineRef.current.getScreenshots(),
      steps: engineRef.current.getSteps(),
      videoMimeType: engineRef.current.getVideoMimeType(),
    });
  }, [savedReport, title]);

  const handleDownloadVideo = useCallback(() => {
    if (!engineRef.current || !savedBugIdRef.current) return;
    const blob = engineRef.current.getRecordingBlob();
    if (!blob) return;
    const ext = engineRef.current.getVideoMimeType().includes('mp4') ? 'mp4' : 'webm';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${savedBugIdRef.current}-video.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, []);

  const handleDownloadReport = useCallback(() => {
    if (!savedBugIdRef.current) return;
    downloadReportPdf(savedBugIdRef.current, savedReport);
  }, [savedReport]);

  const handleNewBug = useCallback(() => {
    if (engineRef.current) {
      engineRef.current.cancel();
      engineRef.current = null;
    }
    savedBugIdRef.current = null;
    setRecorderState('idle');
    setTitle('');
    setNotes('');
    setVulnClass('');
    setSteps([]);
    setElapsed(0);
    setScreenshotCount(0);
    setHttpCount(0);
    setSavedBugId(null);
    setSavedReport('');
    setError(null);
    setNoteInput('');
    onClearFinding?.();
  }, [onClearFinding]);

  const handleCancelRecording = useCallback(() => {
    if (engineRef.current) {
      engineRef.current.cancel();
      engineRef.current = null;
    }
    stopTimer();
    setRecorderState('idle');
    setSteps([]);
    setElapsed(0);
    setScreenshotCount(0);
    setHttpCount(0);
    setNoteInput('');
  }, [stopTimer]);

  useEffect(() => {
    return () => {
      stopTimer();
      if (engineRef.current) {
        engineRef.current.cancel();
      }
    };
  }, [stopTimer]);

  // --- IDLE STATE ---
  if (recorderState === 'idle') {
    return (
      <div className="animate-fade-in max-w-3xl mx-auto">
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium mb-6">
            <Video className="w-3.5 h-3.5" />
            Bug Recorder — Capture, Document, Submit
          </div>
          <h2 className="text-4xl font-extrabold text-white tracking-tight mb-4">
            Record a <span className="gradient-text">Bug</span>
          </h2>
          <p className="text-slate-400 max-w-xl mx-auto">
            Click "New Bug" to start a screen recording. The recorder captures your screen,
            HTTP traffic, and timestamps. When you click "Finish Bug", it generates a complete
            evidence package with video, screenshots, and a submission-ready report.
          </p>
        </div>

        {/* Prefilled finding banner */}
        {prefilledFinding && (
          <div className="mb-6 bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4 flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
              <Check className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex-1">
              <p className="text-sm text-cyan-300 font-medium">Finding pre-loaded from scan</p>
              <p className="text-xs text-slate-400 mt-1">{prefilledFinding.title}</p>
              <p className="text-[10px] text-slate-600 mt-0.5">
                Bug details auto-filled. Start recording to capture video evidence of this vulnerability.
              </p>
            </div>
            <button
              onClick={() => onClearFinding?.()}
              className="text-slate-500 hover:text-slate-300 transition flex-shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {error && (
          <div className="mb-6 bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-red-300 font-medium">Recording Error</p>
              <p className="text-xs text-red-400/70 mt-1">{error}</p>
            </div>
          </div>
        )}

        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur space-y-5">
          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Bug Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Stored XSS in profile bio field"
              className="w-full bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
            />
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Severity</label>
              <div className="flex gap-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    className={`px-3 py-2 rounded-lg text-xs font-medium border transition flex-1 ${
                      severity === s
                        ? s === 'critical' ? 'bg-red-500/20 text-red-300 border-red-500/40'
                        : s === 'high' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40'
                        : s === 'medium' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : s === 'low' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                        : 'bg-slate-500/20 text-slate-300 border-slate-500/40'
                        : 'bg-slate-800/40 text-slate-500 border-slate-700/30 hover:text-slate-300'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Target URL</label>
              <input
                type="text"
                value={targetUrlState}
                onChange={(e) => setTargetUrlState(e.target.value)}
                placeholder="https://example.com/vulnerable-page"
                className="w-full bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Vulnerability Class (optional)</label>
            <input
              type="text"
              value={vulnClass}
              onChange={(e) => setVulnClass(e.target.value)}
              placeholder="e.g. XSS, SQLi, IDOR, RCE, CSRF"
              className="w-full bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 font-semibold mb-2">Notes (optional)</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Additional context about the vulnerability, affected users, business impact..."
              rows={3}
              className="w-full bg-slate-950/60 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition resize-none"
            />
          </div>

          <button
            onClick={handleStart}
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-4 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-bold rounded-xl transition glow-blue"
          >
            <Circle className="w-5 h-5 fill-current" />
            New Bug — Start Recording
          </button>
        </div>

        {/* Feature overview */}
        <div className="mt-8 grid sm:grid-cols-3 gap-4">
          <FeatureMini icon={<Video className="w-4 h-4" />} title="Screen Recording" desc="Full screen capture with audio" color="text-red-400" bg="bg-red-500/10" />
          <FeatureMini icon={<Camera className="w-4 h-4" />} title="Screenshots" desc="Capture key moments on demand" color="text-cyan-400" bg="bg-cyan-500/10" />
          <FeatureMini icon={<Activity className="w-4 h-4" />} title="HTTP Traffic" desc="Automatic request monitoring" color="text-amber-400" bg="bg-amber-500/10" />
          <FeatureMini icon={<Clock className="w-4 h-4" />} title="Timestamped Steps" desc="Every action logged with time" color="text-violet-400" bg="bg-violet-500/10" />
          <FeatureMini icon={<Film className="w-4 h-4" />} title="Video Download" desc="Download raw video file" color="text-pink-400" bg="bg-pink-500/10" />
          <FeatureMini icon={<Download className="w-4 h-4" />} title="ZIP Package" desc="Video + screenshots + report" color="text-emerald-400" bg="bg-emerald-500/10" />
        </div>
      </div>
    );
  }

  // --- RECORDING STATE ---
  if (recorderState === 'recording') {
    return (
      <div className="animate-fade-in max-w-4xl mx-auto">
        {/* Recording bar */}
        <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-4 mb-6 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500 animate-pulse" />
              <span className="text-sm font-bold text-red-300">RECORDING</span>
            </div>
            <span className="text-2xl font-mono font-bold text-white tabular-nums">{formatDuration(Math.floor(elapsed / 1000))}</span>
            <span className="text-xs text-slate-500">
              <Camera className="w-3.5 h-3.5 inline mr-1 text-cyan-400" />{screenshotCount}
              <Activity className="w-3.5 h-3.5 inline ml-3 mr-1 text-amber-400" />{httpCount} HTTP
              <Clock className="w-3.5 h-3.5 inline ml-3 mr-1 text-violet-400" />{steps.length} steps
            </span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleScreenshot}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 text-sm rounded-lg border border-cyan-500/20 transition"
            >
              <Camera className="w-4 h-4" />
              Screenshot
            </button>
            <button
              onClick={handleCancelRecording}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 text-sm rounded-lg border border-slate-700/50 transition"
            >
              <X className="w-4 h-4" />
              Cancel
            </button>
            <button
              onClick={handleStop}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-semibold rounded-lg transition"
            >
              <StopCircle className="w-4 h-4" />
              Finish Bug
            </button>
          </div>
        </div>

        {/* Quick note input */}
        <div className="flex gap-2 mb-6">
          <input
            type="text"
            value={noteInput}
            onChange={(e) => setNoteInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAddNote()}
            placeholder="Add a note about what you're doing right now..."
            className="flex-1 bg-slate-900/60 border border-slate-700/50 rounded-xl px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500/50 focus:outline-none transition"
          />
          <button
            onClick={handleAddNote}
            className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-xl border border-slate-700/50 transition"
          >
            <Plus className="w-4 h-4" />
            Add Note
          </button>
        </div>

        {/* Steps log */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl backdrop-blur">
          <div className="px-5 py-3 border-b border-slate-800/50">
            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
              <Clock className="w-4 h-4 text-violet-400" />
              Recorded Steps ({steps.length})
            </h3>
          </div>
          <div className="max-h-[400px] overflow-y-auto p-4 space-y-2">
            {steps.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-8">No steps recorded yet. Take screenshots and add notes as you reproduce the bug.</p>
            ) : (
              steps.map((step, i) => (
                <div key={step.id} className="flex items-start gap-3 bg-slate-800/30 rounded-lg p-3">
                  <span className="text-xs font-mono text-slate-600 mt-0.5 w-6 text-right">{i + 1}</span>
                  <span className="text-xs font-mono text-cyan-400 mt-0.5 w-16 flex-shrink-0">{formatRelativeTime(step.relativeTime)}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <ActionIcon action={step.action} />
                      <span className="text-xs text-slate-400 capitalize">{step.action}</span>
                    </div>
                    <p className="text-sm text-slate-300 mt-0.5">{step.description}</p>
                    {step.url && step.url !== 'desktop' && (
                      <p className="text-[10px] text-slate-600 mt-0.5 truncate"><Globe className="w-2.5 h-2.5 inline mr-1" />{step.url}</p>
                    )}
                  </div>
                  {step.screenshotDataUrl && (
                    <img src={step.screenshotDataUrl} alt="step screenshot" className="w-16 h-10 object-cover rounded border border-slate-700" />
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Bug details preview */}
        <div className="mt-6 bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur">
          <div className="grid sm:grid-cols-3 gap-3 text-xs">
            <div><span className="text-slate-500">Title:</span> <span className="text-slate-300">{title || 'Untitled'}</span></div>
            <div><span className="text-slate-500">Severity:</span> <span className="text-slate-300 capitalize">{severity}</span></div>
            <div><span className="text-slate-500">Target:</span> <span className="text-slate-300 truncate">{targetUrlState || 'N/A'}</span></div>
          </div>
        </div>
      </div>
    );
  }

  // --- DONE STATE ---
  if (recorderState === 'done') {
    const hasVideo = engineRef.current?.getRecordingBlob() != null;
    return (
      <div className="animate-fade-in max-w-3xl mx-auto">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
            <Check className="w-8 h-8 text-emerald-400" />
          </div>
          <h2 className="text-3xl font-extrabold text-white mb-2">Bug Package Ready</h2>
          <p className="text-slate-400">Your bug evidence package has been generated and saved.</p>
          <p className="text-xs text-slate-600 font-mono mt-2">ID: {savedBugId}</p>
        </div>

        {/* Video preview */}
        {hasVideo && engineRef.current && (
          <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-4 backdrop-blur mb-6">
            <h3 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
              <Film className="w-4 h-4 text-cyan-400" />
              Video Evidence
            </h3>
            <VideoPreview engine={engineRef.current} />
          </div>
        )}

        {/* Summary card */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl p-6 backdrop-blur mb-6">
          <div className="grid sm:grid-cols-2 gap-4 mb-5">
            <SummaryItem label="Title" value={title || 'Untitled Bug'} />
            <SummaryItem label="Severity" value={severity} />
            <SummaryItem label="Target URL" value={targetUrlState || 'N/A'} />
            <SummaryItem label="Recording Duration" value={formatDuration(Math.floor(elapsed / 1000))} />
            <SummaryItem label="Steps Recorded" value={String(steps.length)} />
            <SummaryItem label="HTTP Entries" value={String(httpCount)} />
            <SummaryItem label="Screenshots" value={String(screenshotCount)} />
            <SummaryItem label="Vulnerability Class" value={vulnClass || 'N/A'} />
          </div>

          {/* Download buttons */}
          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleDownloadVideo}
              disabled={!hasVideo}
              className="inline-flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white font-semibold rounded-xl transition glow-blue disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Film className="w-5 h-5" />
              Download Video
            </button>
            <button
              onClick={handleDownloadZip}
              className="inline-flex items-center gap-2 px-5 py-3 bg-violet-500/15 hover:bg-violet-500/25 text-violet-300 font-medium rounded-xl border border-violet-500/20 transition"
            >
              <Download className="w-5 h-5" />
              Download ZIP Package
            </button>
            <button
              onClick={handleDownloadReport}
              className="inline-flex items-center gap-2 px-5 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium rounded-xl border border-slate-700/50 transition"
            >
              <FileText className="w-5 h-5" />
              Download Report (HTML)
            </button>
            <button
              onClick={handleNewBug}
              className="inline-flex items-center gap-2 px-5 py-3 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 font-medium rounded-xl border border-emerald-500/20 transition"
            >
              <Plus className="w-5 h-5" />
              Record New Bug
            </button>
          </div>
        </div>

        {/* Report preview */}
        <div className="bg-slate-900/40 border border-slate-700/30 rounded-2xl backdrop-blur overflow-hidden">
          <div className="px-5 py-3 border-b border-slate-800/50">
            <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
              <FileText className="w-4 h-4 text-emerald-400" />
              Report Preview
            </h3>
          </div>
          <div className="p-5 max-h-[400px] overflow-y-auto">
            <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap leading-relaxed">{savedReport}</pre>
          </div>
        </div>
      </div>
    );
  }

  // --- FINALIZING STATE ---
  return (
    <div className="animate-fade-in max-w-3xl mx-auto text-center py-20">
      <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-4">
        <Activity className="w-8 h-8 text-cyan-400 animate-pulse" />
      </div>
      <h2 className="text-2xl font-bold text-white mb-2">Finalizing Bug Package...</h2>
      <p className="text-slate-400">Stopping recording, generating report, and saving to database.</p>
    </div>
  );
}

function VideoPreview({ engine }: { engine: BugRecorderEngine }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [videoUrl, setVideoUrl] = useState<string>('');

  useEffect(() => {
    const blob = engine.getRecordingBlob();
    if (blob) {
      const url = URL.createObjectURL(blob);
      setVideoUrl(url);
      return () => URL.revokeObjectURL(url);
    }
  }, [engine]);

  if (!videoUrl) return null;
  return (
    <video
      ref={videoRef}
      src={videoUrl}
      controls
      className="w-full rounded-xl border border-slate-700"
      style={{ maxHeight: '400px' }}
    />
  );
}

function ActionIcon({ action }: { action: RecordingStep['action'] }) {
  const icons: Record<string, React.ReactNode> = {
    navigate: <Globe className="w-3.5 h-3.5 text-cyan-400" />,
    click: <Circle className="w-3 h-3 text-slate-400" />,
    input: <FileText className="w-3.5 h-3.5 text-amber-400" />,
    scroll: <Activity className="w-3.5 h-3.5 text-slate-400" />,
    screenshot: <Camera className="w-3.5 h-3.5 text-cyan-400" />,
    'http-request': <Activity className="w-3.5 h-3.5 text-amber-400" />,
    note: <Plus className="w-3.5 h-3.5 text-violet-400" />,
  };
  return <>{icons[action] || <Circle className="w-3 h-3 text-slate-400" />}</>;
}

function FeatureMini({ icon, title, desc, color, bg }: { icon: React.ReactNode; title: string; desc: string; color: string; bg: string }) {
  return (
    <div className="bg-slate-900/40 border border-slate-700/30 rounded-xl p-4">
      <div className={`w-8 h-8 rounded-lg ${bg} flex items-center justify-center ${color} mb-2`}>{icon}</div>
      <h4 className="text-sm font-semibold text-slate-200">{title}</h4>
      <p className="text-xs text-slate-500 mt-0.5">{desc}</p>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold">{label}</div>
      <div className="text-sm text-slate-300 mt-0.5 capitalize truncate">{value}</div>
    </div>
  );
}
