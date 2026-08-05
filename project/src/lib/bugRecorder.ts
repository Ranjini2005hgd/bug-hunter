import JSZip from 'jszip';
import type { RecordingStep, HttpEntry, Severity, BugRecord } from './types';

/**
 * Bug Recorder — captures screen recording, screenshots, HTTP traffic,
 * and user actions during a security testing session, then packages
 * everything into a downloadable ZIP folder.
 */

export class BugRecorderEngine {
  private mediaStream: MediaStream | null = null;
  private mediaRecorder: MediaRecorder | null = null;
  private chunks: Blob[] = [];
  private perfObserver: PerformanceObserver | null = null;
  private startTime: number = 0;
  private steps: RecordingStep[] = [];
  private httpEntries: HttpEntry[] = [];
  private screenshots: string[] = [];
  private recordingBlob: Blob | null = null;

  get isRecording(): boolean {
    return this.mediaRecorder?.state === 'recording';
  }

  get elapsedMs(): number {
    if (this.startTime === 0) return 0;
    return Date.now() - this.startTime;
  }

  get stepCount(): number {
    return this.steps.length;
  }

  get httpCount(): number {
    return this.httpEntries.length;
  }

  get screenshotCount(): number {
    return this.screenshots.length;
  }

  async startRecording(): Promise<void> {
    this.mediaStream = await navigator.mediaDevices.getDisplayMedia({
      video: { frameRate: 30 },
      audio: true,
    });

    const mimeTypes = [
      'video/webm;codecs=vp9,opus',
      'video/webm;codecs=vp8,opus',
      'video/webm',
      'video/mp4',
    ];
    let mimeType = '';
    for (const mt of mimeTypes) {
      if (MediaRecorder.isTypeSupported(mt)) {
        mimeType = mt;
        break;
      }
    }

    this.mediaRecorder = new MediaRecorder(this.mediaStream, {
      mimeType: mimeType || undefined,
      videoBitsPerSecond: 2_500_000,
    });

    this.chunks = [];
    this.mediaRecorder.ondataavailable = (e) => {
      if (e.data.size > 0) this.chunks.push(e.data);
    };

    this.mediaRecorder.onstop = () => {
      const type = this.mediaRecorder?.mimeType || 'video/webm';
      this.recordingBlob = new Blob(this.chunks, { type });
      this.mediaStream?.getTracks().forEach((t) => t.stop());
    };

    this.mediaRecorder.start(1000);
    this.startTime = Date.now();
    this.steps = [];
    this.httpEntries = [];
    this.screenshots = [];

    this.startHttpMonitoring();

    this.mediaStream.getVideoTracks()[0].onended = () => {
      if (this.isRecording) this.stopRecording();
    };
  }

  private startHttpMonitoring(): void {
    if (typeof PerformanceObserver === 'undefined') return;
    try {
      this.perfObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          const res = entry as PerformanceResourceTiming;
          if (res.initiatorType === 'xmlhttprequest' || res.initiatorType === 'fetch' || res.initiatorType === 'navigation') {
            this.httpEntries.push({
              id: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              url: res.name,
              method: 'GET',
              status: 0,
              statusText: '',
              duration: Math.round(res.duration),
              initiatorType: res.initiatorType,
              transferSize: res.transferSize || 0,
              encodedBodySize: res.encodedBodySize || 0,
              decodedBodySize: res.decodedBodySize || 0,
            });
          }
        }
      });
      this.perfObserver.observe({ entryTypes: ['resource', 'navigation'] });
    } catch {
      // PerformanceObserver not available in this context
    }
  }

  async stopRecording(): Promise<void> {
    return new Promise((resolve) => {
      if (this.perfObserver) {
        this.perfObserver.disconnect();
        this.perfObserver = null;
      }

      if (this.mediaRecorder && this.mediaRecorder.state === 'recording') {
        this.mediaRecorder.onstop = () => {
          const type = this.mediaRecorder?.mimeType || 'video/webm';
          this.recordingBlob = new Blob(this.chunks, { type });
          this.mediaStream?.getTracks().forEach((t) => t.stop());
          resolve();
        };
        this.mediaRecorder.stop();
      } else {
        resolve();
      }
    });
  }

  async captureScreenshot(): Promise<string | null> {
    if (!this.mediaStream) return null;
    const videoTrack = this.mediaStream.getVideoTracks()[0];
    if (!videoTrack) return null;

    try {
      const MstpCtor = (window as unknown as { MediaStreamTrackProcessor?: new (opts: { track: MediaStreamTrack }) => { readable: ReadableStream<VideoFrame> } }).MediaStreamTrackProcessor;
      if (!MstpCtor) return null;
      const trackProcessor = new MstpCtor({ track: videoTrack });
      const reader = trackProcessor.readable.getReader();
      const frame = await reader.read();
      reader.releaseLock();

      if (frame.value) {
        const bitmap = await createImageBitmap(frame.value);
        const canvas = document.createElement('canvas');
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;
        ctx.drawImage(bitmap, 0, 0);
        frame.value.close();
        const dataUrl = canvas.toDataURL('image/png');
        this.screenshots.push(dataUrl);
        return dataUrl;
      }
    } catch {
      // Track processor not available — fallback to video frame capture
    }
    return null;
  }

  addStep(action: RecordingStep['action'], description: string, url: string, screenshotDataUrl?: string): RecordingStep {
    const step: RecordingStep = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      relativeTime: Date.now() - this.startTime,
      action,
      url,
      description,
      screenshotDataUrl,
    };
    this.steps.push(step);
    return step;
  }

  addNote(note: string, url: string): void {
    this.addStep('note', note, url);
  }

  getSteps(): RecordingStep[] {
    return [...this.steps];
  }

  getHttpEntries(): HttpEntry[] {
    return [...this.httpEntries];
  }

  getScreenshots(): string[] {
    return [...this.screenshots];
  }

  getRecordingBlob(): Blob | null {
    return this.recordingBlob;
  }

  getRecordingDuration(): number {
    return Math.round(this.elapsedMs / 1000);
  }

  getVideoMimeType(): string {
    return this.mediaRecorder?.mimeType || 'video/webm';
  }

  cancel(): void {
    if (this.perfObserver) {
      this.perfObserver.disconnect();
      this.perfObserver = null;
    }
    if (this.mediaRecorder && this.mediaRecorder.state === 'recording') {
      this.mediaRecorder.onstop = null;
      this.mediaRecorder.stop();
    }
    this.mediaStream?.getTracks().forEach((t) => t.stop());
    this.mediaStream = null;
    this.mediaRecorder = null;
    this.chunks = [];
    this.steps = [];
    this.httpEntries = [];
    this.screenshots = [];
    this.recordingBlob = null;
    this.startTime = 0;
  }
}

export function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function formatRelativeTime(ms: number): string {
  const s = (ms / 1000).toFixed(1);
  return `+${s}s`;
}

export function generateBugReportMarkdown(params: {
  bugId: string;
  title: string;
  severity: Severity;
  targetUrl: string;
  notes: string;
  vulnerabilityClass?: string;
  steps: RecordingStep[];
  httpEntries: HttpEntry[];
  recordingDuration: number;
  screenshotCount: number;
  createdAt: string;
}): string {
  const { bugId, title, severity, targetUrl, notes, vulnerabilityClass, steps, httpEntries, recordingDuration, screenshotCount, createdAt } = params;

  const stepsMd = steps.map((s, i) => {
    const time = formatRelativeTime(s.relativeTime);
    let line = `### Step ${i + 1} — ${s.action.toUpperCase()} (${time})\n\n`;
    line += `**Timestamp:** ${s.timestamp}\n\n`;
    line += `**URL:** ${s.url}\n\n`;
    line += `**Action:** ${s.description}\n\n`;
    if (s.screenshotDataUrl) {
      line += `**Screenshot:** screenshot-${String(i + 1).padStart(2, '0')}.png\n\n`;
    }
    if (s.httpEntryId) {
      const http = httpEntries.find((h) => h.id === s.httpEntryId);
      if (http) {
        line += `**HTTP:** ${http.method} ${http.url} → ${http.status} ${http.statusText} (${http.duration}ms)\n\n`;
      }
    }
    return line;
  }).join('---\n\n');

  const httpMd = httpEntries.length > 0
    ? httpEntries.map((h, i) => {
        let line = `### Entry ${i + 1}\n\n`;
        line += `- **URL:** ${h.url}\n`;
        line += `- **Method:** ${h.method}\n`;
        line += `- **Status:** ${h.status} ${h.statusText}\n`;
        line += `- **Duration:** ${h.duration}ms\n`;
        line += `- **Type:** ${h.initiatorType}\n`;
        line += `- **Transfer Size:** ${h.transferSize} bytes\n`;
        line += `- **Timestamp:** ${h.timestamp}\n`;
        return line;
      }).join('\n\n')
    : 'No HTTP entries were captured during this recording.';

  return `# Bug Report — ${title}

## Report Metadata

| Field | Value |
|-------|-------|
| **Bug ID** | ${bugId} |
| **Title** | ${title} |
| **Severity** | ${severity.toUpperCase()} |
| **Status** | Open |
| **Target URL** | ${targetUrl} |
| **Vulnerability Class** | ${vulnerabilityClass || 'N/A'} |
| **Date Discovered** | ${createdAt} |
| **Recording Duration** | ${formatDuration(recordingDuration)} |
| **Steps Recorded** | ${steps.length} |
| **HTTP Entries** | ${httpEntries.length} |
| **Screenshots** | ${screenshotCount} |

## Summary

${notes || 'No additional notes provided by the researcher.'}

## Steps to Reproduce

${stepsMd || 'No steps were recorded.'}

## HTTP Traffic Log

${httpMd}

## Evidence

- **Video Recording:** recording.webm (full screen capture, ${formatDuration(recordingDuration)})
- **Screenshots:** ${screenshotCount} screenshot(s) captured during reproduction
- **HTTP Log:** ${httpEntries.length} HTTP request(s) captured via PerformanceObserver

## Impact

${severity === 'critical' ? 'This vulnerability poses a critical security risk and should be remediated immediately.' : severity === 'high' ? 'This vulnerability poses a significant security risk and should be remediated within one week.' : severity === 'medium' ? 'This vulnerability poses a moderate security risk and should be addressed in the current development cycle.' : 'This vulnerability poses a low security risk but should be addressed when feasible.'}

## Disclosure

This report was generated as part of an authorized security assessment. All evidence was collected during authorized testing within the defined scope. This report is confidential and intended only for the authorized recipient.

---
*Report ID: ${bugId} | Generated: ${createdAt} | CONFIDENTIAL — AUTHORIZED RECIPIENT ONLY*
`;
}

export async function downloadBugPackage(params: {
  bugId: string;
  title: string;
  reportMarkdown: string;
  recordingBlob: Blob | null;
  screenshots: string[];
  steps: RecordingStep[];
  videoMimeType: string;
}): Promise<void> {
  const { bugId, title, reportMarkdown, recordingBlob, screenshots, steps, videoMimeType } = params;
  const zip = new JSZip();

  const folder = zip.folder(bugId);
  if (!folder) throw new Error('Failed to create ZIP folder');

  // 1. Video recording
  if (recordingBlob) {
    const ext = videoMimeType.includes('mp4') ? 'mp4' : 'webm';
    folder.file(`recording.${ext}`, recordingBlob);
  }

  // 2. Screenshots
  const screenshotsFolder = folder.folder('screenshots');
  if (screenshotsFolder) {
    screenshots.forEach((dataUrl, i) => {
      const base64 = dataUrl.split(',')[1];
      if (base64) {
        screenshotsFolder.file(`screenshot-${String(i + 1).padStart(2, '0')}.png`, base64, { base64: true });
      }
    });
    // Also save step screenshots
    steps.forEach((step, i) => {
      if (step.screenshotDataUrl) {
        const base64 = step.screenshotDataUrl.split(',')[1];
        if (base64) {
          screenshotsFolder.file(`step-${String(i + 1).padStart(2, '0')}.png`, base64, { base64: true });
        }
      }
    });
  }

  // 3. Reproduction document (Markdown)
  folder.file('report.md', reportMarkdown);

  // 4. Steps as JSON for programmatic use
  const stepsJson = JSON.stringify(steps.map((s, i) => ({
    step: i + 1,
    timestamp: s.timestamp,
    relativeTime: formatRelativeTime(s.relativeTime),
    action: s.action,
    url: s.url,
    description: s.description,
    hasScreenshot: !!s.screenshotDataUrl,
  })), null, 2);
  folder.file('steps.json', stepsJson);

  // 5. HTTP log
  folder.file('README.txt', `${bugId} — ${title}\n\nThis package contains:\n  1. recording.${recordingBlob ? (videoMimeType.includes('mp4') ? 'mp4' : 'webm') : 'N/A'} — Full screen recording of the reproduction\n  2. screenshots/ — Screenshots captured during the recording\n  3. report.md — Step-by-step reproduction report in Markdown\n  4. steps.json — Machine-readable step data with timestamps\n\nGenerated: ${new Date().toISOString()}\n`);

  const content = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(content);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${bugId}.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function downloadReportPdf(bugId: string, markdown: string): Promise<void> {
  const html = markdownToHtml(bugId, markdown);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${bugId}-report.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function markdownToHtml(bugId: string, md: string): string {
  const lines = md.split('\n');
  let html = '';
  let inTable = false;
  let inList = false;

  for (const line of lines) {
    if (line.startsWith('# ')) {
      if (inTable) { html += '</table>\n'; inTable = false; }
      if (inList) { html += '</ul>\n'; inList = false; }
      html += `<h1>${esc(line.slice(2))}</h1>\n`;
    } else if (line.startsWith('## ')) {
      if (inTable) { html += '</table>\n'; inTable = false; }
      if (inList) { html += '</ul>\n'; inList = false; }
      html += `<h2>${esc(line.slice(3))}</h2>\n`;
    } else if (line.startsWith('### ')) {
      if (inTable) { html += '</table>\n'; inTable = false; }
      if (inList) { html += '</ul>\n'; inList = false; }
      html += `<h3>${esc(line.slice(4))}</h3>\n`;
    } else if (line.startsWith('---')) {
      if (inTable) { html += '</table>\n'; inTable = false; }
      if (inList) { html += '</ul>\n'; inList = false; }
      html += '<hr>\n';
    } else if (line.startsWith('|')) {
      if (inList) { html += '</ul>\n'; inList = false; }
      if (!inTable) {
        html += '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">\n';
        inTable = true;
      }
      const cells = line.split('|').filter((c) => c.trim()).map((c) => c.trim());
      if (cells.every((c) => /^[-:]+$/.test(c))) continue;
      const tag = 'td';
      html += `<tr>${cells.map((c) => `<${tag}>${esc(c)}</${tag}>`).join('')}</tr>\n`;
    } else if (line.startsWith('- ')) {
      if (inTable) { html += '</table>\n'; inTable = false; }
      if (!inList) { html += '<ul>\n'; inList = true; }
      html += `<li>${esc(line.slice(2))}</li>\n`;
    } else if (line.trim() === '') {
      if (inList) { html += '</ul>\n'; inList = false; }
      if (inTable) { html += '</table>\n'; inTable = false; }
      html += '<br>\n';
    } else {
      if (inList) { html += '</ul>\n'; inList = false; }
      if (inTable) { html += '</table>\n'; inTable = false; }
      html += `<p>${esc(line)}</p>\n`;
    }
  }
  if (inTable) html += '</table>\n';
  if (inList) html += '</ul>\n';

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>${esc(bugId)}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; color: #1e293b; }
  h1 { color: #0f172a; border-bottom: 2px solid #0891b2; padding-bottom: 8px; }
  h2 { color: #0f172a; margin-top: 28px; }
  h3 { color: #334155; }
  table { margin: 12px 0; }
  th { background: #f1f5f9; }
  code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; font-size: 0.9em; }
  hr { border: none; border-top: 1px solid #cbd5e1; margin: 20px 0; }
  @media print { body { margin: 0; } }
</style>
</head>
<body>
${html}
</body>
</html>`;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export { generateBugId } from './bugDb';
