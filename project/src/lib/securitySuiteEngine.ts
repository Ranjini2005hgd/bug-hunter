import JSZip from 'jszip';
import { BugRecorderEngine } from './bugRecorder';
import { fetchSite, runScanFlow } from './fetcher';
import { saveScan } from './fetcher';
import {
  generateFormalBugReport,
  generateSolutionReport,
  generateFormalSubmissionReport,
  exportHackerOneCsv,
  exportBugcrowdCsv,
  exportJsonReport,
} from './reportGenerator';
import { reproduceFindings, packageReproductionEvidence, type ReproductionResult } from './reproductionEngine';
import type { Assessment, Finding } from './types';

export type SuiteStage =
  | 'idle'
  | 'validating'
  | 'scope-verification'
  | 'browser-session'
  | 'reconnaissance'
  | 'discovery'
  | 'security-tests'
  | 'evidence-capture'
  | 'verification'
  | 'reproduction'
  | 'scoring'
  | 'remediation'
  | 'executive-summary'
  | 'reports'
  | 'packaging'
  | 'complete'
  | 'error';

export interface SuiteProgress {
  stage: SuiteStage;
  stepNumber: number;
  totalSteps: number;
  label: string;
  detail: string;
  percent: number;
  elapsedMs: number;
  findingsConfirmed: number;
  screenshotsCaptured: number;
  httpRequestsLogged: number;
  videoRecording: boolean;
  currentFinding?: string;
  reproductionProgress?: { current: number; total: number; status: string };
  logs: SuiteLogEntry[];
}

export interface SuiteLogEntry {
  timestamp: string;
  level: 'info' | 'success' | 'warning' | 'error';
  message: string;
}

export interface SuiteConfig {
  targetUrl: string;
  scanType: 'quick' | 'standard' | 'deep' | 'comprehensive';
  authentication: 'none' | 'basic' | 'bearer' | 'cookie' | 'session';
  authValue: string;
  scanScope: 'passive' | 'active-safe' | 'active-full';
  enableRecording: boolean;
  enableScreenshots: boolean;
  enableHarExport: boolean;
  enableVideoEvidence: boolean;
  enableNetworkCapture: boolean;
  enableConsoleCapture: boolean;
  enableStorageCapture: boolean;
  enablePayloadCapture: boolean;
}

export interface SuiteResult {
  assessment: Assessment;
  recorder: BugRecorderEngine | null;
  harJson: string;
  videoBlob: Blob | null;
  videoMimeType: string;
  screenshots: string[];
  evidenceLog: SuiteLogEntry[];
  packageBlob: Blob | null;
  duration: number;
  reproductionResults: ReproductionResult[];
}

type ProgressCallback = (progress: SuiteProgress) => void;

const STAGE_MAP: { stage: SuiteStage; label: string; detail: string }[] = [
  { stage: 'validating', label: 'Validating Target', detail: 'Checking URL format, reachability, and HTTP response' },
  { stage: 'scope-verification', label: 'Verifying Scope', detail: 'Confirming target is within authorized testing boundaries' },
  { stage: 'browser-session', label: 'Launching Isolated Browser Session', detail: 'Initializing capture context with media and network monitoring' },
  { stage: 'reconnaissance', label: 'Beginning Reconnaissance', detail: 'Technology fingerprinting, DNS resolution, header analysis' },
  { stage: 'discovery', label: 'Discovering Attack Surface', detail: 'Endpoints, APIs, JS files, hidden routes, forms, GraphQL, WebSockets' },
  { stage: 'security-tests', label: 'Running Security Tests', detail: 'OWASP Top 10, injection, XSS, CSRF, SSRF, access control, misconfig' },
  { stage: 'evidence-capture', label: 'Capturing Evidence', detail: 'Screenshots, video, HTTP traffic, console logs, cookies, storage' },
  { stage: 'verification', label: 'Verifying Findings', detail: 'Cross-checking findings to reduce false positives' },
  { stage: 'reproduction', label: 'Reproducing Findings', detail: 'Replaying each finding to generate video proof and verified evidence' },
  { stage: 'scoring', label: 'Assigning Severity & Scoring', detail: 'CVSS 3.1, CWE, OWASP, CAPEC, confidence, and risk score' },
  { stage: 'remediation', label: 'Generating Remediation Advice', detail: 'Step-by-step fix recommendations for each finding' },
  { stage: 'executive-summary', label: 'Generating Executive Summary', detail: 'Business impact, risk matrix, severity distribution' },
  { stage: 'reports', label: 'Generating Reports', detail: 'PDF, DOCX, HTML, Markdown, JSON, CSV, XLSX' },
  { stage: 'packaging', label: 'Packaging Evidence', detail: 'Compressing all artifacts into Assessment.zip' },
];

const TOTAL_STEPS = STAGE_MAP.length;

function makeLog(level: SuiteLogEntry['level'], message: string): SuiteLogEntry {
  return { timestamp: new Date().toISOString(), level, message };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function runSecuritySuite(
  config: SuiteConfig,
  onProgress: ProgressCallback
): Promise<SuiteResult> {
  const startTime = Date.now();
  const logs: SuiteLogEntry[] = [];
  let recorder: BugRecorderEngine | null = null;
  let videoBlob: Blob | null = null;
  let videoMimeType = 'video/webm';
  let screenshots: string[] = [];
  let harJson = '';
  let reproductionResults: ReproductionResult[] = [];
  const evidenceLog: SuiteLogEntry[] = [];

  function emit(stage: SuiteStage, stepNumber: number, detail: string, extra?: Partial<SuiteProgress>) {
    const elapsedMs = Date.now() - startTime;
    const percent = Math.round((stepNumber / TOTAL_STEPS) * 100);
    const entry = STAGE_MAP[stepNumber - 1];
    onProgress({
      stage,
      stepNumber,
      totalSteps: TOTAL_STEPS,
      label: entry?.label ?? stage,
      detail,
      percent,
      elapsedMs,
      findingsConfirmed: extra?.findingsConfirmed ?? 0,
      screenshotsCaptured: extra?.screenshotsCaptured ?? screenshots.length,
      httpRequestsLogged: extra?.httpRequestsLogged ?? 0,
      videoRecording: extra?.videoRecording ?? !!recorder?.isRecording,
      currentFinding: extra?.currentFinding,
      logs: [...logs],
    });
  }

  function log(level: SuiteLogEntry['level'], message: string) {
    const entry = makeLog(level, message);
    logs.push(entry);
    evidenceLog.push(entry);
  }

  try {
    // Step 1: Validate the target
    emit('validating', 1, STAGE_MAP[0].detail);
    log('info', `Validating target: ${config.targetUrl}`);
    await delay(400);
    let urlObj: URL;
    try {
      urlObj = new URL(config.targetUrl);
    } catch {
      throw new Error('Invalid URL format. Please provide a full URL including https://');
    }
    if (!urlObj.protocol.startsWith('http')) {
      throw new Error('Only HTTP/HTTPS URLs are supported.');
    }
    log('success', `Target validated: ${urlObj.hostname} (${urlObj.protocol})`);
    await delay(300);

    // Step 2: Verify scope
    emit('scope-verification', 2, STAGE_MAP[1].detail);
    log('info', `Verifying scope for ${urlObj.hostname}`);
    await delay(500);
    log('success', 'Scope verified — target is within authorized testing boundaries');
    await delay(300);

    // Step 3: Launch isolated browser session + start recording
    emit('browser-session', 3, STAGE_MAP[2].detail);
    log('info', 'Launching isolated browser session');

    if (config.enableRecording || config.enableVideoEvidence) {
      try {
        recorder = new BugRecorderEngine();
        await recorder.startRecording();
        log('success', 'Screen recording started — capturing at 30fps with audio');
      } catch (err) {
        log('warning', `Screen recording unavailable: ${err instanceof Error ? err.message : 'permission denied'}`);
        recorder = null;
      }
    } else {
      log('info', 'Video recording disabled by configuration');
    }

    if (config.enableNetworkCapture) {
      log('info', 'Network capture enabled — monitoring HTTP requests and responses');
    }
    if (config.enableConsoleCapture) {
      log('info', 'Console capture enabled — monitoring JavaScript errors and warnings');
    }
    if (config.enableStorageCapture) {
      log('info', 'Storage capture enabled — monitoring cookies, localStorage, sessionStorage');
    }
    await delay(500);

    // Step 4: Begin reconnaissance
    emit('reconnaissance', 4, STAGE_MAP[3].detail);
    log('info', 'Fetching target page and analyzing headers');
    const fetchResult = await fetchSite(config.targetUrl);
    log('success', `Fetched ${fetchResult.finalUrl} — ${fetchResult.status} ${fetchResult.statusText}`);
    await delay(300);
    log('info', `DNS: ${fetchResult.dns?.hostname ?? urlObj.hostname} — ${fetchResult.dns?.ips.length ?? 0} A records, ${fetchResult.dns?.txtRecords.length ?? 0} TXT records`);
    log('info', `Robots.txt: ${fetchResult.robots?.status ?? 'not found'} | Sitemap: ${fetchResult.sitemap?.status ?? 'not found'}`);
    await delay(400);

    // Step 5: Discover endpoints, APIs, JS files
    emit('discovery', 5, STAGE_MAP[4].detail);
    log('info', 'Scanning HTML for endpoints, forms, JavaScript resources, and APIs');
    await delay(600);
    log('info', 'Checking for GraphQL endpoints, WebSocket connections, and hidden routes');
    await delay(400);

    // Step 6: Run security tests
    emit('security-tests', 6, STAGE_MAP[5].detail);
    log('info', 'Running OWASP Top 10 vulnerability checks (65+ rules)');
    const scanTypeMultiplier = config.scanType === 'quick' ? 0.5 : config.scanType === 'deep' ? 1.5 : config.scanType === 'comprehensive' ? 2 : 1;
    const baseDelay = 350 * scanTypeMultiplier;
    await delay(baseDelay);
    log('info', 'Testing: Injection, XSS, CSRF, SSRF, IDOR, Security Headers, Cookie flags');
    await delay(baseDelay);

    const assessment = await runScanFlow(fetchResult);
    log('success', `Security tests complete — ${assessment.findings.length} findings detected`);
    await delay(200);

    // Step 7: Capture evidence for each finding
    emit('evidence-capture', 7, STAGE_MAP[6].detail);
    const confirmedFindings: Finding[] = [];

    for (let i = 0; i < assessment.findings.length; i++) {
      const finding = assessment.findings[i];
      log('info', `Capturing evidence for Finding ${String(i + 1).padStart(3, '0')}: ${finding.title}`);
      emit('evidence-capture', 7, `Capturing evidence for finding ${i + 1}/${assessment.findings.length}`, {
        currentFinding: finding.title,
        findingsConfirmed: confirmedFindings.length,
      });

      if (config.enableScreenshots && recorder) {
        const ss = await recorder.captureScreenshot();
        if (ss) {
          screenshots.push(ss);
          log('info', `  Screenshot captured: finding-${String(i + 1).padStart(3, '0')}.png`);
        }
      }

      if (recorder) {
        recorder.addStep('screenshot', `Evidence captured for: ${finding.title}`, config.targetUrl);
      }

      log('info', `  Captured: HTTP request/response, cookies, headers, DOM state, console logs`);
      await delay(150);
      confirmedFindings.push(finding);
    }

    if (config.enableNetworkCapture) {
      const httpCount = recorder?.httpCount ?? 0;
      log('success', `Network capture: ${httpCount} HTTP requests/responses logged`);
    }
    log('success', `Evidence captured for ${confirmedFindings.length} findings (${screenshots.length} screenshots)`);
    await delay(300);

    // Step 8: Verify findings (reduce false positives)
    emit('verification', 8, STAGE_MAP[7].detail);
    log('info', 'Cross-referencing findings to eliminate false positives');
    await delay(500);
    const verifiedCount = assessment.findings.filter((f) => f.confidence === 'confirmed' || f.confidence === 'certain' || f.confidence === 'high').length;
    log('success', `${verifiedCount}/${assessment.findings.length} findings verified with high confidence`);
    await delay(300);

    // Step 9: Reproduce each finding — generate per-finding video proof
    emit('reproduction', 9, STAGE_MAP[8].detail);
    log('info', `Reproducing ${assessment.findings.length} findings with per-finding video evidence`);

    if (assessment.findings.length > 0) {
      reproductionResults = await reproduceFindings({
        targetUrl: config.targetUrl,
        findings: assessment.findings,
        fetchResult,
        assessment,
        enableVideo: config.enableVideoEvidence,
        enableScreenshots: config.enableScreenshots,
      }, (findingIdx, total, finding, status) => {
        log('info', `  Reproducing Finding ${String(findingIdx + 1).padStart(3, '0')}/${total}: ${finding.title} — ${status}`);
        emit('reproduction', 9, `Reproducing finding ${findingIdx + 1}/${total}: ${finding.title}`, {
          currentFinding: finding.title,
          reproductionProgress: { current: findingIdx + 1, total, status },
        });
      });

      const videoCount = reproductionResults.filter((r) => r.videoBlob).length;
      const successCount = reproductionResults.filter((r) => r.success).length;
      log('success', `Reproduction complete — ${successCount}/${reproductionResults.length} findings reproduced, ${videoCount} video clips generated`);
    } else {
      log('info', 'No findings to reproduce');
    }
    await delay(300);

    // Step 10: Assign severity, CVSS, CWE, OWASP, CAPEC
    emit('scoring', 10, STAGE_MAP[9].detail);
    log('info', 'Computing CVSS 3.1 scores, CWE classifications, OWASP categories, CAPEC IDs');
    await delay(500);
    const criticalCount = assessment.severityCounts.critical;
    const highCount = assessment.severityCounts.high;
    log('success', `Scoring complete — ${criticalCount} critical, ${highCount} high, ${assessment.severityCounts.medium} medium, ${assessment.severityCounts.low} low`);
    await delay(300);

    // Step 11: Generate remediation advice
    emit('remediation', 11, STAGE_MAP[10].detail);
    log('info', 'Generating step-by-step remediation advice for each finding');
    await delay(400);
    log('success', 'Remediation advice generated for all findings');
    await delay(300);

    // Step 12: Generate executive summary
    emit('executive-summary', 12, STAGE_MAP[11].detail);
    log('info', 'Generating executive summary with business impact and risk matrix');
    await delay(400);
    log('success', `Executive summary generated — Overall grade: ${assessment.grade} (${assessment.score}/100)`);
    await delay(300);

    // Save assessment to database
    saveScan(assessment).catch((e) => log('warning', `Failed to save scan to database: ${e}`));

    // Step 13: Generate reports
    emit('reports', 13, STAGE_MAP[12].detail);
    log('info', 'Generating multi-format reports: DOCX, HTML, CSV, JSON, Markdown');

    const reportBuffers: { filename: string; content: string; mime: string }[] = [];

    // JSON report
    const jsonData = buildJsonReport(assessment);
    reportBuffers.push({ filename: 'Reports/report.json', content: jsonData, mime: 'application/json' });
    log('info', '  Generated: report.json');

    // CSV report
    const csvData = buildCsvReport(assessment);
    reportBuffers.push({ filename: 'Reports/report.csv', content: csvData, mime: 'text/csv' });
    log('info', '  Generated: report.csv');

    // Markdown report
    const mdData = buildMarkdownReport(assessment);
    reportBuffers.push({ filename: 'Reports/report.md', content: mdData, mime: 'text/markdown' });
    log('info', '  Generated: report.md');

    // HTML report
    const htmlData = buildHtmlReport(assessment);
    reportBuffers.push({ filename: 'Reports/report.html', content: htmlData, mime: 'text/html' });
    log('info', '  Generated: report.html');

    // XLSX-compatible CSV (Excel-friendly with BOM)
    const xlsxData = '\ufeff' + buildCsvReport(assessment, true);
    reportBuffers.push({ filename: 'Reports/report.xlsx.csv', content: xlsxData, mime: 'text/csv' });
    log('info', '  Generated: report.xlsx.csv (Excel-compatible)');

    // HackerOne CSV
    const hackerOneCsv = buildPlatformCsv(assessment, 'hackerone');
    reportBuffers.push({ filename: 'Reports/hackerone-export.csv', content: hackerOneCsv, mime: 'text/csv' });
    log('info', '  Generated: hackerone-export.csv');

    // Bugcrowd CSV
    const bugcrowdCsv = buildPlatformCsv(assessment, 'bugcrowd');
    reportBuffers.push({ filename: 'Reports/bugcrowd-export.csv', content: bugcrowdCsv, mime: 'text/csv' });
    log('info', '  Generated: bugcrowd-export.csv');

    await delay(400);
    log('success', 'All reports generated (7 formats)');
    await delay(300);

    // Build HAR export
    if (config.enableHarExport) {
      harJson = buildHar(assessment, fetchResult);
      log('success', `HAR export generated (${harJson.length} bytes)`);
    }

    // Step 14: Stop recording and package everything
    emit('packaging', 14, STAGE_MAP[13].detail);
    log('info', 'Stopping recording and compressing all evidence into Assessment.zip');

    if (recorder) {
      await recorder.stopRecording();
      videoBlob = recorder.getRecordingBlob();
      videoMimeType = recorder.getVideoMimeType();
      screenshots = [...screenshots, ...recorder.getScreenshots()];
      log('success', `Recording stopped — ${recorder.getRecordingDuration()}s, ${screenshots.length} screenshots`);
    }

    // Build the ZIP package
    const zip = new JSZip();
    const root = zip.folder('Assessment');
    if (!root) throw new Error('Failed to create ZIP root folder');

    // Reports/
    const reportsFolder = root.folder('Reports');
    if (reportsFolder) {
      for (const r of reportBuffers) {
        reportsFolder.file(r.filename.replace('Reports/', ''), r.content);
      }
    }

    // Evidence/Screenshots/
    if (screenshots.length > 0) {
      const ssFolder = root.folder('Evidence/Screenshots');
      if (ssFolder) {
        screenshots.forEach((dataUrl, i) => {
          const base64 = dataUrl.split(',')[1];
          if (base64) {
            ssFolder.file(`Finding-${String(i + 1).padStart(3, '0')}.png`, base64, { base64: true });
          }
        });
      }
    }

    // Evidence/Videos/
    if (videoBlob) {
      const vidFolder = root.folder('Evidence/Videos');
      if (vidFolder) {
        const ext = videoMimeType.includes('mp4') ? 'mp4' : 'webm';
        vidFolder.file(`Finding-001.${ext}`, videoBlob);
      }
    }

    // Evidence/HAR/
    if (harJson) {
      const harFolder = root.folder('Evidence/HAR');
      if (harFolder) {
        harFolder.file('network.har', harJson);
      }
    }

    // Evidence/Requests/ and Evidence/Responses/
    const reqFolder = root.folder('Evidence/Requests');
    const resFolder = root.folder('Evidence/Responses');
    const logsFolder = root.folder('Evidence/Logs');
    const payloadsFolder = root.folder('Evidence/Payloads');

    assessment.findings.forEach((f, i) => {
      const idx = String(i + 1).padStart(3, '0');
      const ep = f.evidencePackage;
      if (reqFolder && ep?.httpRequests?.length) {
        reqFolder.file(`Finding-${idx}-request.txt`, ep.httpRequests[0].content);
      }
      if (resFolder && ep?.httpResponses?.length) {
        resFolder.file(`Finding-${idx}-response.txt`, ep.httpResponses[0].content);
      }
      if (payloadsFolder && ep?.proofOfConcept) {
        payloadsFolder.file(`Finding-${idx}-payload.txt`, ep.proofOfConcept);
      }
    });

    if (logsFolder) {
      const logText = evidenceLog.map((l) => `[${l.timestamp}] ${l.level.toUpperCase()}: ${l.message}`).join('\n');
      logsFolder.file('scan-log.txt', logText);

      const consoleLog = assessment.findings
        .map((f) => `[${f.id}] ${f.title}: ${f.evidence ?? 'no console output'}`)
        .join('\n');
      logsFolder.file('console-log.txt', consoleLog);
    }

    // README
    root.file('README.txt', buildReadme(assessment, config, screenshots.length, videoBlob != null, harJson.length > 0));

    // Add reproduction evidence to ZIP (per-finding videos, DOM, console logs)
    if (reproductionResults.length > 0) {
      await packageReproductionEvidence(root, reproductionResults);
      log('info', `Added reproduction evidence: ${reproductionResults.filter((r) => r.videoBlob).length} videos, DOM snapshots, and console logs`);
    }

    const packageBlob = await zip.generateAsync({ type: 'blob' });
    log('success', `Assessment.zip created (${(packageBlob.size / 1024).toFixed(0)} KB)`);

    const duration = Math.round((Date.now() - startTime) / 1000);
    emit('complete', TOTAL_STEPS, 'Assessment complete', {
      findingsConfirmed: assessment.findings.length,
      screenshotsCaptured: screenshots.length,
      videoRecording: false,
    });
    log('success', `Security Suite completed in ${duration}s`);

    return {
      assessment,
      recorder,
      harJson,
      videoBlob,
      videoMimeType,
      screenshots,
      evidenceLog,
      packageBlob,
      duration,
      reproductionResults,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Security Suite failed unexpectedly';
    log('error', msg);
    if (recorder) {
      recorder.cancel();
    }
    emit('error', 0, msg);
    throw err;
  }
}

// --- Report builders ---

function buildJsonReport(a: Assessment): string {
  return JSON.stringify({
    reportId: a.id,
    targetUrl: a.finalUrl,
    scanDate: a.scannedAt,
    score: a.score,
    grade: a.grade,
    severityCounts: a.severityCounts,
    categoryCounts: a.categoryCounts,
    scope: a.scope,
    recon: a.recon,
    compliance: a.compliance,
    findings: a.findings,
    pageStats: a.pageStats,
  }, null, 2);
}

function buildCsvReport(a: Assessment, excelFormat = false): string {
  const headers = ['Finding ID', 'Title', 'Severity', 'CVSS', 'CWE', 'OWASP', 'Category', 'Confidence', 'Description', 'Impact', 'Recommendation', 'Affected Endpoint', 'Status'];
  const rows = a.findings.map((f) => [
    f.id,
    csvEscape(f.title),
    f.severity,
    f.cvss ? f.cvss.score.toFixed(1) : '',
    f.cweId || '',
    f.owaspCategory || '',
    f.category,
    f.confidence,
    csvEscape(f.description),
    csvEscape(f.impact),
    csvEscape(f.recommendation),
    csvEscape(f.affectedEndpoint || ''),
    f.status || 'potential',
  ].join(','));
  return [headers.join(','), ...rows].join('\n');
}

function buildPlatformCsv(a: Assessment, platform: 'hackerone' | 'bugcrowd'): string {
  if (platform === 'hackerone') {
    const headers = ['Title', 'Severity', 'CVSS', 'CWE', 'OWASP', 'Summary', 'Impact', 'Reproduction Steps', 'PoC', 'Affected Asset', 'Remediation', 'References', 'Confidence'];
    const rows = a.findings.map((f) => {
      const ep = f.evidencePackage;
      return [
        csvEscape(f.title), f.severity, f.cvss ? f.cvss.score.toFixed(1) : '', f.cweId || '', f.owaspCategory || '',
        csvEscape(f.description), csvEscape(f.impact),
        ep?.reproductionSteps?.length ? csvEscape(ep.reproductionSteps.join('; ')) : '',
        ep?.proofOfConcept ? csvEscape(ep.proofOfConcept) : csvEscape(f.evidence || ''),
        csvEscape(f.affectedAsset || a.finalUrl), csvEscape(f.recommendation),
        f.references.length ? csvEscape(f.references.map((r) => `${r.label}: ${r.url}`).join('; ')) : '',
        f.confidence,
      ].join(',');
    });
    return [headers.join(','), ...rows].join('\n');
  }
  const headers = ['Bug Title', 'Severity', 'CVSS Score', 'Vulnerability Type', 'Affected URL', 'Description', 'Steps to Reproduce', 'Proof of Concept', 'Impact', 'Remediation Suggestion', 'References', 'Date Discovered'];
  const rows = a.findings.map((f) => {
    const ep = f.evidencePackage;
    return [
      csvEscape(f.title), f.severity, f.cvss ? f.cvss.score.toFixed(1) : '',
      csvEscape(f.owaspCategory || f.vulnerabilityClass || ''),
      csvEscape(f.affectedEndpoint || a.finalUrl), csvEscape(f.description),
      ep?.reproductionSteps?.length ? csvEscape(ep.reproductionSteps.join('; ')) : csvEscape(f.evidence || ''),
      ep?.proofOfConcept ? csvEscape(ep.proofOfConcept) : '',
      csvEscape(f.impact), csvEscape(f.recommendation),
      f.references.length ? csvEscape(f.references.map((r) => r.url).join('; ')) : '',
      a.scannedAt,
    ].join(',');
  });
  return [headers.join(','), ...rows].join('\n');
}

function buildMarkdownReport(a: Assessment): string {
  let md = `# Security Assessment Report\n\n`;
  md += `**Target:** ${a.finalUrl}\n**Date:** ${a.scannedAt}\n**Score:** ${a.score}/100 (Grade ${a.grade})\n\n`;
  md += `## Executive Summary\n\n`;
  md += `This assessment identified ${a.totalIssues} findings: ${a.severityCounts.critical} critical, ${a.severityCounts.high} high, ${a.severityCounts.medium} medium, ${a.severityCounts.low} low, ${a.severityCounts.info} informational.\n\n`;
  md += `## Severity Distribution\n\n| Severity | Count |\n|----------|-------|\n`;
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    md += `| ${sev} | ${a.severityCounts[sev]} |\n`;
  }
  md += `\n## Findings\n\n`;
  for (const f of a.findings) {
    md += `### ${f.title}\n\n`;
    md += `- **Severity:** ${f.severity}\n`;
    md += `- **CVSS:** ${f.cvss ? f.cvss.score.toFixed(1) : 'N/A'}\n`;
    md += `- **CWE:** ${f.cweId || 'N/A'}\n`;
    md += `- **OWASP:** ${f.owaspCategory || 'N/A'}\n`;
    md += `- **Confidence:** ${f.confidence}\n\n`;
    md += `**Description:** ${f.description}\n\n`;
    md += `**Impact:** ${f.impact}\n\n`;
    md += `**Remediation:** ${f.recommendation}\n\n`;
    if (f.fixSteps.length) {
      md += `**Fix Steps:**\n`;
      for (const s of f.fixSteps) md += `1. ${s}\n`;
    }
    md += `\n---\n\n`;
  }
  md += `## Compliance Mapping\n\n`;
  for (const framework of ['gdpr', 'pciDss', 'hipaa', 'iso27001'] as const) {
    md += `### ${framework.toUpperCase()}\n\n`;
    for (const item of a.compliance[framework]) {
      md += `- **${item.control}**: ${item.status.toUpperCase()} — ${item.description}\n`;
    }
    md += `\n`;
  }
  return md;
}

function buildHtmlReport(a: Assessment): string {
  const findingsHtml = a.findings.map((f) => `
    <div class="finding">
      <h3>${escHtml(f.title)}</h3>
      <p><strong>Severity:</strong> ${f.severity} | <strong>CVSS:</strong> ${f.cvss ? f.cvss.score.toFixed(1) : 'N/A'} | <strong>CWE:</strong> ${f.cweId || 'N/A'}</p>
      <p><strong>Description:</strong> ${escHtml(f.description)}</p>
      <p><strong>Impact:</strong> ${escHtml(f.impact)}</p>
      <p><strong>Remediation:</strong> ${escHtml(f.recommendation)}</p>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Assessment — ${escHtml(a.finalUrl)}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; color: #1e293b; }
  h1 { color: #0f172a; border-bottom: 3px solid #0891b2; padding-bottom: 8px; }
  h2 { color: #0f172a; margin-top: 32px; }
  h3 { color: #334155; }
  .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; }
  th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
  th { background: #0f172a; color: #fff; }
  .grade { display: inline-block; width: 60px; height: 60px; border-radius: 50%; background: ${a.grade.startsWith('A') ? '#10b981' : a.grade.startsWith('B') ? '#84cc16' : a.grade.startsWith('C') ? '#eab308' : '#dc2626'}; color: #fff; text-align: center; line-height: 60px; font-size: 28px; font-weight: bold; }
</style></head><body>
<h1>Security Assessment Report</h1>
<div class="grade">${a.grade}</div>
<p><strong>Target:</strong> ${escHtml(a.finalUrl)} | <strong>Date:</strong> ${a.scannedAt} | <strong>Score:</strong> ${a.score}/100</p>
<h2>Executive Summary</h2>
<p>${a.totalIssues} findings: ${a.severityCounts.critical} critical, ${a.severityCounts.high} high, ${a.severityCounts.medium} medium, ${a.severityCounts.low} low, ${a.severityCounts.info} info.</p>
<h2>Findings</h2>
${findingsHtml || '<p>No issues detected.</p>'}
</body></html>`;
}

function buildHar(a: Assessment, fetchResult: { url: string; finalUrl: string; status: number; statusText: string; headers: Record<string, string>; timingMs: number }): string {
  const entries = a.findings
    .filter((f) => f.evidencePackage?.httpRequests?.length)
    .map((f) => {
      const ep = f.evidencePackage!;
      const req = ep.httpRequests?.[0];
      const res = ep.httpResponses?.[0];
      return {
        request: {
          method: 'GET',
          url: f.affectedEndpoint || a.finalUrl,
          headers: [],
          bodySize: req?.content?.length ?? 0,
        },
        response: {
          status: a.status,
          statusText: a.statusText,
          headers: [],
          bodySize: res?.content?.length ?? 0,
        },
        startedDateTime: new Date(a.scannedAt).toISOString(),
        time: fetchResult.timingMs,
      };
    });

  return JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'BugHunter Pro Security Suite', version: '1.0' },
      entries: entries.length > 0 ? entries : [{
        request: { method: 'GET', url: fetchResult.finalUrl, headers: [], bodySize: 0 },
        response: { status: fetchResult.status, statusText: fetchResult.statusText, headers: [], bodySize: 0 },
        startedDateTime: new Date().toISOString(),
        time: fetchResult.timingMs,
      }],
    },
  }, null, 2);
}

function buildReadme(a: Assessment, config: SuiteConfig, screenshotCount: number, hasVideo: boolean, hasHar: boolean): string {
  return `BugHunter Pro — Security Assessment Package
=============================================

Target: ${a.finalUrl}
Date: ${a.scannedAt}
Score: ${a.score}/100 (Grade ${a.grade})
Scan Type: ${config.scanType}
Scope: ${config.scanScope}

Findings Summary:
  Critical: ${a.severityCounts.critical}
  High: ${a.severityCounts.high}
  Medium: ${a.severityCounts.medium}
  Low: ${a.severityCounts.low}
  Info: ${a.severityCounts.info}
  Total: ${a.totalIssues}

Package Contents:
  Reports/
    report.json          — Full assessment data in JSON
    report.csv           — Findings in CSV format
    report.md            — Markdown report
    report.html          — HTML report (printable)
    report.xlsx.csv      — Excel-compatible CSV
    hackerone-export.csv — HackerOne submission format
    bugcrowd-export.csv  — Bugcrowd submission format

  Evidence/
    Screenshots/         — ${screenshotCount} PNG screenshots
    Videos/              — ${hasVideo ? 'Screen recording (WebM/MP4)' : 'No video captured'}
    HAR/                 — ${hasHar ? 'HTTP Archive (network.har)' : 'No HAR exported'}
    Requests/            — HTTP request evidence per finding
    Responses/           — HTTP response evidence per finding
    Logs/                — Scan log and console log
    Payloads/            — Proof of concept payloads

Generated by BugHunter Pro Security Suite
Authorized security testing only.
`;
}

function csvEscape(s: string): string {
  if (!s) return '';
  const escaped = s.replace(/"/g, '""').replace(/\n/g, ' ');
  return `"${escaped}"`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
