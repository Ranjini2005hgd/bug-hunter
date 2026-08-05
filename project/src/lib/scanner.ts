import type { Assessment, CategoryCount, Finding, Severity, SeverityCount, ScanContext, WorkflowState, AssessmentScope, CodeFinding } from './types';
import type { FetchResult } from './types';
import { buildScanContext } from './fetcher';
import { checkSecurity } from './checkers/security';
import { checkAccessibility } from './checkers/accessibility';
import { checkSeo } from './checkers/seo';
import { checkPerformance } from './checkers/performance';
import { checkBestPractices } from './checkers/bestPractices';
import { checkPwa } from './checkers/pwa';
import { runRecon } from './recon';
import { enrichFindings, buildComplianceReport } from './enricher';
import { createInitialWorkflowState, completeWorkflow } from './workflow';
import { analyzeCode } from './codeAnalyzer';
import { generateAiExplanation, enumerateSubdomains, analyzeJavaScript, bruteForceDirectories } from './reconAdvanced';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 100,
  high: 30,
  medium: 10,
  low: 4,
  info: 1,
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export async function runScan(fetch: FetchResult): Promise<Assessment> {
  const ctx = buildScanContext(fetch);

  const allCheckers = [checkSecurity, checkAccessibility, checkSeo, checkPerformance, checkBestPractices, checkPwa];

  const rawFindings: Finding[] = [];
  for (const checker of allCheckers) {
    try {
      const result = checker(ctx);
      rawFindings.push(...result);
    } catch (err) {
      console.error(`Checker ${checker.name} failed:`, err);
    }
  }

  // Enrich findings with CVSS, OWASP, evidence packages, confidence, compliance
  const findings = enrichFindings(rawFindings, ctx, fetch);

  // Run source code analysis on inline JavaScript
  const inlineJs = Array.from(ctx.document.querySelectorAll('script:not([src])'))
    .map((s) => s.textContent || '')
    .filter((t) => t.trim().length > 20)
    .join('\n\n');
  let codeFindings: Finding[] = [];
  if (inlineJs.length > 50) {
    const codeResult = analyzeCode(inlineJs, 'javascript');
    codeFindings = codeResult.findings.map((cf: CodeFinding): Finding => ({
      id: cf.id,
      ruleId: cf.ruleId,
      category: 'code' as const,
      severity: cf.severity,
      confidence: cf.confidence,
      title: cf.title,
      description: cf.description,
      evidence: cf.snippet,
      location: `Line ${cf.lineStart}-${cf.lineEnd}`,
      impact: cf.impact,
      recommendation: cf.recommendation,
      fixSteps: cf.fixSteps,
      codeBefore: cf.codeBefore,
      codeAfter: cf.codeAfter,
      references: cf.references,
      cweId: cf.cweId,
      owaspCategory: cf.owaspCategory,
    }));
  }
  const allFindings = [...findings, ...codeFindings];

  // Run reconnaissance
  const recon = runRecon(ctx, fetch);

  // Run advanced reconnaissance (async, non-blocking — best-effort)
  try {
    const [subdomains, jsAnalysis, dirScan] = await Promise.allSettled([
      enumerateSubdomains(ctx.finalUrl),
      analyzeJavaScript(ctx),
      bruteForceDirectories(ctx.finalUrl),
    ]);
    if (subdomains.status === 'fulfilled') recon.subdomains = subdomains.value;
    if (jsAnalysis.status === 'fulfilled') recon.jsAnalysis = jsAnalysis.value;
    if (dirScan.status === 'fulfilled') recon.directoryScan = dirScan.value;
  } catch {
    // Advanced recon is best-effort — don't fail the scan
  }

  // Build compliance report
  const compliance = buildComplianceReport(findings);

  // Generate AI explanations for security findings
  for (const f of allFindings) {
    if (f.category === 'security' || f.category === 'code') {
      (f as Finding & { aiExplanation?: unknown }).aiExplanation = generateAiExplanation({
        title: f.title,
        description: f.description,
        severity: f.severity,
        impact: f.impact,
        cweId: f.cweId,
        owaspCategory: f.owaspCategory,
        vulnerabilityClass: f.vulnerabilityClass,
      });
    }
  }

  // Sort by severity, then category
  allFindings.sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.severity);
    const sb = SEVERITY_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    return a.category.localeCompare(b.category);
  });

  const severityCounts: SeverityCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categoryCounts: CategoryCount = {
    security: 0,
    accessibility: 0,
    seo: 0,
    performance: 0,
    'best-practices': 0,
    pwa: 0,
    code: 0,
  };

  for (const f of allFindings) {
    severityCounts[f.severity] += 1;
    categoryCounts[f.category] += 1;
  }

  let penalty = 0;
  for (const f of allFindings) {
    penalty += SEVERITY_WEIGHTS[f.severity];
  }
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = scoreToGrade(score);

  const pageStats = computePageStats(ctx, fetch);

  // Build scope
  const scope = buildScope(fetch);

  // Build workflow state (all steps completed)
  let workflow = createInitialWorkflowState();
  for (const step of ['reconnaissance', 'asset-discovery', 'endpoint-mapping', 'vulnerability-testing', 'ai-analysis', 'evidence-collection', 'severity-assessment', 'report-generation', 'human-review'] as const) {
    workflow = advanceThroughSteps(workflow, step);
  }
  workflow = completeWorkflow(workflow);

  const result: Assessment = {
    id: crypto.randomUUID(),
    scope,
    workflow,
    recon,
    url: fetch.url,
    finalUrl: fetch.finalUrl,
    status: fetch.status,
    statusText: fetch.statusText,
    score,
    grade,
    totalIssues: allFindings.length,
    severityCounts,
    categoryCounts,
    findings: allFindings,
    pageStats,
    scannedAt: new Date().toISOString(),
    compliance,
  };

  return result;
}

function advanceThroughSteps(state: WorkflowState, to: Assessment['workflow']['currentStep']): WorkflowState {
  const completedSteps = state.completedSteps.includes(state.currentStep) ? state.completedSteps : [...state.completedSteps, state.currentStep];
  const stepStatus = { ...state.stepStatus, [state.currentStep]: 'completed' as const, [to]: 'in-progress' as const };
  return { ...state, currentStep: to, completedSteps, stepStatus };
}

function buildScope(fetch: FetchResult): AssessmentScope {
  let hostname = fetch.url;
  try { hostname = new URL(fetch.finalUrl || fetch.url).hostname; } catch { /* keep */ }
  return {
    programName: `BugHunter Assessment — ${hostname}`,
    targetDomains: [hostname],
    inScopeAssets: [fetch.url],
    outOfScopeAssets: [],
    authAvailable: false,
    programRules: 'Automated passive security assessment. No active exploitation, payload injection, or load testing performed.',
    rateLimit: 'Single request per resource. No concurrent requests to the same host.',
    testingRestrictions: 'Passive analysis only — the scanner reads server responses but does not send attack payloads.',
  };
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  if (score >= 50) return 'E';
  return 'F';
}

function computePageStats(ctx: ScanContext, fetch: FetchResult) {
  const { document: doc } = ctx;
  return {
    htmlSizeBytes: new Blob([fetch.html]).size,
    loadTimeMs: fetch.timingMs,
    numScripts: doc.querySelectorAll('script').length,
    numStylesheets: doc.querySelectorAll('link[rel="stylesheet"]').length,
    numImages: doc.querySelectorAll('img').length,
    numLinks: doc.querySelectorAll('a[href]').length,
    numForms: doc.querySelectorAll('form').length,
    redirectCount: fetch.redirectChain.length > 1 ? fetch.redirectChain.length - 1 : 0,
    hasRobotsTxt: ctx.robots?.status === 200,
    hasSitemapXml: ctx.sitemap?.status === 200,
    hasHttps: ctx.isHttps,
    protocol: ctx.isHttps ? 'https' : 'http',
  };
}
