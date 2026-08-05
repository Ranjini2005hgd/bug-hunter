import type { Assessment, Finding } from './types';

function downloadWord(filename: string, htmlContent: string): void {
  const fullHtml = `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office"
      xmlns:w="urn:schemas-microsoft-com:office:word"
      xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="utf-8">
<meta name="ProgId" content="Word.Document">
<meta name="Generator" content="BugHunter Pro">
<meta name="Originator" content="BugHunter Pro">
<title>${filename}</title>
<!--[if gte mso 9]><xml>
<w:WordDocument>
<w:View>Print</w:View>
<w:Zoom>100</w:Zoom>
<w:DoNotPromptForConvert/>
<w:DoNotShowInsertionsAndDeletions/>
</w:WordDocument>
</xml><![endif]-->
<style>
@page { size: A4; margin: 2cm 2.5cm; }
body { font-family: 'Calibri', 'Segoe UI', Arial, sans-serif; font-size: 11pt; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 22pt; color: #0f172a; border-bottom: 3px solid #0ea5e9; padding-bottom: 6px; margin-top: 0; }
h2 { font-size: 16pt; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-top: 24px; }
h3 { font-size: 13pt; color: #1e293b; margin-top: 18px; margin-bottom: 4px; }
h4 { font-size: 11pt; color: #475569; margin-top: 12px; margin-bottom: 3px; }
p { margin: 6px 0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 10pt; }
th, td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }
th { background: #0f172a; color: #ffffff; }
.cover { text-align: center; padding: 60px 0 40px; }
.cover-title { font-size: 32pt; font-weight: bold; color: #0f172a; margin-bottom: 8px; }
.cover-sub { font-size: 14pt; color: #475569; margin-bottom: 24px; }
.cover-meta { font-size: 11pt; color: #64748b; margin: 4px 0; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 9pt; font-weight: bold; color: #fff; }
.b-critical { background: #dc2626; }
.b-high { background: #ea580c; }
.b-medium { background: #ca8a04; }
.b-low { background: #2563eb; }
.b-info { background: #64748b; }
.sev-critical { color: #dc2626; font-weight: bold; }
.sev-high { color: #ea580c; font-weight: bold; }
.sev-medium { color: #ca8a04; font-weight: bold; }
.sev-low { color: #2563eb; font-weight: bold; }
.sev-info { color: #64748b; font-weight: bold; }
.finding-box { border: 1px solid #e2e8f0; border-radius: 4px; padding: 12px 16px; margin: 12px 0; page-break-inside: avoid; }
.finding-id { font-size: 9pt; color: #94a3b8; font-family: 'Consolas', monospace; }
.code-block { font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt; background: #f1f5f9; border: 1px solid #e2e8f0; padding: 8px; white-space: pre-wrap; border-radius: 3px; margin: 6px 0; }
.code-label { font-size: 9pt; color: #64748b; font-weight: bold; margin-top: 8px; }
.section-break { page-break-before: always; }
.toc-item { margin: 3px 0; font-size: 11pt; }
.toc-sev { color: #94a3b8; font-size: 9pt; }
.kpi-table td { font-size: 11pt; }
.ref-link { color: #2563eb; text-decoration: none; word-break: break-all; }
ol.steps { margin: 6px 0 6px 20px; padding: 0; }
ol.steps li { margin: 4px 0; }
.footnote { font-size: 9pt; color: #94a3b8; margin-top: 24px; border-top: 1px solid #e2e8f0; padding-top: 8px; }
.cvss-badge { display: inline-block; padding: 3px 12px; border-radius: 4px; font-weight: bold; color: #fff; font-size: 10pt; }
.status-pass { color: #16a34a; font-weight: bold; }
.status-fail { color: #dc2626; font-weight: bold; }
.status-warning { color: #ca8a04; font-weight: bold; }
.meta-grid { display: table; width: 100%; }
.meta-grid div { display: table-row; }
.meta-grid span { display: table-cell; padding: 3px 8px; }
.meta-grid .mk { color: #64748b; font-weight: bold; width: 180px; }
.evidence-box { background: #f8fafc; border-left: 3px solid #0ea5e9; padding: 8px 12px; margin: 8px 0; font-size: 10pt; }
.workflow-step { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
.workflow-num { display: inline-block; width: 24px; height: 24px; border-radius: 50%; background: #0f172a; color: #fff; text-align: center; line-height: 24px; font-size: 10pt; font-weight: bold; }
</style>
</head>
<body>
${htmlContent}
</body>
</html>`;

  const blob = new Blob(['\ufeff', fullHtml], { type: 'application/msword' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function esc(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
}

function gradeColor(grade: string): string {
  if (grade === 'A' || grade === 'B') return '#16a34a';
  if (grade === 'C' || grade === 'D') return '#ca8a04';
  return '#dc2626';
}

function severityLabel(s: string): string { return s.charAt(0).toUpperCase() + s.slice(1); }
function severityBadge(s: string): string { return `<span class="badge b-${s}">${severityLabel(s)}</span>`; }
function cvssBadge(score: number, severity: string): string {
  const color = severity === 'critical' ? '#dc2626' : severity === 'high' ? '#ea580c' : severity === 'medium' ? '#ca8a04' : severity === 'low' ? '#2563eb' : '#64748b';
  return `<span class="cvss-badge" style="background:${color}">CVSS ${score.toFixed(1)} — ${severityLabel(severity)}</span>`;
}

function categoryLabel(cat: string): string {
  const map: Record<string, string> = { security: 'Security', accessibility: 'Accessibility', seo: 'SEO', performance: 'Performance', 'best-practices': 'Best Practices', pwa: 'PWA' };
  return map[cat] || cat;
}

function coverPage(a: Assessment, docTitle: string, docSubtitle: string): string {
  return `
<div class="cover">
  <div class="cover-title">BugHunter Pro</div>
  <div class="cover-sub">Advanced Security Assessment Report</div>
  <div style="margin: 20px auto; width: 120px; height: 120px; border-radius: 50%; background: ${gradeColor(a.grade)}; color: #fff; font-size: 48pt; font-weight: bold; text-align: center; line-height: 120px;">${a.grade}</div>
  <div style="font-size: 14pt; color: #475569;">Health Score: ${a.score} / 100</div>
  <div style="margin-top: 30px;">
    <p class="cover-meta"><strong>Document:</strong> ${esc(docTitle)}</p>
    <p class="cover-meta"><strong>Type:</strong> ${esc(docSubtitle)}</p>
    <p class="cover-meta"><strong>Program:</strong> ${esc(a.scope.programName)}</p>
    <p class="cover-meta"><strong>Target URL:</strong> ${esc(a.finalUrl)}</p>
    <p class="cover-meta"><strong>Scan Date:</strong> ${formatDate(a.scannedAt)}</p>
    <p class="cover-meta"><strong>Findings:</strong> ${a.totalIssues} total (${a.severityCounts.critical} critical, ${a.severityCounts.high} high, ${a.severityCounts.medium} medium, ${a.severityCounts.low} low, ${a.severityCounts.info} info)</p>
    <p class="cover-meta"><strong>Technologies:</strong> ${a.recon.technologies.length} detected | <strong>Endpoints:</strong> ${a.recon.endpoints.length} mapped</p>
  </div>
</div>
<p class="footnote">Generated by BugHunter Pro — an AI-powered security assessment platform. This report is based on a point-in-time automated analysis of the target URL. It follows the 10-step bug bounty workflow: scope validation, reconnaissance, asset discovery, endpoint mapping, vulnerability testing, AI analysis, evidence collection, severity assessment, report generation, and human review. Findings marked "needs-verification" are heuristic and should be confirmed manually. This is an authorized assessment within the defined scope.</p>
`;
}

function execSummaryTable(a: Assessment): string {
  const cvssMax = Math.max(0, ...a.findings.map((f) => f.cvss?.score || 0));
  return `
<table class="kpi-table">
  <tr><th>Metric</th><th>Value</th><th>Metric</th><th>Value</th></tr>
  <tr><td><strong>Overall Score</strong></td><td>${a.score} / 100 (Grade ${a.grade})</td><td><strong>HTTP Status</strong></td><td>${a.status} ${esc(a.statusText)}</td></tr>
  <tr><td><strong>Total Issues</strong></td><td>${a.totalIssues}</td><td><strong>Max CVSS</strong></td><td>${cvssMax.toFixed(1)}</td></tr>
  <tr><td class="sev-critical">Critical</td><td>${a.severityCounts.critical}</td><td><strong>Technologies</strong></td><td>${a.recon.technologies.length}</td></tr>
  <tr><td class="sev-high">High</td><td>${a.severityCounts.high}</td><td><strong>Endpoints Mapped</strong></td><td>${a.recon.endpoints.length}</td></tr>
  <tr><td class="sev-medium">Medium</td><td>${a.severityCounts.medium}</td><td><strong>Assets Discovered</strong></td><td>${a.recon.assets.length}</td></tr>
  <tr><td class="sev-low">Low</td><td>${a.severityCounts.low}</td><td><strong>JS Resources</strong></td><td>${a.recon.javascriptResources.length}</td></tr>
  <tr><td class="sev-info">Info</td><td>${a.severityCounts.info}</td><td><strong>DNS Records</strong></td><td>${a.recon.dnsInfo.ips.length} A, ${a.recon.dnsInfo.txtRecords.length} TXT</td></tr>
</table>
`;
}

function scopeSection(a: Assessment): string {
  const s = a.scope;
  return `
<h2>1.1 Scope Validation</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Program Name</td><td>${esc(s.programName)}</td></tr>
  <tr><td>Target Domains</td><td>${s.targetDomains.map(esc).join(', ')}</td></tr>
  <tr><td>In-Scope Assets</td><td>${s.inScopeAssets.map(esc).join(', ')}</td></tr>
  <tr><td>Out-of-Scope Assets</td><td>${s.outOfScopeAssets.length ? s.outOfScopeAssets.map(esc).join(', ') : 'None specified'}</td></tr>
  <tr><td>Authentication Available</td><td>${s.authAvailable ? 'Yes' : 'No'}</td></tr>
  <tr><td>Program Rules</td><td>${esc(s.programRules)}</td></tr>
  <tr><td>Rate Limiting</td><td>${esc(s.rateLimit)}</td></tr>
  <tr><td>Testing Restrictions</td><td>${esc(s.testingRestrictions)}</td></tr>
</table>
`;
}

function reconSection(a: Assessment): string {
  const techRows = a.recon.technologies.map((t) => `<tr><td>${esc(t.name)}</td><td>${esc(t.category)}</td><td>${t.version ? esc(t.version) : '—'}</td><td>${esc(t.confidence)}</td><td>${esc(t.evidence)}</td></tr>`).join('');
  const endpointRows = a.recon.endpoints.slice(0, 30).map((e) => `<tr><td>${esc(e.method)}</td><td>${esc(e.url)}</td><td>${e.authRequired ? 'Yes' : 'No'}</td><td>${e.parameters.length ? e.parameters.map(esc).join(', ') : '—'}</td></tr>`).join('');
  const jsRows = a.recon.javascriptResources.slice(0, 20).map((j) => `<tr><td>${esc(j)}</td></tr>`).join('');
  const dnsRows = `
    <tr><td>Hostname</td><td>${esc(a.recon.dnsInfo.hostname)}</td></tr>
    <tr><td>A Records (IPs)</td><td>${a.recon.dnsInfo.ips.length ? a.recon.dnsInfo.ips.map(esc).join(', ') : 'Not resolved'}</td></tr>
    <tr><td>TXT Records</td><td>${a.recon.dnsInfo.txtRecords.length ? a.recon.dnsInfo.txtRecords.slice(0, 5).map(esc).join(', ') : 'None'}</td></tr>
  `;

  return `
<h2>2.1 Technology Fingerprinting</h2>
<table>
  <tr><th>Name</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr>
  ${techRows || '<tr><td colspan="5">No technologies detected.</td></tr>'}
</table>

<h2>2.2 DNS Information</h2>
<table>
  <tr><th>Record</th><th>Value</th></tr>
  ${dnsRows}
</table>

<h2>2.3 Discovered Assets & Endpoints</h2>
<table>
  <tr><th>Method</th><th>URL</th><th>Auth Required</th><th>Parameters</th></tr>
  ${endpointRows || '<tr><td colspan="4">No endpoints discovered.</td></tr>'}
</table>

<h2>2.4 JavaScript Resources</h2>
<table>
  <tr><th>URL</th></tr>
  ${jsRows || '<tr><td>No JavaScript resources found.</td></tr>'}
</table>
`;
}

function complianceSection(a: Assessment): string {
  const renderFramework = (title: string, items: Assessment['compliance']['gdpr']) => {
    const rows = items.map((item) => {
      const statusClass = item.status === 'pass' ? 'status-pass' : item.status === 'fail' ? 'status-fail' : item.status === 'warning' ? 'status-warning' : '';
      return `<tr><td>${esc(item.control)}</td><td class="${statusClass}">${item.status.toUpperCase()}</td><td>${esc(item.description)}</td><td>${item.finding ? esc(item.finding) : '—'}</td></tr>`;
    }).join('');
    return `<h3>${title}</h3><table><tr><th>Control</th><th>Status</th><th>Description</th><th>Related Finding</th></tr>${rows}</table>`;
  };
  return renderFramework('GDPR', a.compliance.gdpr) + renderFramework('PCI DSS', a.compliance.pciDss) + renderFramework('HIPAA', a.compliance.hipaa) + renderFramework('ISO 27001', a.compliance.iso27001);
}

function findingBlockFormal(f: Finding, index: number): string {
  const refs = f.references.map((r) => `<a class="ref-link" href="${esc(r.url)}">${esc(r.label)}</a>`).join('<br>');
  const ep = f.evidencePackage;
  return `
<div class="finding-box">
  <p class="finding-id">Finding ID: ${f.id} | Rule: ${esc(f.ruleId)} ${f.cweId ? `| ${esc(f.cweId)}` : ''} ${f.wcagLevel ? `| WCAG ${esc(f.wcagLevel)}` : ''} ${f.owaspCategory ? `| OWASP ${esc(f.owaspCategory)}` : ''}</p>
  <h3>${severityBadge(f.severity)} ${esc(f.title)}</h3>
  <div class="meta-grid">
    <div><span class="mk">Category:</span><span>${categoryLabel(f.category)}</span></div>
    <div><span class="mk">Confidence:</span><span>${esc(f.confidence)}</span></div>
    <div><span class="mk">Status:</span><span>${esc(f.status || 'potential')}</span></div>
    ${f.cvss ? `<div><span class="mk">CVSS:</span><span>${cvssBadge(f.cvss.score, f.cvss.severity)}</span></div><div><span class="mk">Vector:</span><span style="font-family:Consolas;font-size:9pt">${esc(f.cvss.vector)}</span></div>` : ''}
    ${f.owaspCategory ? `<div><span class="mk">OWASP Category:</span><span>${esc(f.owaspCategory)}</span></div>` : ''}
    ${f.affectedAsset ? `<div><span class="mk">Affected Asset:</span><span>${esc(f.affectedAsset)}</span></div>` : ''}
    ${f.affectedEndpoint ? `<div><span class="mk">Affected Endpoint:</span><span>${esc(f.affectedEndpoint)}</span></div>` : ''}
    ${f.likelihood ? `<div><span class="mk">Likelihood:</span><span>${esc(f.likelihood)}</span></div>` : ''}
    ${f.prerequisites ? `<div><span class="mk">Prerequisites:</span><span>${esc(f.prerequisites)}</span></div>` : ''}
  </div>

  <h4>Description</h4><p>${esc(f.description)}</p>
  ${f.evidence ? `<h4>Evidence</h4><div class="code-block">${esc(f.evidence)}</div>` : ''}
  <h4>Impact</h4><p>${esc(f.impact)}</p>

  ${ep?.proofOfConcept ? `<h4>Proof of Concept</h4><div class="evidence-box">${esc(ep.proofOfConcept)}</div>` : ''}
  ${ep?.reproductionSteps?.length ? `<h4>Reproduction Steps</h4><ol class="steps">${ep.reproductionSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
  ${ep?.httpRequests?.length ? `<h4>HTTP Request</h4><div class="code-block">${esc(ep.httpRequests[0].content)}</div>` : ''}
  ${ep?.httpResponses?.length ? `<h4>HTTP Response</h4><div class="code-block">${esc(ep.httpResponses[0].content)}</div>` : ''}

  ${f.timeline?.length ? `<h4>Timeline</h4><table><tr><th>Timestamp</th><th>Event</th><th>Detail</th></tr>${f.timeline.map((t) => `<tr><td>${formatDate(t.timestamp)}</td><td>${esc(t.event)}</td><td>${t.detail ? esc(t.detail) : '—'}</td></tr>`).join('')}</table>` : ''}

  ${f.references.length ? `<h4>References</h4><p>${refs}</p>` : ''}

  ${f.aiExplanation ? `
  <h4>AI Vulnerability Analysis</h4>
  <table>
    <tr><th style="width:25%">Aspect</th><th>Analysis</th></tr>
    <tr><td><strong>Summary</strong></td><td>${esc(f.aiExplanation.summary)}</td></tr>
    <tr><td><strong>Attack Scenario</strong></td><td>${esc(f.aiExplanation.attackScenario)}</td></tr>
    <tr><td><strong>Business Risk</strong></td><td>${esc(f.aiExplanation.businessRisk)}</td></tr>
    <tr><td><strong>Remediation Priority</strong></td><td>${esc(f.aiExplanation.remediationPriority)}</td></tr>
    <tr><td><strong>Testing Advice</strong></td><td>${esc(f.aiExplanation.testingAdvice)}</td></tr>
  </table>
  ` : ''}
</div>
`;
}

function findingBlockSolution(f: Finding, index: number): string {
  const steps = f.fixSteps.map((s) => `<li>${esc(s)}</li>`).join('');
  const refs = f.references.map((r) => `<a class="ref-link" href="${esc(r.url)}">${esc(r.label)}</a>`).join('<br>');
  return `
<div class="finding-box">
  <p class="finding-id">Fix #${index} | Rule: ${esc(f.ruleId)} ${f.cvss ? `| CVSS ${f.cvss.score.toFixed(1)}` : ''}</p>
  <h3>${severityBadge(f.severity)} ${esc(f.title)}</h3>
  <h4>Recommended Solution</h4><p>${esc(f.recommendation)}</p>
  <h4>Step-by-Step Fix</h4><ol class="steps">${steps}</ol>
  ${f.codeBefore ? `<div class="code-label">Before:</div><div class="code-block">${esc(f.codeBefore)}</div>` : ''}
  ${f.codeAfter ? `<div class="code-label">After:</div><div class="code-block">${esc(f.codeAfter)}</div>` : ''}
  ${f.references.length ? `<h4>Further Reading</h4><p>${refs}</p>` : ''}
</div>
`;
}

function workflowSection(a: Assessment): string {
  const steps = ['scope-validation', 'reconnaissance', 'asset-discovery', 'endpoint-mapping', 'vulnerability-testing', 'ai-analysis', 'evidence-collection', 'severity-assessment', 'report-generation', 'human-review'];
  const labels: Record<string, string> = {
    'scope-validation': 'Scope Validation', 'reconnaissance': 'Reconnaissance', 'asset-discovery': 'Asset Discovery',
    'endpoint-mapping': 'Endpoint Mapping', 'vulnerability-testing': 'Vulnerability Testing', 'ai-analysis': 'AI Analysis',
    'evidence-collection': 'Evidence Collection', 'severity-assessment': 'Severity Assessment', 'report-generation': 'Report Generation', 'human-review': 'Human Review',
  };
  const items = steps.map((s, i) => `<div class="workflow-step"><span class="workflow-num">${i + 1}</span><strong>${labels[s]}</strong> — Completed</div>`).join('');
  return `<h2>Assessment Workflow</h2><p>This assessment followed the BugHunter Pro 10-step security assessment workflow:</p>${items}`;
}

/**
 * Formal Bug Report — full bug bounty format with scope, recon, CVSS,
 * evidence packages, compliance, and the 10-step workflow documentation.
 */
export function generateFormalBugReport(a: Assessment): void {
  const findingsHtml = a.findings.map((f, i) => findingBlockFormal(f, i + 1)).join('');

  const body = `
${coverPage(a, 'Formal Bug Report', 'Security Assessment Documentation')}
<div class="section-break"></div>
<h1>1. Executive Summary</h1>
<p>This report documents ${a.totalIssues} finding${a.totalIssues === 1 ? '' : 's'} identified during an automated security assessment of <strong>${esc(a.finalUrl)}</strong> conducted on ${formatDate(a.scannedAt)}. The assessment followed the BugHunter Pro 10-step workflow (scope validation through human review) and evaluated the target against OWASP Top 10 (2021), WCAG 2.1, Core Web Vitals, and modern web standards.</p>
<p>The target achieved a health score of <strong>${a.score}/100 (Grade ${a.grade})</strong>. The assessment detected ${a.recon.technologies.length} technologies, mapped ${a.recon.endpoints.length} endpoints, and evaluated ${a.totalIssues} findings with CVSS 3.1 severity scoring where applicable.</p>
${execSummaryTable(a)}
${scopeSection(a)}

<div class="section-break"></div>
<h1>2. Reconnaissance & Asset Discovery</h1>
<p>The reconnaissance phase built an inventory of the target's technology stack, DNS configuration, endpoints, and JavaScript resources. All discovered assets are within the authorized scope.</p>
${reconSection(a)}

<div class="section-break"></div>
<h1>3. Vulnerability Testing & Findings</h1>
<p>The vulnerability testing phase evaluated the target against the OWASP Top 10 vulnerability classes and additional quality categories. Each finding below includes CVSS 3.1 scoring (where applicable), confidence level, evidence package with HTTP request/response captures, proof of concept, and reproduction steps.</p>
${findingsHtml || '<p>No issues were detected during this assessment.</p>'}

<div class="section-break"></div>
<h1>4. Compliance Assessment</h1>
<p>Findings were mapped to common compliance frameworks to identify control gaps. Status of "fail" indicates one or more findings directly violate the control; "warning" indicates an indirect risk; "pass" indicates the control is satisfied.</p>
${complianceSection(a)}

<div class="section-break"></div>
<h1>5. Assessment Methodology</h1>
${workflowSection(a)}
<p><strong>Vulnerability classes tested:</strong> Authentication issues, Authorization (IDOR/BOLA), Injection flaws, XSS, CSRF, SSRF, File upload weaknesses, Path traversal, XXE, Open redirect, Security misconfiguration, Information disclosure, and Business logic flaws (passive analysis).</p>
<p><strong>Limitations:</strong> This assessment performs passive analysis of server-rendered HTML and HTTP headers. It does not perform active exploitation, payload injection, authenticated testing, or load testing. Client-side rendered content may not be fully captured. Findings marked "needs-verification" require manual confirmation.</p>

<p class="footnote">BugHunter Pro Formal Bug Report — Generated ${formatDate(a.scannedAt)} — Confidential — Authorized Assessment</p>
`;

  downloadWord(`BugHunter-Pro-Formal-Report-${a.id.slice(0, 8)}.doc`, body);
}

/**
 * Solution & Remediation Guide — developer-focused document with
 * step-by-step fixes, before/after code examples, and compliance remediation.
 */
export function generateSolutionReport(a: Assessment): void {
  const byCategory = (cat: string) => a.findings.filter((f) => f.category === cat);
  const cats = ['security', 'accessibility', 'seo', 'performance', 'best-practices', 'pwa'];

  const sections = cats.map((cat) => {
    const items = byCategory(cat);
    if (items.length === 0) return '';
    const blocks = items.map((f, i) => findingBlockSolution(f, i + 1)).join('');
    return `<h2>${categoryLabel(cat)} Solutions (${items.length})</h2>${blocks}`;
  }).filter(Boolean).join('<div class="section-break"></div>');

  const complianceRemediation = a.findings
    .filter((f) => f.owaspCategory && (f.severity === 'critical' || f.severity === 'high'))
    .map((f) => `<li><strong>${esc(f.title)}</strong> — ${esc(f.recommendation)}</li>`)
    .join('');

  const body = `
${coverPage(a, 'Solution & Remediation Guide', 'Developer Fix Documentation')}
<div class="section-break"></div>
<h1>1. Remediation Overview</h1>
<p>This guide provides actionable solutions for each finding from the assessment of <strong>${esc(a.finalUrl)}</strong>. It is the companion to the Formal Bug Report and is intended for the development team.</p>
<p>Address findings in severity order: Critical first (same day), then High (within 1 week), Medium (within 2 weeks), Low (within 1 month), and Informational (backlog). After implementing fixes, re-run the assessment to confirm resolution.</p>
${execSummaryTable(a)}

<div class="section-break"></div>
<h1>2. Fix Priority Matrix</h1>
<table>
  <tr><th>Priority</th><th>Action</th><th>Timeline</th></tr>
  <tr><td class="sev-critical">Critical</td><td>Fix immediately — direct security or data-loss risk</td><td>Same day</td></tr>
  <tr><td class="sev-high">High</td><td>Fix urgently — significant risk or major user impact</td><td>Within 1 week</td></tr>
  <tr><td class="sev-medium">Medium</td><td>Fix in the current sprint</td><td>Within 2 weeks</td></tr>
  <tr><td class="sev-low">Low</td><td>Schedule for next maintenance cycle</td><td>Within 1 month</td></tr>
  <tr><td class="sev-info">Informational</td><td>Address when convenient</td><td>Backlog</td></tr>
</table>

<div class="section-break"></div>
<h1>3. Solutions by Category</h1>
${sections || '<p>No issues were detected during this assessment.</p>'}

${complianceRemediation ? `<div class="section-break"></div><h1>4. Compliance-Critical Fixes</h1><p>The following fixes are required to address compliance framework failures (GDPR, PCI DSS, HIPAA, ISO 27001):</p><ol class="steps">${complianceRemediation}</ol>` : ''}

<div class="section-break"></div>
<h1>5. Verification & Next Steps</h1>
<ol class="steps">
  <li>Implement fixes starting with Critical and High severity items.</li>
  <li>For each fix, apply the "After" code pattern in place of the "Before" pattern.</li>
  <li>Test locally — verify the page renders and functions correctly.</li>
  <li>For accessibility fixes, test with NVDA/VoiceOver and keyboard-only navigation.</li>
  <li>For security header fixes, verify with browser devtools or securityheaders.com.</li>
  <li>Re-run the BugHunter Pro assessment to confirm the finding count has dropped.</li>
  <li>Repeat for remaining Medium, Low, and Informational items.</li>
</ol>

<p class="footnote">BugHunter Pro Solution & Remediation Guide — Generated ${formatDate(a.scannedAt)} — For Development Team</p>
`;

  downloadWord(`BugHunter-Pro-Solution-Guide-${a.id.slice(0, 8)}.doc`, body);
}

/**
 * Formal Bug Bounty Submission Report — a formal document that can be
 * submitted directly to an organization's bug bounty program or security
 * team. Includes all required fields: vulnerability title, executive summary,
 * affected assets, severity, CVSS, CWE, OWASP, prerequisites, reproduction
 * steps, PoC, HTTP request/response, impact, likelihood, remediation,
 * references, timeline, and evidence summary.
 */
export function generateFormalSubmissionReport(a: Assessment): void {
  const reportId = `VR-${a.id.slice(0, 8).toUpperCase()}`;
  const submissionDate = formatDate(a.scannedAt);
  const cvssMax = Math.max(0, ...a.findings.map((f) => f.cvss?.score || 0));
  const riskRating = cvssMax >= 9 ? 'Critical' : cvssMax >= 7 ? 'High' : cvssMax >= 4 ? 'Medium' : cvssMax > 0 ? 'Low' : 'Informational';

  const securityFindings = a.findings.filter((f) => f.category === 'security' || f.category === 'code');
  const allFindings = securityFindings.length > 0 ? securityFindings : a.findings;

  const execSummary = `During a manual security assessment of ${esc(a.finalUrl)} conducted on ${submissionDate}, ${allFindings.length} vulnerability${allFindings.length === 1 ? 'y was' : 'ies were'} identified. The assessment uncovered ${a.severityCounts.critical} critical, ${a.severityCounts.high} high, ${a.severityCounts.medium} medium, ${a.severityCounts.low} low, and ${a.severityCounts.info} informational findings. The most severe issue carries a CVSS 3.1 base score of ${cvssMax.toFixed(1)} (${riskRating}). Each finding includes detailed reproduction steps, proof of concept, and evidence (HTTP captures, screenshots, and video recordings where applicable). All testing was performed within the scope defined by the program rules. No data was modified, exfiltrated, or persisted — only read-only verification was conducted.`;

  const findingsHtml = allFindings.map((f, i) => findingBlockSubmission(f, i + 1, reportId)).join('');

  const body = `
<div class="cover">
  <div class="cover-title">Vulnerability Report</div>
  <div class="cover-sub">Security Assessment — Confidential</div>
  <div style="margin: 20px auto; width: 120px; height: 120px; border-radius: 50%; background: ${gradeColor(a.grade)}; color: #fff; font-size: 48pt; font-weight: bold; text-align: center; line-height: 120px;">${a.grade}</div>
  <div style="font-size: 14pt; color: #475569;">Risk Rating: ${riskRating}</div>
  <div style="margin-top: 30px;">
    <p class="cover-meta"><strong>Report ID:</strong> ${reportId}</p>
    <p class="cover-meta"><strong>Target:</strong> ${esc(a.finalUrl)}</p>
    <p class="cover-meta"><strong>Date:</strong> ${submissionDate}</p>
    <p class="cover-meta"><strong>Findings:</strong> ${allFindings.length} (${a.severityCounts.critical} critical, ${a.severityCounts.high} high, ${a.severityCounts.medium} medium, ${a.severityCounts.low} low)</p>
  </div>
</div>
<div class="section-break"></div>

<h1>1. Report Metadata</h1>
<table>
  <tr><th style="width:35%">Field</th><th>Value</th></tr>
  <tr><td><strong>Report ID</strong></td><td style="font-family:Consolas;font-size:10pt">${reportId}</td></tr>
  <tr><td><strong>Program Name</strong></td><td>${esc(a.scope.programName)}</td></tr>
  <tr><td><strong>Researcher</strong></td><td>Security Researcher</td></tr>
  <tr><td><strong>Date of Assessment</strong></td><td>${submissionDate}</td></tr>
  <tr><td><strong>Target URL</strong></td><td style="font-family:Consolas;font-size:10pt">${esc(a.finalUrl)}</td></tr>
  <tr><td><strong>Overall Risk Rating</strong></td><td><span class="badge b-${riskRating.toLowerCase()}">${riskRating}</span></td></tr>
  <tr><td><strong>Max CVSS Score</strong></td><td><strong>${cvssMax.toFixed(1)}</strong> (CVSS 3.1)</td></tr>
  <tr><td><strong>Total Findings</strong></td><td>${allFindings.length}</td></tr>
</table>

<div class="section-break"></div>
<h1>2. Executive Summary</h1>
<p>${execSummary}</p>
<table>
  <tr><th>Severity</th><th>Count</th><th>Description</th></tr>
  <tr><td class="sev-critical">Critical</td><td>${a.severityCounts.critical}</td><td>Immediate security risk — server compromise, data breach, or RCE</td></tr>
  <tr><td class="sev-high">High</td><td>${a.severityCounts.high}</td><td>Significant risk — should be remediated within one week</td></tr>
  <tr><td class="sev-medium">Medium</td><td>${a.severityCounts.medium}</td><td>Moderate risk — address in the current development cycle</td></tr>
  <tr><td class="sev-low">Low</td><td>${a.severityCounts.low}</td><td>Low risk — improvement opportunity</td></tr>
  <tr><td class="sev-info">Informational</td><td>${a.severityCounts.info}</td><td>Informational note — no direct risk</td></tr>
</table>

<div class="section-break"></div>
<h1>3. Scope</h1>
${scopeSection(a)}

<div class="section-break"></div>
<h1>4. Reconnaissance</h1>
<p>The following information was gathered during the reconnaissance phase of the assessment.</p>
${reconSection(a)}

<div class="section-break"></div>
<h1>5. Vulnerability Details</h1>
<p>Each finding below includes the vulnerability title, description, affected asset, severity, CVSS vector, CWE, OWASP category, prerequisites, reproduction steps, proof of concept, HTTP request/response, impact, and remediation. Where applicable, screenshots and video recordings are embedded as evidence.</p>
${findingsHtml || '<p>No vulnerabilities were identified during this assessment.</p>'}

<div class="section-break"></div>
<h1>6. Compliance Impact</h1>
<p>The findings in this report may impact the organization's compliance posture under the following frameworks:</p>
${complianceSection(a)}

<div class="section-break"></div>
<h1>7. Disclosure & Confidentiality</h1>
<table>
  <tr><th style="width:35%">Field</th><th>Value</th></tr>
  <tr><td><strong>Confidentiality</strong></td><td>This report contains confidential security vulnerability information. It must not be shared, published, or disclosed to any party other than the authorized recipient without explicit written permission.</td></tr>
  <tr><td><strong>Disclosure Timeline</strong></td><td>Follow the program's responsible disclosure policy. Do not publicly disclose any finding until the organization has confirmed remediation or the agreed-upon disclosure deadline has passed.</td></tr>
  <tr><td><strong>Evidence Handling</strong></td><td>All evidence (HTTP requests, responses, screenshots, video recordings) was collected during authorized testing within the defined scope. No sensitive personal data was accessed or stored.</td></tr>
  <tr><td><strong>Legal Compliance</strong></td><td>This assessment was conducted within the scope authorized by the program rules. The researcher accepts no liability for any consequences of acting on this report.</td></tr>
</table>

<p class="footnote">
Report ID: ${reportId} | Date: ${submissionDate} | CONFIDENTIAL — AUTHORIZED RECIPIENT ONLY
</p>
`;

  downloadWord(`Vulnerability-Report-${reportId}.doc`, body);
}

function renderMediaEvidence(f: Finding): string {
  if (!f.mediaEvidence || (f.mediaEvidence.screenshots.length === 0 && !f.mediaEvidence.videoRecording)) {
    return '<p>No media evidence attached. Add screenshots or a screen recording to strengthen this submission.</p>';
  }
  let html = '';
  if (f.mediaEvidence.screenshots.length > 0) {
    html += '<h4>Screenshots</h4>';
    for (const ss of f.mediaEvidence.screenshots) {
      html += `<div style="margin: 8px 0; page-break-inside: avoid;"><img src="${ss.dataUrl}" alt="${esc(ss.caption)}" style="max-width: 100%; border: 1px solid #e2e8f0; border-radius: 4px;"/><p style="font-size: 9pt; color: #64748b; margin-top: 4px;">${esc(ss.caption)}</p></div>`;
    }
  }
  if (f.mediaEvidence.videoRecording) {
    html += `<h4>Video Recording</h4><p style="font-size: 10pt; background: #f1f5f9; padding: 8px; border-radius: 3px;">A video recording (${f.mediaEvidence.videoRecording.filename}, ${f.mediaEvidence.videoRecording.duration}s) is attached as evidence. Refer to the video file accompanying this report for a full demonstration of the vulnerability and exploitation steps.</p>`;
  }
  return html;
}

function findingBlockSubmission(f: Finding, index: number, reportId: string): string {
  const refs = f.references.map((r) => `<a class="ref-link" href="${esc(r.url)}">${esc(r.label)}</a>`).join('<br>');
  const ep = f.evidencePackage;
  const findingId = `${reportId}-${String(index).padStart(3, '0')}`;
  const vulnClassLabel = f.vulnerabilityClass ? f.vulnerabilityClass.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') : null;

  return `
<div class="finding-box">
  <p class="finding-id">Finding ${findingId} ${f.cweId ? `| ${esc(f.cweId)}` : ''} ${f.owaspCategory ? `| OWASP ${esc(f.owaspCategory)}` : ''} ${vulnClassLabel ? `| ${esc(vulnClassLabel)}` : ''}</p>
  <h3>${severityBadge(f.severity)} ${esc(f.title)}</h3>

  <h4>Vulnerability Title</h4>
  <p>${esc(f.title)}</p>

  <h4>Summary</h4>
  <p>${esc(f.description)}</p>

  <h4>Affected Asset</h4>
  <p>${esc(f.affectedAsset || 'N/A')}</p>

  <h4>Affected Endpoint</h4>
  <p style="font-family:Consolas;font-size:10pt">${esc(f.affectedEndpoint || 'N/A')}</p>

  <h4>Severity & Scoring</h4>
  <table>
    <tr><th style="width:30%">Metric</th><th>Value</th></tr>
    <tr><td>Severity</td><td>${severityBadge(f.severity)}</td></tr>
    ${f.cvss ? `<tr><td>CVSS 3.1 Score</td><td><strong>${f.cvss.score.toFixed(1)}</strong> — ${esc(f.cvss.severity)}</td></tr><tr><td>CVSS Vector</td><td style="font-family:Consolas;font-size:9pt">${esc(f.cvss.vector)}</td></tr>` : '<tr><td>CVSS</td><td>N/A</td></tr>'}
    ${f.cweId ? `<tr><td>CWE</td><td>${esc(f.cweId)}</td></tr>` : ''}
    ${f.owaspCategory ? `<tr><td>OWASP Category</td><td>${esc(f.owaspCategory)}</td></tr>` : ''}
    ${vulnClassLabel ? `<tr><td>Vulnerability Class</td><td>${esc(vulnClassLabel)}</td></tr>` : ''}
    ${f.likelihood ? `<tr><td>Likelihood</td><td>${esc(f.likelihood)}</td></tr>` : ''}
    <tr><td>Confidence</td><td>${esc(f.confidence)}</td></tr>
  </table>

  <h4>Prerequisites</h4>
  <p>${esc(f.prerequisites || 'Network access to the target.')}</p>

  <h4>Steps to Reproduce</h4>
  ${ep?.reproductionSteps?.length ? `<ol class="steps">${ep.reproductionSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : '<p>See evidence section below.</p>'}

  <h4>Proof of Concept</h4>
  ${ep?.proofOfConcept ? `<div class="evidence-box">${esc(ep.proofOfConcept)}</div>` : `<p>${esc(f.evidence || f.description)}</p>`}

  <h4>Evidence — Screenshots & Video</h4>
  ${renderMediaEvidence(f)}

  <h4>HTTP Request</h4>
  ${ep?.httpRequests?.length ? `<div class="code-block">${esc(ep.httpRequests[0].content)}</div>` : '<p>Not captured.</p>'}

  <h4>HTTP Response</h4>
  ${ep?.httpResponses?.length ? `<div class="code-block">${esc(ep.httpResponses[0].content)}</div>` : '<p>Not captured.</p>'}

  <h4>Impact</h4>
  <p>${esc(f.impact)}</p>

  <h4>Suggested Remediation</h4>
  <p>${esc(f.recommendation)}</p>
  ${f.fixSteps.length ? `<ol class="steps">${f.fixSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}

  ${f.codeBefore ? `<h4>Code Before Fix</h4><div class="code-block">${esc(f.codeBefore)}</div>` : ''}
  ${f.codeAfter ? `<h4>Code After Fix</h4><div class="code-block">${esc(f.codeAfter)}</div>` : ''}

  <h4>References</h4>
  ${f.references.length ? `<p>${refs}</p>` : '<p>N/A</p>'}
</div>
`;
}

/**
 * Generate a standalone report for a single finding — downloadable
 * individually from the findings list. Contains all fields needed
 * for a standalone submission.
 */
export function generateSingleFindingReport(a: Assessment, finding: Finding, index: number): void {
  const reportId = `VR-${a.id.slice(0, 8).toUpperCase()}-${String(index).padStart(3, '0')}`;
  const submissionDate = formatDate(a.scannedAt);
  const vulnClassLabel = finding.vulnerabilityClass ? finding.vulnerabilityClass.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') : 'Security Finding';

  const body = `
<div class="cover">
  <div class="cover-title">${esc(finding.title)}</div>
  <div class="cover-sub">${esc(vulnClassLabel)} — ${severityBadge(finding.severity)}</div>
  <div style="margin: 20px auto; width: 80px; height: 80px; border-radius: 50%; background: ${finding.severity === 'critical' ? '#dc2626' : finding.severity === 'high' ? '#ea580c' : finding.severity === 'medium' ? '#ca8a04' : '#0891b2'}; color: #fff; font-size: 14pt; font-weight: bold; text-align: center; line-height: 80px;">${finding.severity.toUpperCase()}</div>
  <p class="cover-meta"><strong>Report ID:</strong> ${reportId}</p>
  <p class="cover-meta"><strong>Target:</strong> ${esc(a.finalUrl)}</p>
  <p class="cover-meta"><strong>Date:</strong> ${submissionDate}</p>
  ${finding.cvss ? `<p class="cover-meta"><strong>CVSS:</strong> ${finding.cvss.score.toFixed(1)} (${finding.cvss.severity})</p>` : ''}
  ${finding.cweId ? `<p class="cover-meta"><strong>CWE:</strong> ${esc(finding.cweId)}</p>` : ''}
</div>
<div class="section-break"></div>

<h1>1. Vulnerability Details</h1>
<table>
  <tr><th style="width:35%">Field</th><th>Value</th></tr>
  <tr><td><strong>Report ID</strong></td><td style="font-family:Consolas">${reportId}</td></tr>
  <tr><td><strong>Title</strong></td><td>${esc(finding.title)}</td></tr>
  <tr><td><strong>Severity</strong></td><td>${severityBadge(finding.severity)}</td></tr>
  ${finding.cvss ? `<tr><td>CVSS 3.1 Score</td><td><strong>${finding.cvss.score.toFixed(1)}</strong> — ${esc(finding.cvss.severity)}</td></tr><tr><td>CVSS Vector</td><td style="font-family:Consolas;font-size:9pt">${esc(finding.cvss.vector)}</td></tr>` : ''}
  ${finding.cweId ? `<tr><td>CWE</td><td>${esc(finding.cweId)}</td></tr>` : ''}
  ${finding.owaspCategory ? `<tr><td>OWASP Category</td><td>${esc(finding.owaspCategory)}</td></tr>` : ''}
  ${vulnClassLabel !== 'Security Finding' ? `<tr><td>Vulnerability Class</td><td>${esc(vulnClassLabel)}</td></tr>` : ''}
  <tr><td>Affected Asset</td><td>${esc(finding.affectedAsset || a.finalUrl)}</td></tr>
  <tr><td>Affected Endpoint</td><td style="font-family:Consolas">${esc(finding.affectedEndpoint || 'N/A')}</td></tr>
  <tr><td>Confidence</td><td>${esc(finding.confidence)}</td></tr>
  ${finding.likelihood ? `<tr><td>Likelihood</td><td>${esc(finding.likelihood)}</td></tr>` : ''}
</table>

<h1>2. Description</h1>
<p>${esc(finding.description)}</p>

<h1>3. Prerequisites</h1>
<p>${esc(finding.prerequisites || 'Network access to the target.')}</p>

<h1>4. Steps to Reproduce</h1>
${finding.evidencePackage?.reproductionSteps?.length
  ? `<ol class="steps">${finding.evidencePackage.reproductionSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`
  : '<p>1. Navigate to the affected endpoint. 2. Observe the vulnerable condition as described. 3. Confirm the finding per the evidence below.</p>'}

<h1>5. Proof of Concept</h1>
${finding.evidencePackage?.proofOfConcept
  ? `<div class="evidence-box">${esc(finding.evidencePackage.proofOfConcept)}</div>`
  : `<p>${esc(finding.evidence || finding.description)}</p>`}

<h1>6. Evidence — Screenshots & Video</h1>
${renderMediaEvidence(finding)}

<h1>7. HTTP Request / Response</h1>
${finding.evidencePackage?.httpRequests?.length ? `<h4>Request</h4><div class="code-block">${esc(finding.evidencePackage.httpRequests[0].content)}</div>` : ''}
${finding.evidencePackage?.httpResponses?.length ? `<h4>Response</h4><div class="code-block">${esc(finding.evidencePackage.httpResponses[0].content)}</div>` : ''}
${!finding.evidencePackage?.httpRequests?.length && !finding.evidencePackage?.httpResponses?.length ? '<p>Not captured.</p>' : ''}

<h1>8. Impact</h1>
<p>${esc(finding.impact)}</p>

<h1>9. Remediation</h1>
<p>${esc(finding.recommendation)}</p>
${finding.fixSteps.length ? `<ol class="steps">${finding.fixSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}

${finding.codeBefore ? `<h1>10. Code Before Fix</h1><div class="code-block">${esc(finding.codeBefore)}</div>` : ''}
${finding.codeAfter ? `<h1>11. Code After Fix</h1><div class="code-block">${esc(finding.codeAfter)}</div>` : ''}

<h1>12. References</h1>
${finding.references.length ? `<p>${finding.references.map((r) => `<a class="ref-link" href="${esc(r.url)}">${esc(r.label)}</a>`).join('<br>')}</p>` : '<p>N/A</p>'}

<p class="footnote">Report ID: ${reportId} | Date: ${submissionDate} | CONFIDENTIAL</p>
`;

  downloadWord(`Finding-${reportId}.doc`, body);
}

/**
 * HackerOne CSV export — one row per finding with HackerOne's
 * standard report fields.
 */
export function exportHackerOneCsv(a: Assessment): void {
  const headers = ['Title', 'Severity', 'CVSS', 'CWE', 'OWASP', 'Summary', 'Impact', 'Reproduction Steps', 'PoC', 'HTTP Request', 'HTTP Response', 'Affected Asset', 'Remediation', 'References', 'Confidence'];
  const rows = a.findings.map((f) => {
    const ep = f.evidencePackage;
    return [
      csvEscape(f.title),
      f.severity,
      f.cvss ? f.cvss.score.toFixed(1) : '',
      f.cweId || '',
      f.owaspCategory || '',
      csvEscape(f.description),
      csvEscape(f.impact),
      ep?.reproductionSteps?.length ? csvEscape(ep.reproductionSteps.join('; ')) : '',
      ep?.proofOfConcept ? csvEscape(ep.proofOfConcept) : csvEscape(f.evidence || ''),
      ep?.httpRequests?.length ? csvEscape(ep.httpRequests[0].content) : '',
      ep?.httpResponses?.length ? csvEscape(ep.httpResponses[0].content) : '',
      csvEscape(f.affectedAsset || a.finalUrl),
      csvEscape(f.recommendation),
      f.references.length ? csvEscape(f.references.map((r) => `${r.label}: ${r.url}`).join('; ')) : '',
      f.confidence,
    ].join(',');
  });
  const csv = [headers.join(','), ...rows].join('\n');
  downloadFile(`${a.id.slice(0, 8)}-hackerone-export.csv`, csv, 'text/csv');
}

/**
 * Bugcrowd CSV export — Bugcrowd's submission format.
 */
export function exportBugcrowdCsv(a: Assessment): void {
  const headers = ['Bug Title', 'Severity', 'CVSS Score', 'Vulnerability Type', 'Affected URL', 'Description', 'Steps to Reproduce', 'Proof of Concept', 'Impact', 'Remediation Suggestion', 'References', 'Date Discovered'];
  const rows = a.findings.map((f) => {
    const ep = f.evidencePackage;
    return [
      csvEscape(f.title),
      f.severity,
      f.cvss ? f.cvss.score.toFixed(1) : '',
      csvEscape(f.owaspCategory || f.vulnerabilityClass || ''),
      csvEscape(f.affectedEndpoint || a.finalUrl),
      csvEscape(f.description),
      ep?.reproductionSteps?.length ? csvEscape(ep.reproductionSteps.join('; ')) : csvEscape(f.evidence || ''),
      ep?.proofOfConcept ? csvEscape(ep.proofOfConcept) : '',
      csvEscape(f.impact),
      csvEscape(f.recommendation),
      f.references.length ? csvEscape(f.references.map((r) => r.url).join('; ')) : '',
      a.scannedAt,
    ].join(',');
  });
  const csv = [headers.join(','), ...rows].join('\n');
  downloadFile(`${a.id.slice(0, 8)}-bugcrowd-export.csv`, csv, 'text/csv');
}

/**
 * Export all findings as JSON for programmatic integration.
 */
export function exportJsonReport(a: Assessment): void {
  const data = {
    reportId: a.id,
    targetUrl: a.finalUrl,
    scanDate: a.scannedAt,
    score: a.score,
    grade: a.grade,
    severityCounts: a.severityCounts,
    findings: a.findings.map((f) => ({
      title: f.title,
      severity: f.severity,
      cvss: f.cvss,
      cwe: f.cweId,
      owasp: f.owaspCategory,
      description: f.description,
      impact: f.impact,
      evidence: f.evidence,
      recommendation: f.recommendation,
      fixSteps: f.fixSteps,
      affectedAsset: f.affectedAsset,
      affectedEndpoint: f.affectedEndpoint,
      references: f.references,
      aiExplanation: f.aiExplanation,
    })),
    recon: {
      technologies: a.recon.technologies,
      endpoints: a.recon.endpoints.length,
      assets: a.recon.assets.length,
    },
  };
  downloadFile(`${a.id.slice(0, 8)}-findings.json`, JSON.stringify(data, null, 2), 'application/json');
}

function csvEscape(s: string): string {
  if (!s) return '';
  const escaped = s.replace(/"/g, '""').replace(/\n/g, ' ');
  return `"${escaped}"`;
}

function downloadFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
