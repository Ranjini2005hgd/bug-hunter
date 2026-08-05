import type { Finding, ScanContext, EvidencePackage, ComplianceReport, ComplianceItem, FetchResult } from './types';
import { calculateCvss, CVSS_PRESETS, OWASP_CATEGORIES } from './cvss';

// Enrich raw findings with CVSS scores, OWASP categories, evidence packages,
// confidence levels, and compliance mappings.
export function enrichFindings(findings: Finding[], ctx: ScanContext, fetch: FetchResult): Finding[] {
  return findings.map((f) => {
    const enriched = { ...f };

    // Assign CVSS if a preset exists for this rule
    const preset = CVSS_PRESETS[f.ruleId];
    if (preset && !f.cvss) {
      enriched.cvss = calculateCvss(preset);
    }

    // Assign OWASP category
    const owasp = OWASP_CATEGORIES[f.ruleId];
    if (owasp && !f.owaspCategory) {
      enriched.owaspCategory = `${owasp.code}: ${owasp.name}`;
    }

    // Set affected asset/endpoint
    if (!f.affectedAsset) {
      enriched.affectedAsset = ctx.finalUrl;
    }
    if (!f.affectedEndpoint && f.location) {
      enriched.affectedEndpoint = f.location;
    }

    // Set finding status based on confidence
    if (!f.status) {
      if (f.confidence === 'certain') enriched.status = 'confirmed';
      else if (f.confidence === 'high') enriched.status = 'confirmed';
      else if (f.confidence === 'medium') enriched.status = 'needs-verification';
      else enriched.status = 'potential';
    }

    // Set likelihood based on severity and confidence
    if (!f.likelihood) {
      if (f.severity === 'critical' || f.severity === 'high') {
        enriched.likelihood = f.confidence === 'certain' || f.confidence === 'high' ? 'high' : 'medium';
      } else {
        enriched.likelihood = 'low';
      }
    }

    // Set prerequisites
    if (!f.prerequisites) {
      if (f.category === 'security' && (f.severity === 'critical' || f.severity === 'high')) {
        enriched.prerequisites = 'Network access to the target URL. No authentication required.';
      } else if (f.category === 'accessibility') {
        enriched.prerequisites = 'A screen reader or keyboard-only navigation environment.';
      } else {
        enriched.prerequisites = 'Access to the target URL via a web browser.';
      }
    }

    // Build evidence package
    if (!f.evidencePackage) {
      enriched.evidencePackage = buildEvidencePackage(f, ctx, fetch);
    }

    // Build timeline
    if (!f.timeline) {
      enriched.timeline = buildTimeline(f, fetch.fetchedAt);
    }

    return enriched;
  });
}

function buildEvidencePackage(f: Finding, ctx: ScanContext, fetch: FetchResult): Partial<EvidencePackage> {
  const timestamp = fetch.fetchedAt;

  const httpRequest = f.location
    ? `${(f.location.startsWith('http') ? 'GET' : 'GET')} ${f.affectedEndpoint || ctx.finalUrl}\nHost: ${new URL(ctx.finalUrl).host}\nUser-Agent: BugHunter/1.0\nAccept: text/html,*/*`
    : `GET ${ctx.finalUrl}\nHost: ${new URL(ctx.finalUrl).host}\nUser-Agent: BugHunter/1.0\nAccept: text/html,*/*`;

  const httpResponse = `HTTP/${fetch.status >= 200 ? '1.1' : '1.1'} ${fetch.status} ${fetch.statusText}\n${Object.entries(fetch.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n[HTML body truncated — ${fetch.html.length} bytes received]`;

  const poc = `Precondition: ${f.prerequisites || 'Access to the target'}\n\nAction: During the security assessment, the condition "${f.title}" was identified on the target.\n\nObserved result: ${f.evidence || f.description}\n\nSecurity impact: ${f.impact}`;

  const reproductionSteps = [
    `Open ${ctx.finalUrl} in a web browser.`,
    `View the page source (Ctrl+U or right-click > View Page Source).`,
    f.evidence ? `Locate the following evidence in the source:\n${f.evidence}` : `Examine the ${f.category} properties of the page.`,
    `Confirm the finding: ${f.title}`,
  ];

  return {
    httpRequests: [{
      id: crypto.randomUUID(),
      type: 'request',
      filename: 'request.txt',
      content: httpRequest,
      mimeType: 'text/plain',
      timestamp,
    }],
    httpResponses: [{
      id: crypto.randomUUID(),
      type: 'response',
      filename: 'response.txt',
      content: httpResponse,
      mimeType: 'text/plain',
      timestamp,
    }],
    proofOfConcept: poc,
    reproductionSteps,
    metadata: {
      timestamp,
      affectedEndpoint: f.affectedEndpoint || ctx.finalUrl,
      httpMethod: 'GET',
      parameters: [],
      authState: 'unauthenticated',
      evidenceIds: [f.id],
    },
  };
}

function buildTimeline(f: Finding, fetchedAt: string): { timestamp: string; event: string; detail?: string }[] {
  return [
    { timestamp: fetchedAt, event: 'Discovery', detail: `Finding identified: ${f.title}` },
    { timestamp: fetchedAt, event: 'Classification', detail: `Severity: ${f.severity}, Confidence: ${f.confidence}` },
    ...(f.cvss ? [{ timestamp: fetchedAt, event: 'CVSS Assessment', detail: `Score: ${f.cvss.score} (${f.cvss.severity}), Vector: ${f.cvss.vector}` }] : []),
    { timestamp: fetchedAt, event: 'Evidence Collection', detail: 'HTTP request/response and proof of concept captured' },
  ];
}

// Compliance mapping — map findings to compliance control frameworks
export function buildComplianceReport(findings: Finding[]): ComplianceReport {
  return {
    gdpr: mapGdpr(findings),
    pciDss: mapPciDss(findings),
    hipaa: mapHipaa(findings),
    iso27001: mapIso27001(findings),
  };
}

function mapGdpr(findings: Finding[]): ComplianceItem[] {
  const items: ComplianceItem[] = [];
  const securityFindings = findings.filter((f) => f.category === 'security');

  items.push({
    control: 'Article 32 — Security of processing',
    status: securityFindings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'fail' : securityFindings.length > 0 ? 'warning' : 'pass',
    description: 'Implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.',
    finding: securityFindings.find((f) => f.severity === 'critical')?.title,
  });

  const hasEncryptionIssue = findings.some((f) => ['no-https', 'mixed-content', 'missing-hsts'].includes(f.ruleId));
  items.push({
    control: 'Article 32(1)(a) — Encryption',
    status: hasEncryptionIssue ? 'fail' : 'pass',
    description: 'Pseudonymisation and encryption of personal data where appropriate.',
    finding: hasEncryptionIssue ? 'Transport encryption (HTTPS/HSTS) not properly configured' : undefined,
  });

  const hasXssRisk = findings.some((f) => ['missing-csp', 'inline-event-handlers', 'inline-scripts', 'javascript-urls', 'eval-document-write'].includes(f.ruleId));
  items.push({
    control: 'Article 5(1)(f) — Integrity and confidentiality',
    status: hasXssRisk ? 'fail' : 'pass',
    description: 'Personal data shall be processed in a manner ensuring appropriate security including protection against unauthorized processing.',
    finding: hasXssRisk ? 'XSS prevention controls (CSP) missing' : undefined,
  });

  return items;
}

function mapPciDss(findings: Finding[]): ComplianceItem[] {
  const items: ComplianceItem[] = [];

  const hasEncryptionIssue = findings.some((f) => ['no-https', 'mixed-content', 'missing-hsts'].includes(f.ruleId));
  items.push({
    control: 'Requirement 4 — Encrypt transmission of cardholder data',
    status: hasEncryptionIssue ? 'fail' : 'pass',
    description: 'Cardholder data must be encrypted during transmission over open, public networks.',
    finding: hasEncryptionIssue ? 'HTTPS not enforced or mixed content present' : undefined,
  });

  const hasXssRisk = findings.some((f) => ['missing-csp', 'inline-event-handlers', 'inline-scripts', 'javascript-urls'].includes(f.ruleId));
  items.push({
    control: 'Requirement 6.5.7 — Cross-site scripting',
    status: hasXssRisk ? 'fail' : 'pass',
    description: 'Address common coding vulnerabilities in software development processes including XSS.',
    finding: hasXssRisk ? 'XSS prevention controls not in place' : undefined,
  });

  const hasCsrfIssue = findings.some((f) => f.ruleId === 'missing-csrf-token');
  items.push({
    control: 'Requirement 6.5.9 — Cross-site request forgery',
    status: hasCsrfIssue ? 'fail' : 'pass',
    description: 'Address common coding vulnerabilities including CSRF.',
    finding: hasCsrfIssue ? 'CSRF token not detected on authentication forms' : undefined,
  });

  const hasInfoDisclosure = findings.some((f) => ['server-version-disclosure', 'x-powered-by-disclosure'].includes(f.ruleId));
  items.push({
    control: 'Requirement 2.2.2 — Disable unnecessary services',
    status: hasInfoDisclosure ? 'warning' : 'pass',
    description: 'Configuration standards should minimize system services and protocols.',
    finding: hasInfoDisclosure ? 'Server version information disclosed in headers' : undefined,
  });

  return items;
}

function mapHipaa(findings: Finding[]): ComplianceItem[] {
  const items: ComplianceItem[] = [];

  const hasEncryptionIssue = findings.some((f) => ['no-https', 'mixed-content'].includes(f.ruleId));
  items.push({
    control: '164.312(a)(2)(iv) — Encryption and decryption',
    status: hasEncryptionIssue ? 'fail' : 'pass',
    description: 'Implement a mechanism to encrypt and decrypt electronic protected health information (ePHI).',
    finding: hasEncryptionIssue ? 'Data transmitted without encryption (no HTTPS)' : undefined,
  });

  const hasAuthIssue = findings.some((f) => ['insecure-cookie', 'missing-csrf-token', 'form-get-password'].includes(f.ruleId));
  items.push({
    control: '164.312(d) — Person or entity authentication',
    status: hasAuthIssue ? 'fail' : 'pass',
    description: 'Implement procedures to verify that a person seeking access to ePHI is the one claimed.',
    finding: hasAuthIssue ? 'Authentication mechanisms have security weaknesses' : undefined,
  });

  const hasAuditIssue = findings.some((f) => ['server-version-disclosure', 'exposed-email'].includes(f.ruleId));
  items.push({
    control: '164.312(b) — Audit controls',
    status: hasAuditIssue ? 'warning' : 'pass',
    description: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity.',
    finding: hasAuditIssue ? 'Information disclosure may compromise audit integrity' : undefined,
  });

  return items;
}

function mapIso27001(findings: Finding[]): ComplianceItem[] {
  const items: ComplianceItem[] = [];

  const hasTransportIssue = findings.some((f) => ['no-https', 'missing-hsts'].includes(f.ruleId));
  items.push({
    control: 'A.8.24 — Cryptography',
    status: hasTransportIssue ? 'fail' : 'pass',
    description: 'Cryptographic controls should be used to protect confidentiality, integrity, and authenticity.',
    finding: hasTransportIssue ? 'Transport layer encryption not enforced' : undefined,
  });

  const hasAppSecIssue = findings.filter((f) => f.category === 'security').length > 3;
  items.push({
    control: 'A.8.25 — Secure development life cycle',
    status: hasAppSecIssue ? 'fail' : 'pass',
    description: 'Security should be designed and implemented within the development life cycle.',
    finding: hasAppSecIssue ? 'Multiple security vulnerabilities detected indicating insufficient secure development practices' : undefined,
  });

  const hasInfoDisclosure = findings.some((f) => ['server-version-disclosure', 'x-powered-by-disclosure', 'exposed-email'].includes(f.ruleId));
  items.push({
    control: 'A.5.12 — Classification of information',
    status: hasInfoDisclosure ? 'warning' : 'pass',
    description: 'Information should be classified based on its security needs.',
    finding: hasInfoDisclosure ? 'Sensitive information (server version, email) exposed' : undefined,
  });

  const hasXss = findings.some((f) => ['missing-csp', 'inline-scripts', 'javascript-urls'].includes(f.ruleId));
  items.push({
    control: 'A.8.28 — Secure coding',
    status: hasXss ? 'fail' : 'pass',
    description: 'Secure coding principles should be applied to software development.',
    finding: hasXss ? 'XSS prevention controls not implemented' : undefined,
  });

  return items;
}
