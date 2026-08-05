import type { CvssVector, CvssResult, Severity } from './types';

// CVSS 3.1 specification implementation
// https://www.first.org/cvss/v3.1/specification-document

const METRIC_VALUES: Record<keyof CvssVector, Record<string, number>> = {
  attackVector: { network: 0.85, adjacent: 0.62, local: 0.55, physical: 0.2 },
  attackComplexity: { low: 0.77, high: 0.44 },
  privilegesRequired: { none: 0.85, low: 0.62, high: 0.27 },
  userInteraction: { none: 0.85, required: 0.62 },
  scope: { unchanged: 0, changed: 0 },
  confidentiality: { none: 0, low: 0.22, high: 0.56 },
  integrity: { none: 0, low: 0.22, high: 0.56 },
  availability: { none: 0, low: 0.22, high: 0.56 },
};

// Modified privilege weights when scope is changed
const PR_CHANGED = { none: 0.85, low: 0.68, high: 0.5 };

export function calculateCvss(v: CvssVector): CvssResult {
  const av = METRIC_VALUES.attackVector[v.attackVector];
  const ac = METRIC_VALUES.attackComplexity[v.attackComplexity];
  const pr = v.scope === 'changed' ? PR_CHANGED[v.privilegesRequired] : METRIC_VALUES.privilegesRequired[v.privilegesRequired];
  const ui = METRIC_VALUES.userInteraction[v.userInteraction];
  const c = METRIC_VALUES.confidentiality[v.confidentiality];
  const i = METRIC_VALUES.integrity[v.integrity];
  const a = METRIC_VALUES.availability[v.availability];

  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = v.scope === 'changed' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;

  const exploitability = 8.22 * av * ac * pr * ui;
  const baseScore = v.scope === 'changed'
    ? Math.min(10, roundup(1.08 * (impact + exploitability)))
    : Math.min(10, roundup(impact + exploitability));

  const vector = `CVSS:3.1/AV:${v.attackVector[0].toUpperCase()}/AC:${v.attackComplexity[0].toUpperCase()}/PR:${v.privilegesRequired[0].toUpperCase()}/UI:${v.userInteraction[0].toUpperCase()}/S:${v.scope === 'changed' ? 'C' : 'U'}/C:${v.confidentiality[0].toUpperCase()}/I:${v.integrity[0].toUpperCase()}/A:${v.availability[0].toUpperCase()}`;

  return {
    score: baseScore,
    severity: scoreToSeverity(baseScore),
    vector,
  };
}

function roundup(value: number): number {
  return Math.ceil(value * 10) / 10;
}

function scoreToSeverity(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

// Preset CVSS vectors for common vulnerability patterns
export const CVSS_PRESETS: Record<string, CvssVector> = {
  noHttps: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'none',
    scope: 'unchanged',
    confidentiality: 'high',
    integrity: 'high',
    availability: 'high',
  },
  missingCsp: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'required',
    scope: 'changed',
    confidentiality: 'low',
    integrity: 'low',
    availability: 'none',
  },
  missingXfo: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'required',
    scope: 'unchanged',
    confidentiality: 'low',
    integrity: 'low',
    availability: 'none',
  },
  xss: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'required',
    scope: 'changed',
    confidentiality: 'low',
    integrity: 'low',
    availability: 'none',
  },
  insecureCookie: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'none',
    scope: 'unchanged',
    confidentiality: 'high',
    integrity: 'high',
    availability: 'none',
  },
  missingCsrf: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'required',
    scope: 'unchanged',
    confidentiality: 'low',
    integrity: 'high',
    availability: 'none',
  },
  mixedContent: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'none',
    scope: 'unchanged',
    confidentiality: 'low',
    integrity: 'low',
    availability: 'none',
  },
  openRedirect: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'required',
    scope: 'changed',
    confidentiality: 'none',
    integrity: 'low',
    availability: 'none',
  },
  missingSri: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'none',
    scope: 'changed',
    confidentiality: 'low',
    integrity: 'low',
    availability: 'none',
  },
  infoDisclosure: {
    attackVector: 'network',
    attackComplexity: 'low',
    privilegesRequired: 'none',
    userInteraction: 'none',
    scope: 'unchanged',
    confidentiality: 'low',
    integrity: 'none',
    availability: 'none',
  },
};

// OWASP Top 10 (2021) category mapping
export const OWASP_CATEGORIES: Record<string, { code: string; name: string }> = {
  'no-https': { code: 'A02', name: 'Cryptographic Failures' },
  'mixed-content': { code: 'A02', name: 'Cryptographic Failures' },
  'missing-hsts': { code: 'A02', name: 'Cryptographic Failures' },
  'hsts-short-maxage': { code: 'A02', name: 'Cryptographic Failures' },
  'missing-csp': { code: 'A03', name: 'Injection' },
  'inline-event-handlers': { code: 'A03', name: 'Injection' },
  'inline-scripts': { code: 'A03', name: 'Injection' },
  'javascript-urls': { code: 'A03', name: 'Injection' },
  'eval-document-write': { code: 'A03', name: 'Injection' },
  'missing-xfo': { code: 'A05', name: 'Security Misconfiguration' },
  'missing-xcto': { code: 'A05', name: 'Security Misconfiguration' },
  'missing-referrer-policy': { code: 'A05', name: 'Security Misconfiguration' },
  'missing-permissions-policy': { code: 'A05', name: 'Security Misconfiguration' },
  'server-version-disclosure': { code: 'A05', name: 'Security Misconfiguration' },
  'x-powered-by-disclosure': { code: 'A05', name: 'Security Misconfiguration' },
  'insecure-cookie': { code: 'A05', name: 'Security Misconfiguration' },
  'missing-csrf-token': { code: 'A01', name: 'Broken Access Control' },
  'missing-sri': { code: 'A08', name: 'Software and Data Integrity Failures' },
  'missing-noopener': { code: 'A01', name: 'Broken Access Control' },
  'meta-refresh-redirect': { code: 'A01', name: 'Broken Access Control' },
  'exposed-email': { code: 'A04', name: 'Insecure Design' },
  'password-autocomplete': { code: 'A07', name: 'Identification and Authentication Failures' },
  'form-get-password': { code: 'A07', name: 'Identification and Authentication Failures' },
};
