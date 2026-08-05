import type {
  ScanContext,
  SubdomainResult,
  SecretFinding,
  JsAnalysisResult,
  JsFileAnalysis,
  DirectoryScanResult,
  Severity,
} from './types';

function uuid(): string {
  return crypto.randomUUID();
}

// ============================================================
// SUBDOMAIN ENUMERATION via Certificate Transparency logs (crt.sh)
// ============================================================

export async function enumerateSubdomains(targetUrl: string): Promise<SubdomainResult[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return [];
  }

  const rootDomain = getRootDomain(hostname);
  if (!rootDomain) return [];

  const subdomains: Map<string, SubdomainResult> = new Map();
  subdomains.set(hostname, {
    id: uuid(),
    hostname,
    source: 'user-input',
    open: true,
  });

  // Query crt.sh Certificate Transparency logs
  try {
    const resp = await fetch(`https://crt.sh/?q=%25.${rootDomain}&output=json`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    if (resp.ok) {
      const data = await resp.json() as Array<{ name_value?: string; common_name?: string }>;
      const names = new Set<string>();
      for (const entry of data) {
        const name = entry.name_value || entry.common_name || '';
        // CT logs can contain multiple domains separated by newlines
        for (const n of name.split('\n')) {
          const trimmed = n.trim().toLowerCase();
          if (trimmed && trimmed.endsWith(rootDomain) && !trimmed.startsWith('*.')) {
            names.add(trimmed);
          }
        }
      }
      for (const name of names) {
        if (!subdomains.has(name)) {
          subdomains.set(name, {
            id: uuid(),
            hostname: name,
            source: 'crt.sh',
            open: true,
          });
        }
      }
    }
  } catch {
    // crt.sh may be unreachable from the browser — that's OK
  }

  // Add common subdomain guesses
  const commonSubs = ['www', 'mail', 'admin', 'api', 'dev', 'staging', 'test', 'beta', 'app', 'blog', 'shop', 'portal', 'vpn', 'git', 'ci', 'jenkins', 'grafana', 'kibana', 'internal', 'secure', 'login', 'sso', 'cdn', 'static', 'assets', 'img', 'media'];
  for (const sub of commonSubs) {
    const candidate = `${sub}.${rootDomain}`;
    if (!subdomains.has(candidate)) {
      subdomains.set(candidate, {
        id: uuid(),
        hostname: candidate,
        source: 'common-guess',
        open: false,
      });
    }
  }

  // Try DNS resolution for discovered subdomains via DNS-over-HTTPS
  const results = Array.from(subdomains.values());
  await Promise.all(results.slice(0, 30).map(async (sub) => {
    if (sub.source === 'user-input') return;
    try {
      const dohResp = await fetch(`https://dns.google/resolve?name=${sub.hostname}&type=A`);
      if (dohResp.ok) {
        const dohData = await dohResp.json() as { Answer?: Array<{ data: string; type: number }> };
        if (dohData.Answer && dohData.Answer.length > 0) {
          const aRecord = dohData.Answer.find((a) => a.type === 1);
          if (aRecord) {
            sub.ip = aRecord.data;
            sub.open = true;
          }
        }
      }
    } catch {
      // DNS-over-HTTPS may fail — that's fine
    }
  }));

  return results;
}

function getRootDomain(hostname: string): string {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  // Handle common TLDs like co.uk, com.au
  const tld = parts.slice(-2).join('.');
  const commonMultiPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'com.sg', 'com.hk'];
  if (commonMultiPartTlds.includes(tld)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// ============================================================
// JAVASCRIPT ANALYSIS — endpoint & secret extraction
// ============================================================

const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp; severity: Severity; description: string }> = [
  { type: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', description: 'AWS Access Key ID found in JavaScript' },
  { type: 'AWS Secret Key', pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, severity: 'critical', description: 'Potential AWS Secret Access Key (40-char base64)' },
  { type: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high', description: 'Google API Key found in JavaScript' },
  { type: 'Stripe Live Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical', description: 'Stripe Live Secret Key found in JavaScript' },
  { type: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'medium', description: 'Stripe Live Publishable Key found in JavaScript' },
  { type: 'GitHub Token', pattern: /gh[pousr]_[0-9A-Za-z]{36,}/g, severity: 'critical', description: 'GitHub Personal Access Token found in JavaScript' },
  { type: 'Slack Token', pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'high', description: 'Slack Token found in JavaScript' },
  { type: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high', description: 'JWT Token found in JavaScript' },
  { type: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----/g, severity: 'critical', description: 'Private key block found in JavaScript' },
  { type: 'Generic API Key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/gi, severity: 'high', description: 'Generic API key/secret found in JavaScript' },
  { type: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/g, severity: 'high', description: 'Bearer authentication token found in JavaScript' },
  { type: 'Firebase URL', pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g, severity: 'medium', description: 'Firebase database URL found in JavaScript' },
  { type: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/gi, severity: 'critical', description: 'Database connection string with credentials found in JavaScript' },
  { type: 'Facebook App ID', pattern: /fb(?:app)?[_-]?id\s*[:=]\s*['"]?\d{15,}['"]?/gi, severity: 'low', description: 'Facebook App ID found in JavaScript' },
  { type: 'Twilio Account SID', pattern: /AC[a-z0-9]{32}/g, severity: 'high', description: 'Twilio Account SID found in JavaScript' },
];

const ENDPOINT_PATTERNS: RegExp[] = [
  /["'`](\/api\/[a-z0-9_\-\/{}.:]+)["'`]/gi,
  /["'`](\/v[0-9]+\/[a-z0-9_\-\/{}.:]+)["'`]/gi,
  /["'`](\/graphql)["'`]/gi,
  /["'`](\/rest\/[a-z0-9_\-\/{}.:]+)["'`]/gi,
  /fetch\(\s*["'`]([^"'`]+)["'`]/gi,
  /axios\.[a-z]+\(\s*["'`]([^"'`]+)["'`]/gi,
  /XMLHttpRequest[^;]*open\(\s*["'`][A-Z]+["'`],\s*["'`]([^"'`]+)["'`]/gi,
];

const FRAMEWORK_SIGNATURES: Array<{ name: string; pattern: RegExp }> = [
  { name: 'React', pattern: /react|createElement|useState|useEffect|jsx/i },
  { name: 'Vue', pattern: /vue|createApp|defineComponent|__vue/i },
  { name: 'Angular', pattern: /angular|@Component|NgModule|platformBrowser/i },
  { name: 'Next.js', pattern: /__NEXT_DATA__|_next\/static|next\/router/i },
  { name: 'Nuxt', pattern: /__NUXT__|_nuxt\//i },
  { name: 'Svelte', pattern: /svelte|__sveltekit/i },
  { name: 'jQuery', pattern: /jquery|jQuery|\$\(/i },
  { name: 'Axios', pattern: /axios/i },
  { name: 'Lodash', pattern: /lodash|_\./i },
  { name: 'Moment.js', pattern: /moment\.|moment\(/i },
  { name: 'Chart.js', pattern: /chart\.js|Chart\(/i },
  { name: 'GSAP', pattern: /gsap|TweenMax|TimelineMax/i },
  { name: 'Three.js', pattern: /three\.|THREE\./i },
  { name: 'Socket.io', pattern: /socket\.io|io\(/i },
  { name: 'Webpack', pattern: /webpack|__webpack_require__/i },
  { name: 'Google Analytics', pattern: /google-analytics|gtag|UA-\d+/i },
  { name: 'Sentry', pattern: /sentry|@sentry/i },
  { name: 'Stripe', pattern: /stripe|pk_live_|pk_test_/i },
];

export async function analyzeJavaScript(ctx: ScanContext): Promise<JsAnalysisResult> {
  // Extract JS file URLs from the document
  const jsFiles = Array.from(ctx.document.querySelectorAll('script[src]'))
    .map((s) => {
      try { return new URL(s.getAttribute('src') || '', ctx.finalUrl).href; } catch { return ''; }
    })
    .filter(Boolean);
  const fileAnalyses: JsFileAnalysis[] = [];
  const allEndpoints = new Set<string>();
  const allSecrets: SecretFinding[] = [];

  // Analyze inline scripts
  const inlineScripts = Array.from(ctx.document.querySelectorAll('script:not([src])'))
    .map((s) => s.textContent || '')
    .filter((t) => t.length > 10);

  for (const script of inlineScripts) {
    const secrets = findSecrets(script, 'inline-script');
    const endpoints = findEndpoints(script, ctx.finalUrl);
    const frameworks = detectJsFrameworks(script);
    allSecrets.push(...secrets);
    endpoints.forEach((e) => allEndpoints.add(e));
    if (secrets.length > 0 || endpoints.length > 0 || frameworks.length > 0) {
      fileAnalyses.push({
        url: 'inline-script',
        size: script.length,
        hasSourceMap: false,
        frameworks,
        endpoints,
        secrets,
      });
    }
  }

  // Fetch and analyze external JS files (limited to first 15)
  for (const jsUrl of jsFiles.slice(0, 15)) {
    try {
      const resp = await fetch(jsUrl);
      if (!resp.ok) continue;
      const text = await resp.text();
      if (text.length < 10) continue;

      const secrets = findSecrets(text, jsUrl);
      const endpoints = findEndpoints(text, ctx.finalUrl);
      const frameworks = detectJsFrameworks(text);
      const hasSourceMap = resp.headers.get('SourceMap') !== null || text.includes('//# sourceMappingURL');

      allSecrets.push(...secrets);
      endpoints.forEach((e) => allEndpoints.add(e));

      fileAnalyses.push({
        url: jsUrl,
        size: text.length,
        hasSourceMap,
        frameworks,
        endpoints,
        secrets,
      });
    } catch {
      // CORS may block fetching external JS — that's OK
    }
  }

  return {
    files: fileAnalyses,
    totalFiles: jsFiles.length,
    totalSize: fileAnalyses.reduce((sum, f) => sum + f.size, 0),
    endpoints: Array.from(allEndpoints),
    secrets: allSecrets,
  };
}

function findSecrets(code: string, file: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const { type, pattern, severity, description } of SECRET_PATTERNS) {
    const matches = code.matchAll(pattern);
    for (const match of matches) {
      const value = match[0];
      if (!value || value.length < 5) continue;
      // Calculate approximate line number
      const line = code.slice(0, match.index || 0).split('\n').length;
      findings.push({
        id: uuid(),
        type,
        value: value.slice(0, 60) + (value.length > 60 ? '...' : ''),
        file,
        line,
        severity,
        description,
      });
    }
  }
  return findings;
}

function findEndpoints(code: string, baseUrl: string): string[] {
  const endpoints = new Set<string>();
  for (const pattern of ENDPOINT_PATTERNS) {
    const matches = code.matchAll(pattern);
    for (const match of matches) {
      const ep = match[1] || match[0];
      if (!ep || ep.length < 2) continue;
      try {
        const resolved = new URL(ep, baseUrl).href;
        endpoints.add(resolved);
      } catch {
        if (ep.startsWith('/')) endpoints.add(ep);
      }
    }
  }
  return Array.from(endpoints).slice(0, 30);
}

function detectJsFrameworks(code: string): string[] {
  const found: string[] = [];
  for (const { name, pattern } of FRAMEWORK_SIGNATURES) {
    if (pattern.test(code) && !found.includes(name)) {
      found.push(name);
    }
  }
  return found;
}

// ============================================================
// DIRECTORY BRUTE-FORCING — probe common paths
// ============================================================

const INTERESTING_PATHS: string[] = [
  // Admin panels
  '/admin', '/admin/', '/administrator', '/admin.php', '/admin.html', '/wp-admin/', '/wp-admin/admin-ajax.php',
  '/manager', '/panel', '/dashboard', '/cpanel', '/phpmyadmin', '/adminer', '/wp-login.php',
  // Config files
  '/.env', '/.env.local', '/.env.production', '/config.php', '/config.json', '/config.yml', '/configuration.php',
  '/wp-config.php', '/settings.php', '/settings.json', '/.htconfig', '/appsettings.json',
  // Backup files
  '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql', '/dump.sql',
  '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/store',
  // API endpoints
  '/api', '/api/', '/api/v1', '/api/v2', '/api/users', '/api/admin', '/graphql', '/rest',
  // Sensitive files
  '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
  '/web.config', '/server-status', '/server-info', '/.well-known/security.txt',
  // Common frameworks
  '/wp-content/', '/wp-includes/', '/vendor/', '/node_modules/', '/composer.json', '/package.json',
  '/Gemfile', '/requirements.txt', '/Dockerfile', '/docker-compose.yml',
  // Auth pages
  '/login', '/login.php', '/signin', '/register', '/signup', '/auth', '/oauth',
  // Upload
  '/upload', '/uploads', '/upload.php', '/files', '/media',
  // Debug
  '/debug', '/debugbar', '/_debug', '/__debug', '/trace', '/console', '/actuator', '/actuator/health',
  '/actuator/env', '/actuator/heapdump', '/metrics', '/prometheus',
  // Info disclosure
  '/phpinfo.php', '/phpinfo', '/info.php', '/test.php', '/.gitignore', '/.dockerenv',
  '/swagger-ui', '/swagger-ui.html', '/api-docs', '/openapi.json', '/api/swagger.json',
  // Misc
  '/.DS_Store', '/Thumbs.db', '/error', '/500', '/404', '/403',
];

export async function bruteForceDirectories(targetUrl: string): Promise<DirectoryScanResult[]> {
  let baseUrl: string;
  try {
    const u = new URL(targetUrl);
    baseUrl = `${u.protocol}//${u.host}`;
  } catch {
    return [];
  }

  const results: DirectoryScanResult[] = [];
  const BATCH_SIZE = 10;

  for (let i = 0; i < INTERESTING_PATHS.length; i += BATCH_SIZE) {
    const batch = INTERESTING_PATHS.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(async (path) => {
      const url = `${baseUrl}${path}`;
      try {
        const resp = await fetch(url, { method: 'GET', redirect: 'manual', mode: 'cors' });
        const status = resp.status;
        const redirect = status === 0 || status >= 300 && status < 400;
        const interesting = status === 200 || status === 401 || status === 403 || (status >= 300 && status < 400);
        const contentType = resp.headers.get('content-type') || undefined;
        let redirectUrl: string | undefined;
        if (redirect) {
          redirectUrl = resp.headers.get('location') || undefined;
        }
        const size = parseInt(resp.headers.get('content-length') || '0', 10);
        return {
          path,
          url,
          status: status === 0 ? 0 : status,
          size,
          redirect,
          redirectUrl,
          contentType,
          interesting,
        } as DirectoryScanResult;
      } catch {
        // CORS or network error — mark as unknown
        return {
          path,
          url,
          status: 0,
          size: 0,
          redirect: false,
          interesting: false,
        } as DirectoryScanResult;
      }
    }));
    results.push(...batchResults);
  }

  return results;
}

// ============================================================
// AI VULNERABILITY EXPLANATION GENERATOR
// ============================================================

export interface AiExplanation {
  summary: string;
  attackScenario: string;
  remediationPriority: string;
  businessRisk: string;
  testingAdvice: string;
}

export function generateAiExplanation(params: {
  title: string;
  description: string;
  severity: Severity;
  impact: string;
  cweId?: string;
  owaspCategory?: string;
  vulnerabilityClass?: string;
}): AiExplanation {
  const { title, description, severity, impact, cweId, owaspCategory, vulnerabilityClass } = params;

  const severityText: Record<Severity, string> = {
    critical: 'This is a critical vulnerability that should be treated as a P1 incident. Immediate remediation is required — ideally within 24 hours of discovery. An attacker can exploit this to achieve full system compromise, data exfiltration, or service disruption.',
    high: 'This is a high-severity vulnerability that poses a significant risk. It should be remediated within one week. An attacker can leverage this to gain unauthorized access, escalate privileges, or access sensitive data.',
    medium: 'This is a medium-severity vulnerability that presents a moderate risk. It should be addressed in the current development cycle. Exploitation requires specific conditions or user interaction, but the impact is still meaningful.',
    low: 'This is a low-severity issue that represents a minor security weakness. It should be addressed when feasible but does not pose an immediate threat. It may be useful as part of a chain of vulnerabilities.',
    info: 'This is an informational finding that does not represent a direct security vulnerability. It highlights a configuration or practice that could be improved to strengthen the overall security posture.',
  };

  const vulnClassText: Record<string, string> = {
    'remote-code-execution': 'Remote Code Execution (RCE) is one of the most severe vulnerability classes. It allows an attacker to execute arbitrary code on the server, leading to complete system compromise. Attackers can install backdoors, exfiltrate all data, pivot to internal networks, and persist their access indefinitely.',
    'sql-injection': 'SQL Injection allows an attacker to manipulate database queries by injecting malicious SQL code. This can lead to complete database compromise, authentication bypass, data exfiltration, and in some cases, remote code execution via database functions like xp_cmdshell or COPY TO.',
    'xss-stored': 'Stored XSS is particularly dangerous because the payload persists on the server and executes for every user who views the affected page. This enables mass session theft, credential harvesting, and worm-like propagation.',
    'xss-reflected': 'Reflected XSS requires the victim to click a crafted link, but it can be weaponized via phishing or social engineering. It enables session token theft, credential harvesting via fake login forms, and browser exploitation.',
    'account-takeover': 'Account takeover vulnerabilities allow an attacker to fully compromise a user account without authorization. This gives access to all the victim\'s data, settings, and permissions, and can be used as a stepping stone to attack other users or admin functions.',
    'idor': 'Insecure Direct Object Reference (IDOR) is a broken access control vulnerability that allows accessing other users\' data by manipulating identifiers. It is one of the most common and impactful vulnerability classes in bug bounty programs, often exposing large volumes of sensitive data.',
    'payment-bypass': 'Payment bypass vulnerabilities allow an attacker to circumvent the payment mechanism — purchasing items for free, at a fraction of the cost, or receiving refunds illegitimately. This causes direct financial loss and can be exploited at scale.',
    'security-misconfiguration': 'Security misconfigurations are a broad class covering default credentials, verbose error messages, unnecessary enabled features, and missing security headers. While individual findings may seem minor, they collectively create a significant attack surface.',
    'information-disclosure': 'Information disclosure vulnerabilities expose sensitive data such as internal paths, software versions, credentials, or user data. This information aids attackers in crafting targeted attacks and should always be minimized.',
  };

  const classText = vulnerabilityClass ? vulnClassText[vulnerabilityClass] || '' : '';

  const attackScenarios: Record<Severity, string> = {
    critical: `Attack Scenario: An attacker discovers this vulnerability during reconnaissance. By crafting a specific payload targeting the ${vulnerabilityClass || 'affected component'}, they achieve ${impact.toLowerCase().includes('code execution') ? 'remote code execution' : 'unauthorized access'}. From there, they can pivot to internal systems, exfiltrate the database, install persistent backdoors, and potentially move laterally across the entire infrastructure. The time from discovery to full compromise can be minutes.`,
    high: `Attack Scenario: An attacker identifies this vulnerability and crafts an exploit that leverages it to ${impact.split('.')[0].toLowerCase()}. The exploit may require some reconnaissance or user interaction, but once successful, the attacker gains significant unauthorized access or can manipulate application behavior to their advantage.`,
    medium: `Attack Scenario: An attacker would need specific preconditions to exploit this vulnerability — such as an authenticated session, a particular application state, or user interaction. Once those conditions are met, they can leverage the issue to gain elevated access or access data beyond their authorization level.`,
    low: `Attack Scenario: Exploiting this issue alone has limited impact. However, an attacker could chain it with other vulnerabilities to increase the severity. For example, the information leaked could be used to craft more targeted attacks against higher-severity vulnerabilities.`,
    info: `Attack Scenario: This finding does not have a direct exploitation path. However, it indicates a security practice or configuration that could be improved. Addressing it contributes to defense-in-depth and reduces the overall attack surface.`,
  };

  const priorities: Record<Severity, string> = {
    critical: 'P1 — Fix immediately (within 24 hours). Deploy a hotfix and conduct a full incident response investigation to determine if the vulnerability has already been exploited.',
    high: 'P2 — Fix within one week. Prioritize this in the current sprint and deploy a patch as soon as possible. Monitor for active exploitation attempts in the meantime.',
    medium: 'P3 — Fix in the current development cycle. Schedule the fix for the next release and track it in the issue tracker.',
    low: 'P4 — Fix when feasible. Add to the technical debt backlog and address during routine maintenance.',
    info: 'P5 — No immediate action required. Consider addressing as part of continuous security improvement.',
  };

  const businessRisks: Record<Severity, string> = {
    critical: 'Business Risk: Critical vulnerabilities can lead to full data breaches, regulatory fines (GDPR, CCPA), reputational damage, loss of customer trust, and legal liability. If exploited, the financial impact can reach millions of dollars. This finding may require disclosure to regulators and affected users.',
    high: 'Business Risk: High-severity vulnerabilities can lead to unauthorized data access, service disruption, and compliance violations. The reputational damage from a public exploit can be significant. Prompt remediation is essential to maintain customer trust.',
    medium: 'Business Risk: Medium vulnerabilities may not lead to immediate breach but contribute to the overall risk profile. If chained with other issues, they can enable more serious attacks. Addressing them demonstrates due diligence in security practices.',
    low: 'Business Risk: Low-severity findings have minimal direct business impact but addressing them improves the overall security posture and demonstrates attention to security detail, which is valued by security-conscious customers.',
    info: 'Business Risk: Informational findings have no direct business risk. Addressing them contributes to security maturity and may be required by compliance frameworks as evidence of continuous improvement.',
  };

  const testingAdvice = `Testing Advice: To verify this finding, ${cweId ? `refer to the ${cweId} testing guide. ` : ''}Start by reproducing the issue in a controlled environment. Document each step with screenshots and HTTP captures. Test for variations — different input vectors, encoding bypasses, and edge cases. If this is a logic vulnerability, test with different user roles and permission levels. Always test within the authorized scope and never access or modify data that is not your own.${owaspCategory ? ` This finding maps to OWASP ${owaspCategory}.` : ''}`;

  return {
    summary: `${severityText[severity]} ${classText} ${description}`,
    attackScenario: attackScenarios[severity],
    remediationPriority: priorities[severity],
    businessRisk: businessRisks[severity],
    testingAdvice,
  };
}
