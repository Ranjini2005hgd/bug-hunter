import type { Checker, Finding, ScanContext } from '../types';

function getMeta(ctx: ScanContext, name: string): string | null {
  const el = ctx.document.querySelector(`meta[name="${name}"], meta[property="${name}"]`);
  return el?.getAttribute('content')?.trim() || null;
}

function hasHeader(ctx: ScanContext, name: string): boolean {
  return name.toLowerCase() in ctx.headers;
}

function headerValue(ctx: ScanContext, name: string): string {
  return ctx.headers[name.toLowerCase()] || '';
}

export const checkSecurity: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc, headers, isHttps } = ctx;

  // 1. HTTPS / mixed content
  if (!isHttps) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'no-https',
      category: 'security',
      severity: 'critical',
      title: 'Site served over unencrypted HTTP',
      description:
        'The page is delivered over plain HTTP instead of HTTPS. All traffic — including passwords, session cookies, and personal data — is transmitted in cleartext and can be read or modified by anyone on the network path.',
      impact:
        'Man-in-the-middle attacks can steal credentials, hijack sessions, inject malware into pages, and break user trust. Modern browsers mark HTTP sites as "Not Secure."',
      recommendation:
        'Provision an TLS certificate (e.g. via Let\u2019s Encrypt), redirect all HTTP requests to HTTPS, and enable HSTS.',
      fixSteps: [
        'Obtain a TLS certificate from a certificate authority such as Let\u2019s Encrypt (free).',
        'Configure your web server to serve the site exclusively over HTTPS on port 443.',
        'Add a permanent 301 redirect from the http:// host to the https:// equivalent.',
        'Enable HTTP Strict Transport Security (HSTS) with a long max-age once HTTPS is confirmed working.',
      ],
      codeBefore: 'http://example.com  (unencrypted)',
      codeAfter: 'https://example.com  + 301 redirect from http + HSTS header',
      references: [
        { label: 'OWASP Transport Layer Protection Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html' },
        { label: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org/' },
      ],
      cweId: 'CWE-319',
      confidence: 'certain',
    });
  }

  // Mixed-content: http:// subresources on an https page
  if (isHttps) {
    const insecure = Array.from(
      doc.querySelectorAll('script[src^="http://"], img[src^="http://"], link[href^="http://"], iframe[src^="http://"], video[src^="http://"], audio[src^="http://"], source[src^="http://"], embed[src^="http://"]'),
    ).slice(0, 5);
    if (insecure.length) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'mixed-content',
        category: 'security',
        severity: 'high',
        title: 'Mixed content: insecure resources loaded over HTTPS page',
        description:
          'The page is loaded over HTTPS but references scripts, images, stylesheets, or frames over plain HTTP. Browsers block or degrade these resources, and active mixed content (scripts) can be tampered with.',
        evidence: insecure.map((el) => el.getAttribute('src') || el.getAttribute('href') || '').filter(Boolean).join('\n'),
        impact:
          'Active mixed content (scripts, stylesheets, iframes) is blocked by modern browsers, breaking functionality. Passive mixed content (images) triggers warnings and degrades trust.',
        recommendation:
          'Update every subresource URL from http:// to https:// or use protocol-relative paths. Modern browsers refuse to load active mixed content entirely.',
        fixSteps: [
          'Search the HTML and source code for src="http://" and href="http://" references.',
          'Replace each with the https:// equivalent or a protocol-relative //host/path form.',
          'Add a Content-Security-Policy: upgrade-insecure-requests directive to auto-upgrade legacy URLs.',
          'Test with browser devtools \u2014 the Console and Security tabs flag any remaining mixed content.',
        ],
        codeBefore: '<script src="http://cdn.example.com/lib.js"></script>',
        codeAfter: '<script src="https://cdn.example.com/lib.js"></script>',
        references: [
          { label: 'MDN: Mixed Content', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content' },
        ],
        cweId: 'CWE-319',
        confidence: 'certain',
      });
    }
  }

  // 2. Security headers — check a comprehensive set
  const headerChecks: Array<{
    name: string;
    rule: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    desc: string;
    impact: string;
    rec: string;
    steps: string[];
    before: string;
    after: string;
    ref: { label: string; url: string };
    cwe: string;
  }> = [
    {
      name: 'strict-transport-security',
      rule: 'missing-hsts',
      severity: 'high',
      title: 'Missing HTTP Strict Transport Security (HSTS) header',
      desc: 'The site does not send a Strict-Transport-Security header, so browsers are not instructed to always use HTTPS for this host. Without HSTS, users who type or are redirected to the http:// version are vulnerable on the first request of each session.',
      impact: 'SSL stripping attacks can downgrade users to HTTP even when the site supports HTTPS, exposing credentials and enabling session hijacking.',
      rec: 'Add a Strict-Transport-Security header with a long max-age, includeSubDomains, and preload once HTTPS is fully functional.',
      steps: [
        'Confirm the entire site (including subdomains) works over HTTPS.',
        'Add the HSTS header to your server/CDN configuration.',
        'Start with a short max-age (e.g. 300) to test, then increase to at least 31536000 (1 year).',
        'Consider submitting to the HSTS preload list at hstspreload.org for maximum protection.',
      ],
      before: '(no header)',
      after: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      ref: { label: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
      cwe: 'CWE-319',
    },
    {
      name: 'content-security-policy',
      rule: 'missing-csp',
      severity: 'high',
      title: 'Missing Content-Security-Policy (CSP) header',
      desc: 'No Content-Security-Policy is set. CSP is the most effective defense against cross-site scripting (XSS) and data injection attacks because it restricts which sources may load scripts, styles, and other resources.',
      impact: 'Without CSP, any injected script runs with the full privileges of the page origin. XSS attacks can steal session tokens, deface the site, and act on behalf of the user.',
      rec: 'Deploy a strict CSP that disallows inline scripts and restricts resource sources to trusted origins. Use a report-only header first to measure impact.',
      steps: [
        'Audit all current script/style/image sources the page loads.',
        'Write a CSP that allowlists only those origins; avoid unsafe-inline and unsafe-eval.',
        'Deploy as Content-Security-Policy-Report-Only first and collect violation reports.',
        'Resolve any violations, then switch to the enforcing Content-Security-Policy header.',
        'Add a nonce or hash for any scripts that must remain inline.',
      ],
      before: '(no header)',
      after: "Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; base-uri 'self'",
      ref: { label: 'MDN: Content-Security-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
      cwe: 'CWE-79',
    },
    {
      name: 'x-frame-options',
      rule: 'missing-xfo',
      severity: 'medium',
      title: 'Missing X-Frame-Options header (clickjacking defense)',
      desc: 'The site does not send X-Frame-Options or a CSP frame-ancestors directive, so it can be embedded in an iframe on a malicious site. An attacker overlays invisible UI elements to trick users into clicking hidden actions.',
      impact: 'Clickjacking attacks can trick authenticated users into performing unintended actions such as changing settings, transferring funds, or granting permissions.',
      rec: 'Set X-Frame-Options: DENY (or SAMEORIGIN) and/or a CSP frame-ancestors directive to control who may embed the page.',
      steps: [
        'Determine whether any legitimate pages need to be framed by your own site.',
        'For pages that should never be framed, set X-Frame-Options: DENY.',
        'For pages framed only by your own origin, set X-Frame-Options: SAMEORIGIN.',
        'Prefer the modern CSP frame-ancestors directive for finer-grained control.',
      ],
      before: '(no header)',
      after: "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none'",
      ref: { label: 'OWASP Clickjacking Defense Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
      cwe: 'CWE-1021',
    },
    {
      name: 'x-content-type-options',
      rule: 'missing-xcto',
      severity: 'medium',
      title: 'Missing X-Content-Type-Options: nosniff header',
      desc: 'The site does not send X-Content-Type-Options: nosniff, so browsers may "sniff" the MIME type of a response and execute a file as a different type than declared. This can turn an image upload into executable script.',
      impact: 'MIME-type confusion can allow uploaded or attacker-controlled files to be executed as scripts, leading to XSS or content spoofing.',
      rec: 'Add X-Content-Type-Options: nosniff to all responses.',
      steps: [
        'Add the header globally in your web server or CDN configuration.',
        'Ensure all responses also declare a correct Content-Type.',
        'Verify with browser devtools that the header appears on all resources.',
      ],
      before: '(no header)',
      after: 'X-Content-Type-Options: nosniff',
      ref: { label: 'MDN: X-Content-Type-Options', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options' },
      cwe: 'CWE-430',
    },
    {
      name: 'referrer-policy',
      rule: 'missing-referrer-policy',
      severity: 'low',
      title: 'Missing Referrer-Policy header',
      desc: 'The site does not set a Referrer-Policy, so browsers use the default (no-referrer-when-downgrade) which may leak full URLs \u2014 including query parameters with sensitive data \u2014 to third-party origins via the Referer header.',
      impact: 'Sensitive query parameters (session tokens, user IDs, search terms) can leak to third-party services and analytics providers.',
      rec: 'Set a Referrer-Policy of strict-origin-when-cross-origin or stricter to limit what URL information is shared with third parties.',
      steps: [
        'Add Referrer-Policy: strict-origin-when-cross-origin to all responses.',
        'For highly sensitive pages, use no-referrer or same-origin.',
        'Review external links to ensure referrer leakage is acceptable.',
      ],
      before: '(no header)',
      after: 'Referrer-Policy: strict-origin-when-cross-origin',
      ref: { label: 'MDN: Referrer-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy' },
      cwe: 'CWE-200',
    },
    {
      name: 'permissions-policy',
      rule: 'missing-permissions-policy',
      severity: 'low',
      title: 'Missing Permissions-Policy header',
      desc: 'The site does not set a Permissions-Policy (formerly Feature-Policy), so browser features such as camera, microphone, geolocation, and payment can be accessed by the page and any embedded third-party content.',
      impact: 'Third-party scripts or iframes could access powerful device capabilities without the site owner\u2019s intent.',
      rec: 'Add a Permissions-Policy that disables features the site does not use.',
      steps: [
        'List the browser features your site genuinely needs (e.g. camera, microphone, geolocation, payment).',
        'Add a Permissions-Policy header that allowlists only those features for your own origin.',
        'Disable all unused features explicitly.',
      ],
      before: '(no header)',
      after: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self)',
      ref: { label: 'MDN: Permissions-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy' },
      cwe: 'CWE-732',
    },
  ];

  for (const h of headerChecks) {
    if (!hasHeader(ctx, h.name)) {
      // CSP frame-ancestors counts as X-Frame-Options alternative
      if (h.name === 'x-frame-options' && /frame-ancestors/i.test(headerValue(ctx, 'content-security-policy'))) {
        continue;
      }
      findings.push({
        id: crypto.randomUUID(),
        ruleId: h.rule,
        category: 'security',
        severity: h.severity,
        title: h.title,
        description: h.desc,
        impact: h.impact,
        recommendation: h.rec,
        fixSteps: h.steps,
        codeBefore: h.before,
        codeAfter: h.after,
        references: [h.ref],
        cweId: h.cwe,
        confidence: 'certain',
      });
    }
  }

  // 3. Inline event handlers (on* attributes) — XSS surface
  const inlineHandlers = Array.from(doc.querySelectorAll('[onclick], [onload], [onerror], [onmouseover], [onsubmit], [onfocus], [onblur], [onchange], [oninput], [onkeyup], [onkeydown]'));
  if (inlineHandlers.length > 0) {
    const sample = inlineHandlers.slice(0, 3).map((el) => {
      const attr = el.getAttributeNames().find((a) => a.startsWith('on'));
      return `<${el.tagName.toLowerCase()} ${attr}="${el.getAttribute(attr || '')?.slice(0, 60)}...">`;
    }).join('\n');
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'inline-event-handlers',
      category: 'security',
      severity: 'medium',
      title: `${inlineHandlers.length} inline event handler${inlineHandlers.length > 1 ? 's' : ''} found (on* attributes)`,
      description:
        'The page uses inline event handler attributes (onclick, onload, onerror, etc.). These make the page harder to secure with Content-Security-Policy because CSP must allow unsafe-inline or carry per-element nonces/hashes, and they couple behavior with markup.',
      evidence: sample,
      impact:
        'Inline handlers expand the XSS attack surface and prevent the use of a strict CSP. If any user input reaches an attribute value unescaped, script execution is immediate.',
      recommendation:
        'Move all event handling to addEventListener() calls in external scripts, then enforce a CSP without unsafe-inline.',
      fixSteps: [
        'For each on* attribute, move the handler logic into a separate .js file.',
        'Select the element (by id, data attribute, or class) and bind the listener with addEventListener.',
        'Remove the on* attribute from the HTML.',
        'Tighten the CSP to remove unsafe-inline for scripts.',
      ],
      codeBefore: '<button onclick="submitForm()">Submit</button>',
      codeAfter: '<button id="submitBtn">Submit</button>\n<script src="app.js"></script>\n// app.js: document.getElementById("submitBtn").addEventListener("click", submitForm);',
      references: [
        { label: 'MDN: addEventListener', url: 'https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener' },
        { label: 'OWASP DOM-based XSS Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html' },
      ],
      cweId: 'CWE-79',
      confidence: 'high',
    });
  }

  // 4. Inline <script> without nonce/src — XSS surface + CSP blocker
  const inlineScripts = Array.from(doc.querySelectorAll('script:not([src])')).filter((s) => s.textContent && s.textContent.trim().length > 0);
  if (inlineScripts.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'inline-scripts',
      category: 'security',
      severity: 'medium',
      title: `${inlineScripts.length} inline <script> block${inlineScripts.length > 1 ? 's' : ''} without external source`,
      description:
        'The page contains inline script blocks. These cannot be protected by a strict CSP without per-script nonces or hashes, and any unescaped user input inside them executes immediately.',
      evidence: inlineScripts.slice(0, 2).map((s) => s.textContent?.slice(0, 80) + '...').join('\n'),
      impact:
        'Inline scripts are a primary XSS vector and force CSP to include unsafe-inline, negating much of CSP\u2019s protection.',
      recommendation:
        'Move inline script logic into external .js files. If inline scripts are unavoidable, assign a unique nonce or hash per script and reflect it in the CSP.',
      fixSteps: [
        'Extract each inline script\u2019s code into a separate .js file.',
        'Replace the inline <script> with <script src="..."></script>.',
        'If a script must stay inline, generate a per-request nonce and add nonce="<value>" to the tag.',
        'Update the CSP script-src to include the nonce: script-src \'self\' \'nonce-<value>\'.',
      ],
      codeBefore: '<script>\n  var x = "hello";\n  doSomething();\n</script>',
      codeAfter: '<script src="app.js"></script>\n// app.js contains the same logic',
      references: [
        { label: 'MDN: CSP \u2014 script-src', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src' },
      ],
      cweId: 'CWE-79',
      confidence: 'high',
    });
  }

  // 5. javascript: URLs in href/src
  const jsUrls = Array.from(doc.querySelectorAll('[href^="javascript:"], [src^="javascript:"]'));
  if (jsUrls.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'javascript-urls',
      category: 'security',
      severity: 'medium',
      title: `${jsUrls.length} javascript: URL${jsUrls.length > 1 ? 's' : ''} found`,
      description:
        'The page uses javascript: URLs in href or src attributes. These execute as inline scripts and are blocked by a strict CSP, and they are a classic XSS vector when the URL is built from user input.',
      evidence: jsUrls.slice(0, 3).map((el) => `${el.tagName.toLowerCase()}: ${el.getAttribute('href') || el.getAttribute('src')}`).join('\n'),
      impact: 'javascript: URLs can execute arbitrary script and are blocked by modern CSPs, causing broken links.',
      recommendation: 'Replace javascript: URLs with proper event listeners bound in external scripts.',
      fixSteps: [
        'Identify every href="javascript:..." and src="javascript:..." in the markup.',
        'Replace with a real URL or a # placeholder and bind the behavior with addEventListener.',
        'Ensure no user input flows into these URLs.',
      ],
      codeBefore: '<a href="javascript:doThing()">Do thing</a>',
      codeAfter: '<a href="#" id="thingLink">Do thing</a>\n<script src="app.js"></script>\n// app.js: link.addEventListener("click", (e) => { e.preventDefault(); doThing(); });',
      references: [{ label: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }],
      cweId: 'CWE-79',
      confidence: 'certain',
    });
  }

  // 6. Forms without autocomplete safety on sensitive fields
  const passwordFields = Array.from(doc.querySelectorAll('input[type="password"]'));
  const unsafePasswords = passwordFields.filter((el) => el.getAttribute('autocomplete') !== 'new-password' && el.getAttribute('autocomplete') !== 'off');
  if (unsafePasswords.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'password-autocomplete',
      category: 'security',
      severity: 'low',
      title: 'Password field without safe autocomplete attribute',
      description:
        'Password inputs do not set an appropriate autocomplete value. On a registration form autocomplete="new-password" tells password managers to suggest a strong new password; on a login form autocomplete="current-password" allows correct autofill.',
      impact: 'Users are less likely to use strong, unique passwords if the browser cannot generate or fill them correctly.',
      recommendation: 'Set autocomplete="new-password" on signup/change-password fields and autocomplete="current-password" on login fields.',
      fixSteps: [
        'On signup and password-change forms, add autocomplete="new-password" to the password input.',
        'On login forms, add autocomplete="current-password".',
        'Verify the browser offers to generate and save strong passwords.',
      ],
      codeBefore: '<input type="password" name="pwd">',
      codeAfter: '<input type="password" name="pwd" autocomplete="new-password" minlength="12" required>',
      references: [{ label: 'MDN: The autocomplete attribute', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete' }],
      cweId: 'CWE-522',
      confidence: 'high',
    });
  }

  // 7. Forms lacking action or using GET
  const forms = Array.from(doc.querySelectorAll('form'));
  for (const form of forms.slice(0, 8)) {
    const method = (form.getAttribute('method') || 'get').toLowerCase();
    if (method === 'get') {
      const hasPassword = form.querySelector('input[type="password"]');
      if (hasPassword) {
        findings.push({
          id: crypto.randomUUID(),
          ruleId: 'form-get-password',
          category: 'security',
          severity: 'high',
          title: 'Password submitted via GET form method',
          description: 'A form containing a password input uses method="get". GET requests place form data in the URL query string, which is logged in browser history, server access logs, and the Referer header to third parties.',
          impact: 'Passwords appear in URLs and are exposed in browser history, server logs, referrer headers, and bookmarks.',
          recommendation: 'Change the form method to POST and ensure the action URL uses HTTPS.',
          fixSteps: [
            'Change the form\u2019s method attribute from "get" to "post".',
            'Ensure the action attribute points to an HTTPS endpoint.',
            'Clear any cached logs that may contain the leaked password.',
          ],
          codeBefore: '<form method="get" action="/login">\n  <input type="password" name="password">\n</form>',
          codeAfter: '<form method="post" action="/login">\n  <input type="password" name="password" autocomplete="current-password">\n</form>',
          references: [{ label: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' }],
          cweId: 'CWE-598',
          confidence: 'certain',
        });
      }
    }
  }

  // 8. Exposed email addresses (spam + enumeration risk)
  const emailRe = /mailto:([^"'\s>]+)/gi;
  const pageText = doc.body?.textContent || '';
  const mailtoMatches = (ctx.html.match(emailRe) || []).slice(0, 5);
  const plainEmails = (pageText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])
    .filter((e) => !e.endsWith('@example.com') && !e.endsWith('@sentry.io') && !e.endsWith('@2x.png'))
    .slice(0, 5);
  if (mailtoMatches.length || plainEmails.length) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'exposed-email',
      category: 'security',
      severity: 'low',
      title: 'Email address exposed in page source',
      description: 'One or more email addresses appear in the HTML source. Email harvesting bots scan the web to build spam lists and can enumerate valid addresses for targeted attacks.',
      evidence: [...mailtoMatches, ...plainEmails].slice(0, 5).join('\n'),
      impact: 'Harvested emails receive spam and phishing, and confirm valid accounts for credential-stuffing attacks.',
      recommendation: 'Replace mailto: links and visible emails with a contact form, an obfuscated address, or a reCAPTCHA-protected mailto.',
      fixSteps: [
        'Replace visible email addresses with a server-side contact form that does not expose the recipient address.',
        'If an email must be shown, split it (e.g. "name [at] example [dot] com") or render it via JavaScript from encoded parts.',
        'Use a honeypot or reCAPTCHA on any form that sends email.',
      ],
      codeBefore: '<a href="mailto:admin@example.com">admin@example.com</a>',
      codeAfter: '<a href="/contact">Contact us</a>  (server-side form)',
      references: [{ label: 'OWASP Email Address Obfuscation', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html' }],
      cweId: 'CWE-200',
      confidence: 'high',
    });
  }

  // 9. Missing crossorigin on external scripts (SRI prerequisite + leak prevention)
  const externalScripts = Array.from(doc.querySelectorAll('script[src^="http"]'));
  const noCrossorigin = externalScripts.filter((s) => !s.getAttribute('crossorigin') && !s.getAttribute('integrity'));
  if (noCrossorigin.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-sri',
      category: 'security',
      severity: 'medium',
      title: `${noCrossorigin.length} external script${noCrossorigin.length > 1 ? 's' : ''} without Subresource Integrity (SRI)`,
      description: 'External scripts are loaded without an integrity attribute. If the CDN or third-party host is compromised, attackers can inject malicious JavaScript that runs with your site\u2019s origin.',
      impact: 'A compromised CDN can inject malware, steal data, or deface your site without any signal to the user or site owner.',
      recommendation: 'Add integrity (SRI) hashes and crossorigin attributes to every external script and stylesheet.',
      fixSteps: [
        'For each external <script src>, generate an SRI hash (e.g. at srihash.org or with openssl).',
        'Add integrity="sha384-<hash>" and crossorigin="anonymous" to the tag.',
        'Repeat for external <link rel="stylesheet"> tags.',
        'Pin to a specific version of each third-party resource so the hash stays valid.',
      ],
      codeBefore: '<script src="https://cdn.example.com/lib.js"></script>',
      codeAfter: '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1ekP1Po..." crossorigin="anonymous"></script>',
      references: [{ label: 'MDN: Subresource Integrity', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity' }],
      cweId: 'CWE-829',
      confidence: 'high',
    });
  }

  // 10. Server header version disclosure
  const serverHeader = headerValue(ctx, 'server');
  const xPoweredBy = headerValue(ctx, 'x-powered-by');
  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'server-version-disclosure',
      category: 'security',
      severity: 'low',
      title: 'Server software version disclosed in headers',
      description: `The Server header reveals specific version information ("${serverHeader}"). This tells attackers exactly which vulnerabilities to try without any probing.`,
      impact: 'Attackers skip reconnaissance and directly target known vulnerabilities for the disclosed version.',
      recommendation: 'Suppress or obfuscate the Server and X-Powered-By headers in your web server configuration.',
      fixSteps: [
        'In Apache: set ServerTokens Prod and ServerSignature Off.',
        'In Nginx: use server_tokens off; and optionally the more_clear_headers module.',
        'Remove or override X-Powered-By in your application framework configuration.',
      ],
      codeBefore: 'Server: Apache/2.4.49',
      codeAfter: 'Server: Apache  (no version)',
      references: [{ label: 'OWASP Configuration \u2014 Information Exposure', url: 'https://owasp.org/www-community/Improper_Error_Handling' }],
      cweId: 'CWE-200',
      confidence: 'certain',
    });
  }
  if (xPoweredBy) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'x-powered-by-disclosure',
      category: 'security',
      severity: 'low',
      title: 'X-Powered-By header discloses technology stack',
      description: `The X-Powered-By header ("${xPoweredBy}") reveals the application framework or runtime. This information helps attackers fingerprint the stack and target known vulnerabilities.`,
      impact: 'Technology fingerprinting reduces an attacker\u2019s effort to find applicable exploits.',
      recommendation: 'Remove the X-Powered-By header in your framework or server configuration.',
      fixSteps: [
        'In Express: app.disable("x-powered-by").',
        'In PHP: set expose_php = Off in php.ini.',
        'In other frameworks, search for the configuration option that controls this header.',
      ],
      codeBefore: 'X-Powered-By: Express',
      codeAfter: '(header removed)',
      references: [{ label: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/' }],
      cweId: 'CWE-200',
      confidence: 'certain',
    });
  }

  // 11. Open redirect risk in client-side redirect
  const metaRefresh = doc.querySelector('meta[http-equiv="refresh"][content*="url="]');
  if (metaRefresh) {
    const content = metaRefresh.getAttribute('content') || '';
    const dest = content.split('url=')[1]?.trim();
    if (dest && (dest.startsWith('http://') || dest.startsWith('//'))) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'meta-refresh-redirect',
        category: 'security',
        severity: 'low',
        title: 'Meta refresh redirect to external URL',
        description: 'The page uses a <meta http-equiv="refresh"> redirect to an external URL. If the destination is ever influenced by a URL parameter, this becomes an open redirect that can be used in phishing.',
        impact: 'Open redirects are abused in phishing campaigns \u2014 a trusted domain redirects victims to a look-alike malicious site.',
        recommendation: 'Avoid meta-refresh redirects. Use server-side 301/302 redirects with a hardcoded, trusted destination.',
        fixSteps: [
          'Replace the meta refresh with a server-side redirect (301 or 302).',
          'Never allow user input to control the redirect destination.',
          'Maintain an allowlist of permitted redirect targets.',
        ],
        codeBefore: '<meta http-equiv="refresh" content="0; url=http://other-site.com">',
        codeAfter: 'Server response: 302 Found  Location: /trusted-path',
        references: [{ label: 'OWASP Unvalidated Redirects and Forwards', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' }],
        cweId: 'CWE-601',
        confidence: 'medium',
      });
    }
  }

  // 12. Missing rel="noopener" on target="_blank" links
  const blankLinks = Array.from(doc.querySelectorAll('a[target="_blank"]')).filter(
    (a) => !a.getAttribute('rel')?.toLowerCase().includes('noopener'),
  );
  if (blankLinks.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-noopener',
      category: 'security',
      severity: 'medium',
      title: `${blankLinks.length} link${blankLinks.length > 1 ? 's' : ''} with target="_blank" missing rel="noopener"`,
      description: 'Links that open in a new tab do not include rel="noopener". The opened page can access the original page via window.opener, enabling tabnabbing attacks where the background tab is redirected to a phishing page.',
      impact: 'A malicious or compromised linked site can silently redirect the original tab to a phishing page.',
      recommendation: 'Add rel="noopener noreferrer" to every link with target="_blank".',
      fixSteps: [
        'Search the HTML for target="_blank" and add rel="noopener noreferrer" to each matching <a> tag.',
        'For framework-generated links, configure the component to add the attribute automatically.',
        'Note: modern browsers default to noopener behavior, but the attribute is still needed for older browsers and to signal intent.',
      ],
      codeBefore: '<a href="https://example.com" target="_blank">Visit</a>',
      codeAfter: '<a href="https://example.com" target="_blank" rel="noopener noreferrer">Visit</a>',
      references: [{ label: 'MDN: target attribute', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#attr-target' }],
      cweId: 'CWE-1022',
      confidence: 'high',
    });
  }

  // 13. Detect eval-like patterns in inline scripts
  const allScriptText = Array.from(doc.querySelectorAll('script')).map((s) => s.textContent || '').join('\n');
  if (/eval\s*\(|new\s+Function\s*\(|document\.write\s*\(/.test(allScriptText)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'eval-document-write',
      category: 'security',
      severity: 'medium',
      title: 'Use of eval(), new Function(), or document.write() detected',
      description: 'The page\u2019s scripts use eval(), the Function constructor, or document.write(). These are dangerous DOM APIs that can execute arbitrary strings as code and are blocked by strict CSPs.',
      impact: 'If any user input reaches these sinks, it executes as script \u2014 a direct XSS vector. document.write() also blocks parsing and is discouraged.',
      recommendation: 'Remove eval/Function usage and replace document.write() with safe DOM manipulation methods.',
      fixSteps: [
        'Find every eval(), new Function(), and document.write() call.',
        'Replace eval of JSON with JSON.parse().',
        'Replace document.write() with element.innerHTML or DOM methods after sanitizing input.',
        'If dynamic code is essential, isolate it in a Web Worker or sandboxed iframe.',
      ],
      codeBefore: 'document.write(userInput);\neval(responseText);',
      codeAfter: 'el.textContent = userInput;  // safe\nconst data = JSON.parse(responseText);',
      references: [{ label: 'MDN: eval() \u2014 never use eval', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval' }],
      cweId: 'CWE-95',
      confidence: 'high',
    });
  }

  // 14. Set-Cookie without Secure/HttpOnly/SameSite (best-effort from headers)
  // Some proxies fold multiple Set-Cookie; check joined value.
  const setCookie = headerValue(ctx, 'set-cookie');
  if (setCookie) {
    const cookies = setCookie.split(/,(?=\s*[A-Za-z0-9_-]+=)/);
    for (const cookie of cookies.slice(0, 3)) {
      const lower = cookie.toLowerCase();
      const missing: string[] = [];
      if (!lower.includes('secure')) missing.push('Secure');
      if (!lower.includes('httponly')) missing.push('HttpOnly');
      if (!lower.includes('samesite')) missing.push('SameSite');
      if (missing.length) {
        findings.push({
          id: crypto.randomUUID(),
          ruleId: 'insecure-cookie',
          category: 'security',
          severity: missing.includes('HttpOnly') || missing.includes('Secure') ? 'high' : 'medium',
          title: `Cookie missing security flags: ${missing.join(', ')}`,
          description: `A Set-Cookie header is missing the ${missing.join(', ')} flag${missing.length > 1 ? 's' : ''}. Cookies without these flags can be read by JavaScript (XSS theft) or sent over unencrypted HTTP.`,
          evidence: cookie.slice(0, 120),
          impact: 'Missing HttpOnly allows XSS to steal the cookie; missing Secure sends it over HTTP; missing SameSite enables cross-site request forgery.',
          recommendation: `Add the ${missing.join(', ')} flag${missing.length > 1 ? 's' : ''} to the Set-Cookie header.`,
          fixSteps: [
            'Update the server code that sets the cookie to include Secure, HttpOnly, and SameSite=Lax (or Strict).',
            'Verify the cookie is only ever set on HTTPS responses.',
            'Test that legitimate cross-site flows still work after adding SameSite.',
          ],
          codeBefore: `Set-Cookie: session=abc123; Path=/`,
          codeAfter: `Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax`,
          references: [{ label: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' }],
          cweId: 'CWE-614',
          confidence: 'high',
        });
      }
    }
  }

  // 15. Accessible authentication / login form without CSRF hint (heuristic)
  const loginForms = forms.filter((f) => f.querySelector('input[type="password"]'));
  if (loginForms.length > 0) {
    const hasCsrfToken = loginForms.some((f) => {
      const inputs = Array.from(f.querySelectorAll('input'));
      return inputs.some((i) => {
        const name = (i.getAttribute('name') || '').toLowerCase();
        return name.includes('csrf') || name.includes('token') || name.includes('_token') || i.getAttribute('type') === 'hidden';
      });
    });
    if (!hasCsrfToken) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'missing-csrf-token',
        category: 'security',
        severity: 'medium',
        title: 'Login form has no visible CSRF token field',
        description: 'The form containing a password input has no hidden CSRF token field. Without CSRF protection, an attacker site can submit the form on a victim\u2019s behalf while their browser attaches their session cookies.',
        impact: 'Cross-site request forgery can force authenticated users to change their password, email, or perform actions without their knowledge.',
        recommendation: 'Add a per-session CSRF token as a hidden input and validate it server-side on every state-changing request.',
        fixSteps: [
          'Generate a cryptographically random CSRF token on session creation.',
          'Include it as a hidden <input> in every form: <input type="hidden" name="_csrf" value="<token>">.',
          'Validate the submitted token against the session token on the server; reject mismatches.',
          'For AJAX, include the token in a custom header and verify it server-side.',
        ],
        codeBefore: '<form method="post" action="/login">\n  <input type="password" name="password">\n</form>',
        codeAfter: '<form method="post" action="/login">\n  <input type="hidden" name="_csrf" value="{{csrfToken}}">\n  <input type="password" name="password">\n</form>',
        references: [{ label: 'OWASP CSRF Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' }],
        cweId: 'CWE-352',
        confidence: 'medium',
      });
    }
  }

  // 16. Strict-Transport-Security present but short max-age
  if (hasHeader(ctx, 'strict-transport-security')) {
    const hsts = headerValue(ctx, 'strict-transport-security');
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    if (maxAgeMatch && parseInt(maxAgeMatch[1], 10) < 31536000) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'hsts-short-maxage',
        category: 'security',
        severity: 'low',
        title: 'HSTS max-age is less than one year',
        description: `The HSTS header uses max-age=${maxAgeMatch[1]} (under 31536000 seconds / 1 year). Short max-age values mean browsers forget the HSTS policy quickly, widening the window for SSL-stripping attacks.`,
        impact: 'A short HSTS window lets attackers downgrade users to HTTP more often.',
        recommendation: 'Increase max-age to at least 31536000 (1 year) once HTTPS is confirmed stable.',
        fixSteps: [
          'Confirm the entire site works over HTTPS with no mixed content.',
          'Update the HSTS header max-age to 31536000 or higher.',
          'Add includeSubDomains and consider preload for comprehensive protection.',
        ],
        codeBefore: `Strict-Transport-Security: max-age=${maxAgeMatch[1]}`,
        codeAfter: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        references: [{ label: 'MDN: Strict-Transport-Security', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' }],
        cweId: 'CWE-319',
        confidence: 'certain',
      });
    }
  }

  void getMeta; // reserved for future cookie/meta token checks

  // 17. Exposed secrets / API keys in inline JavaScript
  const inlineScriptText = Array.from(doc.querySelectorAll('script:not([src]')).map((s) => s.textContent || '').join('\n');
  const allInlineText = inlineScriptText + '\n' + ctx.html;

  const secretPatterns: { name: string; pattern: RegExp; severity: 'critical' | 'high'; cwe: string; rec: string }[] = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', cwe: 'CWE-798', rec: 'Remove the AWS access key from client-side code immediately, rotate it, and use server-side credential management.' },
    { name: 'AWS Secret Key', pattern: /aws_secret_access_key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, severity: 'critical', cwe: 'CWE-798', rec: 'Remove the AWS secret key from client-side code immediately, rotate it, and use environment variables on the server.' },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high', cwe: 'CWE-798', rec: 'Restrict the Google API key to your domain in the Google Cloud Console, or move it server-side.' },
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36}/g, severity: 'critical', cwe: 'CWE-798', rec: 'Revoke the GitHub token immediately in GitHub Settings, then use it only in server-side code or CI secrets.' },
    { name: 'Stripe Secret Key', pattern: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: 'critical', cwe: 'CWE-798', rec: 'Rotate the Stripe secret key in the Stripe Dashboard immediately. Only use publishable keys (pk_) on the client.' },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, severity: 'high', cwe: 'CWE-798', rec: 'Revoke the Slack token and use it only server-side.' },
    { name: 'Generic private key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical', cwe: 'CWE-798', rec: 'Remove the private key from client-accessible code immediately, rotate the key pair, and store keys only on the server.' },
    { name: 'JWT token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high', cwe: 'CWE-798', rec: 'Remove any hardcoded JWT tokens from client-side code. JWTs should be generated server-side and stored in HttpOnly cookies.' },
    { name: 'Generic API key pattern', pattern: /(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9]{32,}['"]/gi, severity: 'high', cwe: 'CWE-798', rec: 'Move API keys to server-side environment variables. Never expose secrets in client-side JavaScript or HTML.' },
    { name: 'Firebase config with private key', pattern: /private_key\s*[:=]\s*['"][^'"]{100,}['"]/gi, severity: 'high', cwe: 'CWE-798', rec: 'Ensure this is a public Firebase config, not a service account key. Service account keys must never appear in client code.' },
  ];

  for (const sp of secretPatterns) {
    const matches = allInlineText.match(sp.pattern);
    if (matches && matches.length > 0) {
      const sample = matches.slice(0, 2).map((m) => m.slice(0, 30) + '...').join('\n');
      findings.push({
        id: crypto.randomUUID(),
        ruleId: `exposed-secret-${sp.name.toLowerCase().replace(/\s+/g, '-')}`,
        category: 'security',
        severity: sp.severity,
        title: `${sp.name} exposed in client-side code`,
        description: `A ${sp.name} appears to be embedded in the page's HTML or inline JavaScript. Anyone who views the page source can extract and abuse this credential.`,
        evidence: sample,
        impact: sp.severity === 'critical'
          ? 'An attacker with this key can access your cloud infrastructure, databases, or payment systems, potentially causing severe data breaches and financial loss.'
          : 'An attacker can abuse this key to access third-party services at your expense, bypass rate limits, or impersonate your application.',
        recommendation: sp.rec,
        fixSteps: [
          `Immediately rotate/revoke the exposed ${sp.name} in the provider's dashboard.`,
          'Remove the key from all client-side code (HTML, inline scripts, bundled JS).',
          'Store credentials in server-side environment variables or a secrets manager.',
          'Set up key rotation policies to limit the impact of future leaks.',
          'Audit version control history to ensure the key was not committed to a public repository.',
        ],
        codeBefore: `// In HTML/JS:\nconst API_KEY = "${matches[0].slice(0, 20)}...";`,
        codeAfter: `// In server-side code only:\nconst API_KEY = process.env.API_KEY;\n// Client calls your server endpoint, which uses the key server-side.`,
        references: [
          { label: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' },
          { label: 'CWE-798: Use of Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html' },
        ],
        cweId: sp.cwe,
        confidence: 'high',
      });
    }
  }

  // 18. CORS misconfiguration — Access-Control-Allow-Origin: *
  const acao = headerValue(ctx, 'access-control-allow-origin');
  if (acao === '*') {
    const hasCreds = headerValue(ctx, 'access-control-allow-credentials');
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'cors-wildcard',
      category: 'security',
      severity: hasCreds ? 'critical' : 'medium',
      title: hasCreds
        ? 'CORS allows all origins with credentials (critical misconfiguration)'
        : 'CORS Access-Control-Allow-Origin set to wildcard',
      description: hasCreds
        ? 'The server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This combination is rejected by modern browsers, but if a reflection-based CORS bypass exists, it enables cross-origin credential theft.'
        : 'The server allows any website to make cross-origin requests with Access-Control-Allow-Origin: *. If the responses contain sensitive data, any site can read them.',
      evidence: `Access-Control-Allow-Origin: ${acao}${hasCreds ? '\nAccess-Control-Allow-Credentials: true' : ''}`,
      impact: hasCreds
        ? 'If a CORS bypass exists, any malicious site can make authenticated requests to your API and read the responses, leading to account takeover and data theft.'
        : 'Any website can read API responses cross-origin. If the API returns sensitive data, it is exposed to all sites.',
      recommendation: hasCreds
        ? 'Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true. Use an allowlist of trusted origins and reflect only those.'
        : 'Replace the wildcard with an explicit allowlist of trusted origins. Only allow cross-origin access from domains that need it.',
      fixSteps: [
        'Identify which origins need cross-origin access to your API.',
        'Configure the server to check the request Origin against an allowlist.',
        'Return only the matching origin in Access-Control-Allow-Origin, not *.',
        hasCreds ? 'If credentials are needed, never use *. Always reflect the specific trusted origin.' : 'If credentials are not needed, keep credentials disabled.',
        'Test with a non-allowlisted origin to confirm it is rejected.',
      ],
      codeBefore: 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true',
      codeAfter: '// Server checks Origin against allowlist:\nconst allowed = ["https://app.example.com"];\nif (allowed.includes(req.headers.origin)) {\n  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n}',
      references: [
        { label: 'OWASP CORS Misconfiguration', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html' },
        { label: 'MDN: CORS', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
      ],
      cweId: 'CWE-942',
      confidence: 'certain',
    });
  }

  // 19. Missing security.txt
  // We check if the edge function found it; if not, flag as info
  // (securityTxt is not in ctx — the edge function returns it separately.
  // We check a heuristic: if the site has a .well-known path pattern)
  // This is handled in the scanner which has access to the full FetchResult.

  // 20. Weak TLS/SSL cipher suites (heuristic from headers)
  const tlsVersion = headers['x-tls-version'] || '';
  if (tlsVersion && /TLSv1\b|SSLv|TLSv1\.0|TLSv1\.1/i.test(tlsVersion)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'weak-tls',
      category: 'security',
      severity: 'high',
      title: 'Outdated TLS version detected',
      description: `The server appears to be using ${tlsVersion}, which is deprecated. TLS 1.0 and 1.1 have known vulnerabilities and are disabled by modern browsers.`,
      impact: 'Weak TLS versions are vulnerable to attacks such as BEAST, POODLE, and downgrade attacks, allowing interception of encrypted traffic.',
      recommendation: 'Disable TLS 1.0 and 1.1. Require TLS 1.2 or higher, and prefer TLS 1.3.',
      fixSteps: [
        'Configure your web server to only accept TLS 1.2 and TLS 1.3.',
        'Disable TLS 1.0, TLS 1.1, and all SSL versions.',
        'Use strong cipher suites (e.g. ECDHE with AES-GCM or ChaCha20).',
        'Test with SSL Labs (ssllabs.com) to verify the configuration.',
      ],
      codeBefore: 'TLSv1.0 enabled',
      codeAfter: 'TLSv1.2+ only, TLSv1.3 preferred',
      references: [
        { label: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org/' },
        { label: 'SSL Labs Test', url: 'https://www.ssllabs.com/ssltest/' },
      ],
      cweId: 'CWE-326',
      confidence: 'high',
    });
  }

  // 21. HTML comments containing sensitive info
  const comments = ctx.html.match(/<!--[\s\S]*?-->/g) || [];
  const sensitiveComments = comments.filter((c) =>
    /(?:password|secret|token|api[_-]?key|credential|TODO|FIXME|HACK|debug|admin|private)/i.test(c),
  ).slice(0, 3);
  if (sensitiveComments.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'sensitive-html-comment',
      category: 'security',
      severity: 'low',
      title: 'HTML comments may contain sensitive information',
      description: 'HTML comments containing keywords like "password", "secret", "token", "debug", or "TODO" were found. While comments are not executable, they leak internal information to anyone who views the page source.',
      evidence: sensitiveComments.map((c) => c.slice(0, 100)).join('\n'),
      impact: 'Comments reveal internal logic, development notes, and potentially credentials or debugging hints that aid attackers in reconnaissance.',
      recommendation: 'Remove all sensitive or development-related comments from production HTML.',
      fixSteps: [
        'Review all HTML comments and remove any that reference passwords, tokens, secrets, or internal logic.',
        'Configure your build process to strip HTML comments in production.',
        'Never store credentials or debugging hints in HTML comments.',
      ],
      codeBefore: '<!-- TODO: remove test password "admin123" before prod -->',
      codeAfter: '(comments stripped in production build)',
      references: [{ label: 'OWASP Information Exposure', url: 'https://owasp.org/www-community/Improper_Error_Handling' }],
      cweId: 'CWE-615',
      confidence: 'medium',
    });
  }

  // 22. Missing Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy
  if (!hasHeader(ctx, 'cross-origin-opener-policy')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-coop',
      category: 'security',
      severity: 'low',
      title: 'Missing Cross-Origin-Opener-Policy (COOP) header',
      description: 'The site does not send a Cross-Origin-Opener-Policy header. Without COOP, a malicious site can open your page in a popup and access window references, enabling cross-origin window attacks.',
      impact: 'Enables cross-origin window access which can be used in sophisticated attacks like Spectre-based data leaks.',
      recommendation: 'Add Cross-Origin-Opener-Policy: same-origin to isolate your browsing context.',
      fixSteps: [
        'Add Cross-Origin-Opener-Policy: same-origin to all responses.',
        'Test that legitimate popup interactions still work.',
        'For pages that need cross-origin window access, use same-origin-allow-popups.',
      ],
      codeBefore: '(no COOP header)',
      codeAfter: 'Cross-Origin-Opener-Policy: same-origin',
      references: [{ label: 'MDN: COOP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy' }],
      cweId: 'CWE-1021',
      confidence: 'certain',
    });
  }

  if (!hasHeader(ctx, 'cross-origin-embedder-policy')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-coep',
      category: 'security',
      severity: 'low',
      title: 'Missing Cross-Origin-Embedder-Policy (COEP) header',
      description: 'The site does not send a Cross-Origin-Embedder-Policy header. COEP prevents loading cross-origin resources that do not explicitly opt in via CORP or CORS, blocking Spectre-type attacks.',
      impact: 'Without COEP, the page may be vulnerable to speculative execution side-channel attacks if combined with other conditions.',
      recommendation: 'Add Cross-Origin-Embedder-Policy: require-corp to prevent loading unauthorized cross-origin resources.',
      fixSteps: [
        'Add Cross-Origin-Embedder-Policy: require-corp to all responses.',
        'Ensure all cross-origin resources have CORP or CORS headers.',
        'Test thoroughly as this can break third-party resource loading.',
      ],
      codeBefore: '(no COEP header)',
      codeAfter: 'Cross-Origin-Embedder-Policy: require-corp',
      references: [{ label: 'MDN: COEP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy' }],
      cweId: 'CWE-1021',
      confidence: 'certain',
    });
  }

  // 23. Forms without autocomplete="off" on sensitive non-password fields
  const sensitiveInputs = Array.from(doc.querySelectorAll('input[name*="credit"], input[name*="card"], input[name*="ssn"], input[name*="secret"], input[name*="token"]'));
  const unsafeSensitive = sensitiveInputs.filter((el) => !el.getAttribute('autocomplete')?.includes('off'));
  if (unsafeSensitive.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'sensitive-input-autocomplete',
      category: 'security',
      severity: 'medium',
      title: 'Sensitive input fields allow browser autocomplete',
      description: 'Inputs with names suggesting credit cards, SSNs, or tokens do not disable autocomplete. The browser may store this sensitive data in its autofill database.',
      impact: 'Sensitive financial or personal data may be stored in the browser and exposed to other users of the same device, or leaked through autofill on malicious sites.',
      recommendation: 'Add autocomplete="off" to any field collecting credit card numbers, SSNs, or other highly sensitive data.',
      fixSteps: [
        'Add autocomplete="off" to all credit card, SSN, and token input fields.',
        'Consider using the Payment Request API instead of custom card input fields.',
      ],
      codeBefore: '<input name="credit_card" type="text">',
      codeAfter: '<input name="credit_card" type="text" autocomplete="off" inputmode="numeric">',
      references: [{ label: 'MDN: autocomplete', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete' }],
      cweId: 'CWE-522',
      confidence: 'high',
    });
  }

  // 24. Loose CSP with unsafe-inline or unsafe-eval
  const cspHeader = headerValue(ctx, 'content-security-policy');
  if (cspHeader && /unsafe-inline|unsafe-eval/i.test(cspHeader)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'weak-csp',
      category: 'security',
      severity: 'medium',
      title: 'Content-Security-Policy uses unsafe-inline or unsafe-eval',
      description: 'A CSP header is present but includes unsafe-inline or unsafe-eval directives, which significantly weaken the policy. unsafe-inline allows inline scripts/styles (an XSS vector), and unsafe-eval allows eval() and similar functions.',
      evidence: cspHeader.slice(0, 200),
      impact: 'With unsafe-inline, injected scripts execute as if no CSP existed. unsafe-eval enables eval-based attacks. The CSP provides little real protection.',
      recommendation: 'Remove unsafe-inline and unsafe-eval from the CSP. Use nonces or hashes for inline scripts, and eliminate eval() usage.',
      fixSteps: [
        'Replace unsafe-inline with per-request nonces on every inline script.',
        'Remove unsafe-eval and eliminate all eval(), new Function(), and setTimeout(string) usage.',
        'Move inline scripts to external files.',
        'Deploy a strict CSP: default-src \'self\'; script-src \'self\'; object-src \'none\'',
      ],
      codeBefore: "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      codeAfter: "Content-Security-Policy: script-src 'self' 'nonce-{random}'",
      references: [{ label: 'Google: Strict CSP', url: 'https://csp.withgoogle.com/docs/strict-csp.html' }],
      cweId: 'CWE-79',
      confidence: 'certain',
    });
  }

  // 25. Missing security.txt (check via well-known path)
  // The edge function now probes /.well-known/security.txt — we check the fetch result
  // This is handled in scanner.ts which has access to the full FetchResult.

  // 26. SQL Injection indicators — query parameters that look injectable
  let urlObj: URL | null = null;
  try { urlObj = new URL(ctx.finalUrl); } catch { urlObj = null; }
  if (urlObj && urlObj.searchParams.size > 0) {
    const suspiciousParams = ['id', 'user', 'item', 'product', 'page', 'cat', 'category', 'sort', 'order', 'search', 'q', 'name', 'ref'];
    for (const [key, value] of urlObj.searchParams.entries()) {
      if (suspiciousParams.includes(key.toLowerCase())) {
        const looksNumeric = /^\d+$/.test(value);
        if (looksNumeric || value.length > 0) {
          findings.push({
            id: crypto.randomUUID(),
            ruleId: 'sqli-indicator',
            category: 'security',
            severity: 'high',
            title: `Potential SQL injection via "${key}" parameter`,
            description: `The URL parameter "${key}" passes a value directly to the server. If this parameter is concatenated into a SQL query without parameterization, an attacker can inject SQL commands by modifying the URL.`,
            evidence: `URL: ${ctx.finalUrl}\nParameter: ${key}=${value}\nTest payload: ${key}=${value}' OR '1'='1`,
            impact: 'SQL injection can lead to complete database compromise. An attacker can extract all data (user credentials, personal information, payment records), modify or delete records, bypass authentication, and in some cases achieve remote code execution via xp_cmdshell or file write capabilities.',
            recommendation: 'Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings. Validate input types and use an ORM that handles escaping.',
            fixSteps: [
              `Test the "${key}" parameter manually: append a single quote and observe if a SQL error appears or the page changes.`,
              'If vulnerable, immediately switch to parameterized queries: SELECT * FROM table WHERE id = $1 (PostgreSQL) or ? (MySQL).',
              'Validate that the parameter matches the expected type (integer, string) before using it.',
              'Use an ORM (e.g. Prisma, SQLAlchemy, Eloquent) that handles parameterization automatically.',
              'Deploy a Web Application Firewall (WAF) as a temporary mitigation while fixing the code.',
            ],
            codeBefore: `// Vulnerable:\napp.get("/item", (req, res) => {\n  db.query("SELECT * FROM items WHERE id = " + req.query.id);\n});`,
            codeAfter: `// Fixed:\napp.get("/item", (req, res) => {\n  db.query("SELECT * FROM items WHERE id = $1", [req.query.id]);\n});`,
            references: [
              { label: 'OWASP SQL Injection Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
              { label: 'PortSwigger: SQL Injection', url: 'https://portswigger.net/web-security/sql-injection' },
            ],
            cweId: 'CWE-89',
            owaspCategory: 'A03: Injection',
            vulnerabilityClass: 'sql-injection',
            confidence: 'medium',
          });
          break;
        }
      }
    }
  }

  // 27. Reflected XSS indicators — parameters reflected in page
  if (urlObj && urlObj.searchParams.size > 0) {
    for (const [key, value] of urlObj.searchParams.entries()) {
      if (value.length > 2 && ctx.html.includes(value)) {
        findings.push({
          id: crypto.randomUUID(),
          ruleId: 'xss-reflected-indicator',
          category: 'security',
          severity: 'high',
          title: `Potential reflected XSS via "${key}" parameter`,
          description: `The URL parameter "${key}" appears to be reflected directly into the page HTML without sanitization. An attacker can craft a malicious URL that injects JavaScript, which executes when a victim clicks the link.`,
          evidence: `Parameter: ${key}=${value}\nReflected in page HTML: yes\nTest payload: ${key}=<script>alert(document.cookie)</script>`,
          impact: 'XSS allows an attacker to execute arbitrary JavaScript in the victim\'s browser. This enables session token theft, account takeover, credential harvesting via fake login forms, defacement, and malware delivery.',
          recommendation: 'Encode/sanitize all user input before outputting it to HTML. Use context-aware output encoding. Deploy a strict Content-Security-Policy as defense-in-depth.',
          fixSteps: [
            `Test: append ${key}=<img src=x onerror=alert(1)> to the URL and check if a popup appears.`,
            'HTML-encode all dynamic output: &lt; &gt; &quot; &amp; etc.',
            'Use a templating engine that auto-escapes (React, Vue, Twig, Jinja auto-escape by default).',
            'If using innerHTML, sanitize with DOMPurify first.',
            'Deploy a strict CSP: script-src \'self\' to block inline script execution.',
          ],
          codeBefore: `// Vulnerable:\nres.send("<h1>Search: " + req.query.q + "</h1>");`,
          codeAfter: `// Fixed:\nres.send("<h1>Search: " + escapeHtml(req.query.q) + "</h1>");\n// Or use a framework that auto-escapes`,
          references: [
            { label: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
            { label: 'PortSwigger: XSS', url: 'https://portswigger.net/web-security/cross-site-scripting' },
          ],
          cweId: 'CWE-79',
          owaspCategory: 'A03: Injection',
          vulnerabilityClass: 'xss-reflected',
          confidence: 'medium',
        });
        break;
      }
    }
  }

  // 28. Account Takeover indicators — weak session management
  const cookies = headerValue(ctx, 'set-cookie');
  if (cookies) {
    const sessionCookies = cookies.split(/,(?=\s*[a-zA-Z_-]+=)/).filter((c) => /session|sess|sid|token|auth/i.test(c));
    const weakCookies = sessionCookies.filter((c) => !/httponly/i.test(c) || !/secure/i.test(c));
    if (weakCookies.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'ato-session-weakness',
        category: 'security',
        severity: 'critical',
        title: 'Weak session cookie configuration enables account takeover',
        description: 'Session cookies are missing the HttpOnly and/or Secure flags. Without HttpOnly, JavaScript can read the cookie — enabling XSS-based session theft. Without Secure, the cookie is transmitted over unencrypted HTTP.',
        evidence: weakCookies.map((c) => c.trim().slice(0, 80)).join('\n'),
        impact: 'An attacker who finds an XSS vulnerability can steal the session cookie via document.cookie and take over the user\'s account. If the cookie is transmitted over HTTP, it can be intercepted on the network. Account takeover gives the attacker full access to the victim\'s data, settings, and permissions.',
        recommendation: 'Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all session and authentication cookies.',
        fixSteps: [
          'Add the HttpOnly flag to all session cookies to prevent JavaScript access.',
          'Add the Secure flag so cookies are only sent over HTTPS.',
          'Add SameSite=Strict (or Lax for cross-site links) to prevent CSRF.',
          'Regenerate session IDs after login to prevent session fixation.',
          'Implement session timeout and forced re-authentication for sensitive actions.',
        ],
        codeBefore: 'Set-Cookie: session=abc123; Path=/',
        codeAfter: 'Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/',
        references: [
          { label: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
          { label: 'OWASP Authentication Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
        ],
        cweId: 'CWE-614',
        owaspCategory: 'A07: Identification and Authentication Failures',
        vulnerabilityClass: 'account-takeover',
        confidence: 'high',
      });
    }
  }

  // 29. IDOR indicators — numeric IDs in URLs without access control checks
  if (urlObj) {
    const idParams = ['id', 'user_id', 'userid', 'uid', 'account', 'doc', 'file', 'order', 'invoice', 'profile'];
    for (const [key, value] of urlObj.searchParams.entries()) {
      if (idParams.includes(key.toLowerCase()) && /^\d+$/.test(value)) {
        findings.push({
          id: crypto.randomUUID(),
          ruleId: 'idor-indicator',
          category: 'security',
          severity: 'high',
          title: `Potential IDOR via "${key}" parameter`,
          description: `The URL contains a numeric "${key}" parameter (${value}). If the server does not verify that the authenticated user owns this resource, an attacker can change the number to access other users' data. This is an Insecure Direct Object Reference (IDOR) / Broken Access Control vulnerability.`,
          evidence: `URL: ${ctx.finalUrl}\nParameter: ${key}=${value}\nTest: Change ${key} to ${parseInt(value) + 1} or ${parseInt(value) - 1} and check if you can access another user's data.`,
          impact: 'IDOR exposes sensitive data belonging to other users. An attacker can read private documents, view other users\' profiles, access order histories, download invoices, or modify records they do not own. This is one of the most common and impactful vulnerability classes in bug bounty programs.',
          recommendation: 'Implement server-side authorization checks. Verify that the authenticated user owns or has permission to access the requested resource before returning it.',
          fixSteps: [
            `Test: Log in as user A, visit ${ctx.finalUrl.replace(/=.*$/, '=' + (parseInt(value) + 1))}, and check if user B's data appears.`,
            'On the server, add an ownership check: if (resource.userId !== currentUser.id) return 403.',
            'Use indirect references (UUIDs instead of sequential integers) to make enumeration harder.',
            'Implement role-based access control (RBAC) for admin-level resources.',
            'Log all access attempts and alert on unauthorized access patterns.',
          ],
          codeBefore: `// Vulnerable:\napp.get("/api/orders/:id", (req, res) => {\n  const order = db.query("SELECT * FROM orders WHERE id = " + req.params.id);\n  res.json(order); // no ownership check\n});`,
          codeAfter: `// Fixed:\napp.get("/api/orders/:id", auth, (req, res) => {\n  const order = db.query("SELECT * FROM orders WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);\n  if (!order) return res.status(403).send("Forbidden");\n  res.json(order);\n});`,
          references: [
            { label: 'OWASP Access Control Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html' },
            { label: 'PortSwigger: Access Control', url: 'https://portswigger.net/web-security/access-control' },
          ],
          cweId: 'CWE-639',
          owaspCategory: 'A01: Broken Access Control',
          vulnerabilityClass: 'idor',
          confidence: 'medium',
        });
        break;
      }
    }
  }

  // 30. Payment / financial logic bypass indicators
  const paymentForms = Array.from(doc.querySelectorAll('form')).filter((form) => {
    const inputs = Array.from(form.querySelectorAll('input, select, textarea'));
    return inputs.some((el) => {
      const name = (el.getAttribute('name') || '').toLowerCase();
      const id = (el.getAttribute('id') || '').toLowerCase();
      return /price|amount|total|cost|fee|charge|payment|cart|coupon|discount|vat|tax|shipping|currency/.test(name + ' ' + id);
    });
  });
  if (paymentForms.length > 0) {
    const priceInputs = Array.from(doc.querySelectorAll('input[name*="price" i], input[name*="amount" i], input[name*="total" i], input[name*="cost" i], input[name*="fee" i]'));
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'payment-bypass-indicator',
      category: 'security',
      severity: 'critical',
      title: priceInputs.length > 0
        ? 'Client-side price/amount field — potential payment bypass'
        : 'Payment form detected — potential financial logic bypass',
      description: priceInputs.length > 0
        ? 'A price or amount field is present in a client-side form. If the server trusts this value without re-validating, an attacker can modify the price before submission — paying nothing, a fraction, or even receiving a refund.'
        : 'A payment-related form was detected. Payment forms are common targets for logic bypass attacks: price manipulation, coupon stacking, negative quantity, currency switching, and tax miscalculation.',
      evidence: priceInputs.length > 0
        ? priceInputs.slice(0, 3).map((el) => `<input name="${el.getAttribute('name')}" value="${el.getAttribute('value') || ''}">`).join('\n')
        : `Payment form found with action="${paymentForms[0].getAttribute('action') || '(same page)'}"`,
      impact: 'Payment bypasses allow an attacker to purchase items for free or at a fraction of the cost, apply discounts multiple times, use negative values to receive refunds, or bypass quantity limits. This causes direct financial loss to the business.',
      recommendation: 'Never trust client-side price, amount, or quantity values. The server must re-compute the total from the product database and validate all quantities, discounts, and currency before processing payment.',
      fixSteps: [
        'On the server, recompute the order total from the product database — never use the value submitted by the client.',
        'Validate that quantities are positive integers and within reasonable limits.',
        'Server-side: verify coupons are valid, not expired, single-use, and apply the correct discount.',
        'Ensure the currency cannot be changed client-side to a weaker one.',
        'Use a payment gateway (Stripe, PayPal) that handles the amount server-side via a payment intent.',
        'Log all payment attempts and alert on anomalies (zero-amount orders, rapid discount usage).',
      ],
      codeBefore: `<!-- Vulnerable: client controls price -->\n<form action="/checkout" method="POST">\n  <input name="price" value="99.99">\n  <input name="quantity" value="1">\n  <button>Buy</button>\n</form>`,
      codeAfter: `// Fixed: server looks up price from DB\napp.post("/checkout", auth, async (req, res) => {\n  const product = await db.query("SELECT price FROM products WHERE id = $1", [req.body.productId]);\n  const total = product.price * req.body.quantity; // server-computed\n  const intent = await stripe.paymentIntents.create({ amount: total * 100, ... });\n});`,
      references: [
        { label: 'OWASP Business Logic Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html' },
        { label: 'HackerOne: Business Logic Bugs', url: 'https://www.hackerone.com/business-logic-vulnerabilities' },
      ],
      cweId: 'CWE-840',
      owaspCategory: 'A04: Insecure Design',
      vulnerabilityClass: 'payment-bypass',
      confidence: 'medium',
    });
  }

  // 31. Remote Code Execution indicators — server-side template injection / file upload
  const fileInputs = Array.from(doc.querySelectorAll('input[type="file"]'));
  if (fileInputs.length > 0) {
    const accept = fileInputs[0].getAttribute('accept') || '';
    if (!accept || /(\.php|\.jsp|\.asp|\.py|\.sh|\.exe|\.bat|\/)/.test(accept) || accept === '*/*') {
      findings.push({
        id: crypto.randomUUID(),
        ruleId: 'rce-file-upload',
        category: 'security',
        severity: 'critical',
        title: 'Unrestricted file upload — potential remote code execution',
        description: 'A file upload field was found without restrictive file type validation. If the server stores uploaded files in a web-accessible directory and does not validate the file type, an attacker can upload a script (PHP, JSP, ASPX) and execute it by visiting its URL — achieving remote code execution.',
        evidence: `<input type="file" ${accept ? `accept="${accept}"` : 'accept="(unrestricted)"'}>`,
        impact: 'Remote code execution gives the attacker full control of the server. They can read the database, steal credentials, pivot to internal networks, install backdoors, and persist access. This is one of the most severe vulnerability classes.',
        recommendation: 'Validate file types server-side using both extension and MIME type (magic bytes). Store uploads outside the web root or in a CDN that serves them as static content. Never execute uploaded files.',
        fixSteps: [
          'Validate the file extension against an allowlist (jpg, png, pdf, docx) on the server.',
          'Check the file\'s magic bytes (not just the Content-Type header, which can be spoofed).',
          'Store uploaded files outside the web root, or use a dedicated blob storage (S3, GCS).',
          'If files must be web-accessible, serve them via a CDN that forces download (Content-Disposition: attachment).',
          'Strip EXIF metadata and re-encode images to remove embedded payloads.',
          'Set the upload directory to disallow script execution (e.g. php_flag engine off for Apache).',
        ],
        codeBefore: `<!-- Vulnerable: no server-side validation -->\n<input type="file" name="avatar">\n// Server: just saves the file\napp.post("/upload", upload.single("avatar"), (req, res) => {\n  req.file.mv("./public/uploads/" + req.file.name);\n});`,
        codeAfter: `// Fixed: validate type, rename, store outside webroot\napp.post("/upload", upload.single("avatar"), (req, res) => {\n  const allowed = ["image/jpeg", "image/png"];\n  if (!allowed.includes(req.file.mimetype)) return res.status(400).send("Invalid type");\n  const safeName = crypto.randomUUID() + ".jpg";\n  fs.writeFile("./storage/" + safeName, req.file.buffer); // not web-accessible\n});`,
        references: [
          { label: 'OWASP File Upload Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html' },
          { label: 'PortSwigger: File Upload Vulnerabilities', url: 'https://portswigger.net/web-security/file-upload' },
        ],
        cweId: 'CWE-434',
        owaspCategory: 'A04: Insecure Design',
        vulnerabilityClass: 'remote-code-execution',
        confidence: 'medium',
      });
    }
  }

  return findings;
};
