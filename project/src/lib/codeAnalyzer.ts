import type { CodeFinding, CodeLanguage, CodeAnalysisResult } from './types';

// ============================================================
// Source Code Vulnerability Analyzer
// Detects security bugs in JavaScript, TypeScript, Python, PHP,
// Java, Go, Ruby, and C# source code.
// ============================================================

interface CodeRule {
  id: string;
  languages: CodeLanguage[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  pattern: RegExp;
  impact: string;
  recommendation: string;
  fixSteps: string[];
  codeBefore?: string;
  codeAfter?: string;
  cweId: string;
  owaspCategory: string;
}

const CODE_RULES: CodeRule[] = [
  // --- Hardcoded secrets ---
  {
    id: 'hardcoded-password',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp', 'generic'],
    severity: 'critical',
    title: 'Hardcoded password detected',
    description: 'A password appears to be hardcoded in the source. Anyone with access to the code or compiled binary can extract it.',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi,
    impact: 'Hardcoded passwords can be extracted from source code, compiled binaries, or repositories, leading to unauthorized access.',
    recommendation: 'Store passwords in environment variables or a secrets manager. Never commit credentials to source code.',
    fixSteps: ['Remove the hardcoded password from source code.', 'Store the password in an environment variable or secrets manager.', 'Read it at runtime: process.env.PASSWORD or equivalent.', 'Rotate the exposed password immediately.'],
    codeBefore: 'const password = "admin123";',
    codeAfter: 'const password = process.env.PASSWORD;',
    cweId: 'CWE-798',
    owaspCategory: 'A07: Identification and Authentication Failures',
  },
  {
    id: 'hardcoded-api-key',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp', 'generic'],
    severity: 'critical',
    title: 'Hardcoded API key detected',
    description: 'An API key appears to be hardcoded in the source code.',
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/gi,
    impact: 'Extracted API keys grant access to third-party services, cloud infrastructure, or payment systems.',
    recommendation: 'Move API keys to environment variables or a secrets manager.',
    fixSteps: ['Remove the hardcoded key.', 'Store it in an environment variable.', 'Rotate the exposed key immediately.'],
    codeBefore: 'const apiKey = "sk_live_abc123...";',
    codeAfter: 'const apiKey = process.env.API_KEY;',
    cweId: 'CWE-798',
    owaspCategory: 'A07: Identification and Authentication Failures',
  },
  // --- SQL Injection ---
  {
    id: 'sql-injection-string-concat',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'generic'],
    severity: 'critical',
    title: 'Potential SQL injection via string concatenation',
    description: 'User input appears to be concatenated directly into a SQL query string. This allows an attacker to inject arbitrary SQL.',
    pattern: /(?:query|execute|exec|run|sql)\s*\(\s*['"`].*(?:\+\s*\$?\{?\w|\$\w|\.format|%s|\.format\()/gi,
    impact: 'SQL injection can lead to complete database compromise, data exfiltration, authentication bypass, and remote code execution.',
    recommendation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.',
    fixSteps: ['Replace string concatenation with parameterized queries.', 'Use the database driver\'s prepared statement API.', 'Validate and sanitize all inputs.', 'Use an ORM that handles escaping automatically.'],
    codeBefore: 'db.query("SELECT * FROM users WHERE id = " + userId);',
    codeAfter: 'db.query("SELECT * FROM users WHERE id = $1", [userId]);',
    cweId: 'CWE-89',
    owaspCategory: 'A03: Injection',
  },
  {
    id: 'sql-injection-template-literal',
    languages: ['javascript', 'typescript'],
    severity: 'critical',
    title: 'Potential SQL injection via template literal',
    description: 'A SQL query uses a template literal with embedded variables. If those variables come from user input, this is a SQL injection vulnerability.',
    pattern: /(?:query|execute|exec|run)\s*\(`[^`]*\$\{[^}]+\}[^`]*`\)/gi,
    impact: 'SQL injection can lead to complete database compromise, data exfiltration, and authentication bypass.',
    recommendation: 'Use parameterized queries with placeholders instead of template literals for SQL.',
    fixSteps: ['Replace template literals with parameterized queries.', 'Use $1, $2 placeholders (PostgreSQL) or ? (MySQL/SQLite).', 'Pass user input as query parameters, not interpolated strings.'],
    codeBefore: 'db.query(`SELECT * FROM users WHERE name = \'${name}\'`);',
    codeAfter: 'db.query(\'SELECT * FROM users WHERE name = $1\', [name]);',
    cweId: 'CWE-89',
    owaspCategory: 'A03: Injection',
  },
  // --- Command Injection ---
  {
    id: 'command-injection',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'generic'],
    severity: 'critical',
    title: 'Potential command injection via exec/spawn with user input',
    description: 'User input appears to be passed to a system command execution function. An attacker can inject shell commands.',
    pattern: /(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:call|run|Popen)|os\.system)\s*\([^)]*\$\{?\w|(?:exec|execSync|spawn)\s*\([^)]*\+/gi,
    impact: 'Command injection allows an attacker to execute arbitrary operating system commands, leading to full server compromise.',
    recommendation: 'Avoid passing user input to command execution. If necessary, use argument arrays instead of shell strings and validate input.',
    fixSteps: ['Avoid shell command execution with user input entirely if possible.', 'Use array-based argument passing: execFile("ls", [userInput]).', 'Never use exec() with string concatenation — it invokes a shell.', 'Validate input against an allowlist of expected values.'],
    codeBefore: 'exec(`ls ${userInput}`);',
    codeAfter: 'execFile("ls", [validatedInput]); // no shell, array args',
    cweId: 'CWE-78',
    owaspCategory: 'A03: Injection',
  },
  // --- XSS sinks ---
  {
    id: 'xss-innerhtml',
    languages: ['javascript', 'typescript'],
    severity: 'high',
    title: 'Potential XSS via innerHTML with user input',
    description: 'User input is assigned to innerHTML, which executes any embedded HTML or script. This is a cross-site scripting (XSS) vector.',
    pattern: /\.innerHTML\s*=\s*[^;]*\$\{|\.innerHTML\s*=\s*[^;]*\b(?:document|req|input|data|user|param|value)\b/gi,
    impact: 'XSS allows an attacker to execute arbitrary JavaScript in the victim\'s browser, steal session tokens, and perform actions on behalf of the user.',
    recommendation: 'Use textContent instead of innerHTML, or sanitize the input with DOMPurify before assigning to innerHTML.',
    fixSteps: ['Replace innerHTML with textContent when no HTML formatting is needed.', 'If HTML is required, sanitize with DOMPurify: el.innerHTML = DOMPurify.sanitize(input).', 'Use a templating framework that auto-escapes output.'],
    codeBefore: 'element.innerHTML = `<div>${userInput}</div>`;',
    codeAfter: 'element.textContent = userInput;\n// or: element.innerHTML = DOMPurify.sanitize(userInput);',
    cweId: 'CWE-79',
    owaspCategory: 'A03: Injection',
  },
  {
    id: 'xss-document-write',
    languages: ['javascript', 'typescript'],
    severity: 'high',
    title: 'Potential XSS via document.write with user input',
    description: 'document.write() is called with what appears to be user input. This can inject arbitrary HTML and scripts into the page.',
    pattern: /document\.write\s*\([^)]*(?:\$\{|req\.|input|user|param|location\.)/gi,
    impact: 'XSS via document.write allows attackers to inject and execute arbitrary scripts.',
    recommendation: 'Avoid document.write entirely. Use safe DOM manipulation methods.',
    fixSteps: ['Remove document.write calls.', 'Use document.createElement and appendChild for dynamic content.', 'Use textContent for text-only content.'],
    codeBefore: 'document.write(`<div>${location.hash}</div>`);',
    codeAfter: 'const el = document.createElement("div");\nel.textContent = location.hash;\ndocument.body.appendChild(el);',
    cweId: 'CWE-79',
    owaspCategory: 'A03: Injection',
  },
  // --- eval ---
  {
    id: 'eval-usage',
    languages: ['javascript', 'typescript'],
    severity: 'high',
    title: 'Use of eval() detected',
    description: 'eval() executes arbitrary strings as JavaScript. If any user input reaches eval(), it results in code injection.',
    pattern: /\beval\s*\(/g,
    impact: 'eval() with user input allows arbitrary code execution, equivalent to a complete security bypass.',
    recommendation: 'Remove eval(). Use JSON.parse() for JSON data, and Function() only with static code.',
    fixSteps: ['Find every eval() call.', 'If parsing JSON, use JSON.parse().', 'If dynamic computation is needed, refactor to avoid eval.', 'Never pass user input to eval().'],
    codeBefore: 'const result = eval(userExpression);',
    codeAfter: 'const result = JSON.parse(jsonString);',
    cweId: 'CWE-95',
    owaspCategory: 'A03: Injection',
  },
  // --- Insecure crypto ---
  {
    id: 'md5-usage',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'generic'],
    severity: 'medium',
    title: 'MD5 hash function used (weak cryptographic hash)',
    description: 'MD5 is a cryptographically broken hash function. It is vulnerable to collision attacks and must not be used for security purposes.',
    pattern: /\bmd5\s*\(|\.md5\s*\(|hashlib\.md5\s*\(/gi,
    impact: 'MD5 collisions allow attackers to forge certificates, bypass integrity checks, and break digital signatures.',
    recommendation: 'Replace MD5 with SHA-256 or SHA-3 for security purposes. Use bcrypt, scrypt, or argon2 for password hashing.',
    fixSteps: ['Identify all MD5 usage.', 'For password hashing, use bcrypt, scrypt, or argon2.', 'For data integrity, use SHA-256 or SHA-3.', 'For HMAC, use HMAC-SHA256.'],
    codeBefore: 'const hash = md5(password);',
    codeAfter: 'const hash = await bcrypt.hash(password, 12);',
    cweId: 'CWE-327',
    owaspCategory: 'A02: Cryptographic Failures',
  },
  {
    id: 'sha1-usage',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'generic'],
    severity: 'medium',
    title: 'SHA-1 hash function used (weak cryptographic hash)',
    description: 'SHA-1 is deprecated and vulnerable to collision attacks. It should not be used for security-sensitive purposes.',
    pattern: /\bsha1\s*\(|\.sha1\s*\(|hashlib\.sha1\s*\(/gi,
    impact: 'SHA-1 collisions allow forgery of digital signatures and certificates.',
    recommendation: 'Replace SHA-1 with SHA-256 or SHA-3.',
    fixSteps: ['Replace all SHA-1 usage with SHA-256.', 'For password hashing, use bcrypt or argon2 instead.'],
    codeBefore: 'const hash = sha1(data);',
    codeAfter: 'const hash = crypto.createHash("sha256").update(data).digest("hex");',
    cweId: 'CWE-327',
    owaspCategory: 'A02: Cryptographic Failures',
  },
  {
    id: 'math-random-for-crypto',
    languages: ['javascript', 'typescript'],
    severity: 'high',
    title: 'Math.random() used for cryptographic purposes',
    description: 'Math.random() is not cryptographically secure. Its output can be predicted, making it unsafe for tokens, passwords, or session IDs.',
    pattern: /Math\.random\s*\(\s*\)/gi,
    impact: 'Predictable random values allow attackers to guess tokens, session IDs, and nonces, leading to authentication bypass.',
    recommendation: 'Use crypto.getRandomValues() or crypto.randomBytes() for any security-sensitive randomness.',
    fixSteps: ['Find all Math.random() calls used for security purposes.', 'Replace with crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js).', 'Use UUID v4 (crypto.randomUUID()) for unique identifiers.'],
    codeBefore: 'const token = Math.random().toString(36);',
    codeAfter: 'const array = new Uint8Array(16);\ncrypto.getRandomValues(array);\nconst token = array.join("");',
    cweId: 'CWE-338',
    owaspCategory: 'A02: Cryptographic Failures',
  },
  // --- Insecure deserialization ---
  {
    id: 'insecure-deserialize',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'generic'],
    severity: 'high',
    title: 'Insecure deserialization detected',
    description: 'User-controlled data appears to be deserialized without validation. Deserialization of untrusted data can lead to remote code execution.',
    pattern: /(?:eval\s*\(\s*JSON\.parse|pickle\.loads|Marshal\.load|unserialize|yaml\.load)\s*\(/gi,
    impact: 'Insecure deserialization can allow an attacker to execute arbitrary code, bypass authentication, or escalate privileges.',
    recommendation: 'Validate input before deserialization, use safe serialization formats (JSON), and avoid deserializing untrusted data.',
    fixSteps: ['Avoid deserializing untrusted data.', 'Use JSON.parse() instead of eval or pickle for structured data.', 'If using pickle/Marshal, validate the data source first.', 'Use allowlists for deserializable classes.'],
    codeBefore: 'pickle.loads(user_data)',
    codeAfter: 'json.loads(user_data) // JSON is safe to parse',
    cweId: 'CWE-502',
    owaspCategory: 'A08: Software and Data Integrity Failures',
  },
  // --- Path traversal ---
  {
    id: 'path-traversal',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'generic'],
    severity: 'high',
    title: 'Potential path traversal via user input in file path',
    description: 'User input appears to be used in a file path operation. An attacker could use ../ sequences to access files outside the intended directory.',
    pattern: /(?:readFile|readFileSync|open|fopen|file_get_contents|require|include|import)\s*\([^)]*(?:req\.|params|query|input|user|\$\{|\.format)/gi,
    impact: 'Path traversal allows an attacker to read arbitrary files on the server, including configuration files, source code, and credentials.',
    recommendation: 'Validate and sanitize file paths. Use path.resolve() and verify the result is within the allowed directory.',
    fixSteps: ['Resolve the user-supplied path with path.resolve().', 'Check that the resolved path starts with the allowed base directory.', 'Reject paths containing ../ or absolute paths.', 'Use an allowlist of permitted filenames.'],
    codeBefore: 'fs.readFile(req.params.file);',
    codeAfter: 'const safe = path.resolve(baseDir, req.params.file);\nif (!safe.startsWith(baseDir)) throw new Error("Invalid path");\nfs.readFile(safe);',
    cweId: 'CWE-22',
    owaspCategory: 'A01: Broken Access Control',
  },
  // --- SSRF ---
  {
    id: 'ssrf-fetch-user-url',
    languages: ['javascript', 'typescript', 'python', 'go', 'generic'],
    severity: 'high',
    title: 'Potential SSRF via user-controlled URL in fetch/request',
    description: 'A URL from user input appears to be passed directly to fetch/request. An attacker can use this to make the server fetch internal resources.',
    pattern: /(?:fetch|request|axios|requests\.get|http\.Get)\s*\(\s*(?:req\.|params|query|input|user|\$\{)/gi,
    impact: 'SSRF allows an attacker to access internal services, cloud metadata endpoints (169.254.169.254), and bypass firewalls.',
    recommendation: 'Validate and restrict user-supplied URLs. Block internal IP ranges and use an allowlist of permitted domains.',
    fixSteps: ['Parse the user-supplied URL and validate the protocol (http/https only).', 'Resolve the hostname and check it is not a private/internal IP.', 'Block requests to 127.0.0.1, 10.x, 172.16-31.x, 192.168.x, and 169.254.x.', 'Use an allowlist of permitted external domains when possible.'],
    codeBefore: 'const data = await fetch(req.body.url);',
    codeAfter: 'const url = new URL(req.body.url);\nif (!isAllowedDomain(url.hostname)) throw new Error();\nconst data = await fetch(url);',
    cweId: 'CWE-918',
    owaspCategory: 'A10: Server-Side Request Forgery',
  },
  // --- Debug code in production ---
  {
    id: 'debugger-statement',
    languages: ['javascript', 'typescript'],
    severity: 'low',
    title: 'debugger statement left in code',
    description: 'A debugger statement is present. In development, this pauses execution. In production, it can cause unexpected behavior in browsers with devtools open.',
    pattern: /\bdebugger\b/g,
    impact: 'Can cause unexpected page freezes for users with developer tools open; indicates development code in production.',
    recommendation: 'Remove debugger statements before deploying to production.',
    fixSteps: ['Remove all debugger statements.', 'Configure your build tool to strip them in production.'],
    codeBefore: 'function process(data) {\n  debugger;\n  return transform(data);\n}',
    codeAfter: 'function process(data) {\n  return transform(data);\n}',
    cweId: 'CWE-489',
    owaspCategory: 'A05: Security Misconfiguration',
  },
  // --- Insecure random (Python) ---
  {
    id: 'python-random-for-security',
    languages: ['python'],
    severity: 'high',
    title: 'random module used for security-sensitive values (Python)',
    description: 'Python\'s random module is not cryptographically secure. Use secrets or os.urandom for tokens, passwords, and session IDs.',
    pattern: /random\.(?:random|randint|choice|choices|sample)\s*\(/g,
    impact: 'Predictable random values allow attackers to guess tokens and session IDs.',
    recommendation: 'Use the secrets module (Python 3.6+) or os.urandom() for cryptographic randomness.',
    fixSteps: ['Import the secrets module.', 'Replace random.randint with secrets.randbelow.', 'Replace random.choice with secrets.choice.', 'For tokens, use secrets.token_urlsafe().'],
    codeBefore: 'import random\ntoken = "".join(random.choice(string.ascii_letters) for _ in range(32))',
    codeAfter: 'import secrets\ntoken = secrets.token_urlsafe(32)',
    cweId: 'CWE-338',
    owaspCategory: 'A02: Cryptographic Failures',
  },
  // --- Disabled TLS verification ---
  {
    id: 'tls-verification-disabled',
    languages: ['javascript', 'typescript', 'python', 'generic'],
    severity: 'high',
    title: 'TLS certificate verification disabled',
    description: 'TLS/SSL certificate verification appears to be disabled, making the connection vulnerable to man-in-the-middle attacks.',
    pattern: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CERT_NONE|ssl\._create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/gi,
    impact: 'Disabling TLS verification allows an attacker to intercept and modify all encrypted traffic.',
    recommendation: 'Never disable TLS certificate verification. Fix the certificate issue instead.',
    fixSteps: ['Remove the code that disables TLS verification.', 'If certificates are self-signed, add the CA to the trust store instead.', 'Never set rejectUnauthorized: false or verify=False in production.'],
    codeBefore: 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    codeAfter: '// Fix the certificate chain instead of disabling verification',
    cweId: 'CWE-295',
    owaspCategory: 'A02: Cryptographic Failures',
  },
  // --- Open redirect ---
  {
    id: 'open-redirect-code',
    languages: ['javascript', 'typescript', 'python', 'php', 'generic'],
    severity: 'medium',
    title: 'Potential open redirect via user-controlled URL',
    description: 'A redirect appears to use user input without validation, allowing an attacker to redirect users to malicious sites.',
    pattern: /(?:redirect|res\.redirect|header\s*\(\s*['"]Location|window\.location)\s*[=(]\s*[^;)]*(?:req\.|params|query|input|user|\$\{)/gi,
    impact: 'Open redirects are used in phishing campaigns — a trusted domain redirects victims to a look-alike malicious site.',
    recommendation: 'Validate redirect destinations against an allowlist of trusted URLs.',
    fixSteps: ['Maintain an allowlist of permitted redirect destinations.', 'Validate the user-supplied URL against the allowlist before redirecting.', 'Only allow relative paths or same-origin URLs.', 'Never redirect to URLs from query parameters without validation.'],
    codeBefore: 'res.redirect(req.query.returnUrl);',
    codeAfter: 'const allowed = ["/dashboard", "/profile"];\nif (!allowed.includes(req.query.returnUrl)) return res.status(400).send("Invalid redirect");\nres.redirect(req.query.returnUrl);',
    cweId: 'CWE-601',
    owaspCategory: 'A01: Broken Access Control',
  },
  // --- Console.log with sensitive data ---
  {
    id: 'console-log-sensitive',
    languages: ['javascript', 'typescript'],
    severity: 'low',
    title: 'Console logging of potentially sensitive data',
    description: 'console.log appears to log variables that may contain sensitive data (passwords, tokens, users, credentials).',
    pattern: /console\.log\s*\([^)]*(?:password|token|secret|credential|user|auth|session|cookie|key)/gi,
    impact: 'Sensitive data logged to the browser console is visible to anyone with devtools open and may persist in logs.',
    recommendation: 'Remove logging of sensitive data. Use structured logging that redacts sensitive fields.',
    fixSteps: ['Remove console.log calls that output sensitive data.', 'If logging is needed, redact sensitive fields before logging.', 'Use a logging library that supports field-level redaction.'],
    codeBefore: 'console.log("User:", user);\nconsole.log("Token:", token);',
    codeAfter: 'console.log("User ID:", user.id); // only log non-sensitive identifiers',
    cweId: 'CWE-532',
    owaspCategory: 'A09: Security Logging and Monitoring Failures',
  },
  // --- Hardcoded connection strings ---
  {
    id: 'hardcoded-connection-string',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go', 'ruby', 'csharp', 'generic'],
    severity: 'high',
    title: 'Hardcoded database connection string detected',
    description: 'A database connection string with credentials appears to be hardcoded in the source.',
    pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^\s'"]*:[^\s'"@]+@[^\s'"]+/gi,
    impact: 'Database credentials in source code are exposed to anyone with code access and may be committed to version control.',
    recommendation: 'Store connection strings in environment variables. Never commit them to source code.',
    fixSteps: ['Remove the hardcoded connection string.', 'Store it in an environment variable: process.env.DATABASE_URL.', 'Rotate the database credentials immediately if they were committed to a repository.'],
    codeBefore: 'const conn = "mongodb://user:pass123@localhost:27017/db";',
    codeAfter: 'const conn = process.env.DATABASE_URL;',
    cweId: 'CWE-798',
    owaspCategory: 'A07: Identification and Authentication Failures',
  },
];

export function detectLanguage(code: string): CodeLanguage {
  if (/^\s*#!/.test(code) && /python/.test(code.slice(0, 50))) return 'python';
  if (/\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import|print\s*\(/.test(code) && !/(?:=>|const|let|var)\s/.test(code)) return 'python';
  if (/(?:public\s+class|System\.out|import\s+java\.)/.test(code)) return 'java';
  if (/<\?php|function\s+\w+\s*\([^)]*\)\s*{/.test(code) && /\$\w+/.test(code)) return 'php';
  if (/(?:func\s+\w+|package\s+main)/.test(code)) return 'go';
  if (/(?:def\s+\w+|end\s*$|puts\s+|require\s+)/.test(code) && !/(?:function|=>)/.test(code)) return 'ruby';
  if (/(?:using\s+System|namespace\s+\w+|void\s+Main)/.test(code)) return 'csharp';
  if (/(?:interface\s+\w+|type\s+\w+\s*=|:\s*(?:string|number|boolean)\b)/.test(code)) return 'typescript';
  if (/(?:function|const|let|var|=>|console\.log|require\()/.test(code)) return 'javascript';
  return 'generic';
}

export function analyzeCode(code: string, language?: CodeLanguage): CodeAnalysisResult {
  const startTime = Date.now();
  const detectedLang = language || detectLanguage(code);
  const lines = code.split('\n');
  const totalLines = lines.length;
  const findings: CodeFinding[] = [];

  for (const rule of CODE_RULES) {
    if (!rule.languages.includes(detectedLang) && !rule.languages.includes('generic')) continue;

    let match: RegExpExecArray | null;
    const globalPattern = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');

    while ((match = globalPattern.exec(code)) !== null) {
      const matchStart = match.index;
      const beforeMatch = code.slice(0, matchStart);
      const lineStart = beforeMatch.split('\n').length;
      const matchLines = match[0].split('\n').length;
      const lineEnd = lineStart + matchLines - 1;

      // Get a snippet around the match
      const snippetStart = Math.max(0, lineStart - 2);
      const snippetEnd = Math.min(lines.length, lineEnd + 2);
      const snippet = lines.slice(snippetStart, snippetEnd).map((l, i) => {
        const lineNum = snippetStart + i + 1;
        const marker = lineNum >= lineStart && lineNum <= lineEnd ? '>>>' : '   ';
        return `${marker} ${String(lineNum).padStart(4, ' ')} | ${l}`;
      }).join('\n');

      // Deduplicate by ruleId + line
      if (findings.some((f) => f.ruleId === rule.id && f.lineStart === lineStart)) continue;

      findings.push({
        id: crypto.randomUUID(),
        ruleId: rule.id,
        language: detectedLang,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        lineStart,
        lineEnd,
        snippet,
        impact: rule.impact,
        recommendation: rule.recommendation,
        fixSteps: rule.fixSteps,
        codeBefore: rule.codeBefore,
        codeAfter: rule.codeAfter,
        references: rule.cweId ? [
          { label: `${rule.cweId} Details`, url: `https://cwe.mitre.org/data/definitions/${rule.cweId.replace('CWE-', '')}.html` },
          { label: 'OWASP Top 10', url: 'https://owasp.org/Top10/' },
        ] : [],
        cweId: rule.cweId,
        owaspCategory: rule.owaspCategory,
        confidence: 'high',
      });

      if (findings.length >= 100) break; // cap
    }
  }

  // Sort by severity then line number
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => {
    if (sevOrder[a.severity] !== sevOrder[b.severity]) return sevOrder[a.severity] - sevOrder[b.severity];
    return a.lineStart - b.lineStart;
  });

  return {
    findings,
    language: detectedLang,
    totalLines,
    linesScanned: totalLines,
    scanDuration: Date.now() - startTime,
  };
}
