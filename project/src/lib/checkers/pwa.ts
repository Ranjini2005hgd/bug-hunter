import type { Checker, Finding, ScanContext } from '../types';

export const checkPwa: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc, headers } = ctx;

  // 1. Missing web app manifest
  const manifest = doc.querySelector('link[rel="manifest"]');
  if (!manifest) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-manifest',
      category: 'pwa',
      severity: 'medium',
      title: 'No web app manifest linked',
      description: 'The page has no <link rel="manifest">. A manifest enables "Add to Home Screen" and makes the site installable as a Progressive Web App.',
      impact: 'Users cannot install the site to their home screen; no app-like experience on mobile.',
      recommendation: 'Create a web app manifest and link it from every page.',
      fixSteps: [
        'Create a manifest.json with name, short_name, icons, start_url, display, and theme_color.',
        'Add <link rel="manifest" href="/manifest.json"> in <head>.',
        'Add <meta name="theme-color" content="#xxxxxx"> for the browser chrome color.',
      ],
      codeBefore: '(no manifest link)',
      codeAfter: '<link rel="manifest" href="/manifest.json">\n<meta name="theme-color" content="#0f172a">',
      references: [{ label: 'MDN: Web App Manifest', url: 'https://developer.mozilla.org/en-US/docs/Web/Manifest' }],
      confidence: 'certain',
    });
  }

  // 2. Missing theme-color meta
  if (!doc.querySelector('meta[name="theme-color"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-theme-color',
      category: 'pwa',
      severity: 'low',
      title: 'Missing theme-color meta tag',
      description: 'The page has no <meta name="theme-color">. Without it, mobile browsers do not match the browser chrome to your brand color.',
      impact: 'Less polished mobile experience; browser UI uses the default color.',
      recommendation: 'Add a theme-color meta tag matching your brand color.',
      fixSteps: [
        'Add <meta name="theme-color" content="#0f172a"> to <head>.',
        'Optionally add media variants: <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#000000">.',
      ],
      codeBefore: '(no theme-color)',
      codeAfter: '<meta name="theme-color" content="#0f172a">',
      references: [{ label: 'MDN: theme-color', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name/theme-color' }],
      confidence: 'certain',
    });
  }

  // 3. Missing apple-touch-icon (iOS home screen icon)
  if (!doc.querySelector('link[rel="apple-touch-icon"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-apple-touch-icon',
      category: 'pwa',
      severity: 'low',
      title: 'Missing apple-touch-icon for iOS home screen',
      description: 'The page has no <link rel="apple-touch-icon">. When iOS users add the site to their home screen, they get a generic screenshot icon instead of your brand icon.',
      impact: 'Unbranded home screen icon on iOS; less professional PWA experience.',
      recommendation: 'Add a 180x180 apple-touch-icon link.',
      fixSteps: [
        'Create a 180x180 PNG icon of your logo.',
        'Add <link rel="apple-touch-icon" href="/apple-touch-icon.png">.',
      ],
      codeBefore: '(no apple-touch-icon)',
      codeAfter: '<link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180">',
      references: [{ label: 'Apple: Configure web apps', url: 'https://developer.apple.com/library/archive/documentation/AppleApplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html' }],
      confidence: 'high',
    });
  }

  // 4. No service worker registration detected
  const hasSwRegistration = /navigator\.serviceWorker\.register|workbox|self\.__WB_MANIFEST/i.test(
    Array.from(doc.querySelectorAll('script')).map((s) => s.textContent || '').join('\n'),
  );
  if (!hasSwRegistration && !manifest) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'no-service-worker',
      category: 'pwa',
      severity: 'low',
      title: 'No service worker registration detected',
      description: 'No service worker registration was found in the page scripts. A service worker enables offline support, background sync, and push notifications \u2014 the core of a PWA.',
      impact: 'The site cannot work offline or send push notifications; not installable as a true PWA.',
      recommendation: 'Register a service worker with at least a basic caching strategy.',
      fixSteps: [
        'Create a service worker file (sw.js) with a caching strategy (e.g. Workbox or a hand-written cache-first strategy).',
        'Register it from your main script: navigator.serviceWorker.register("/sw.js").',
        'Test offline behavior in browser devtools (Application > Service Workers).',
      ],
      codeBefore: '(no service worker)',
      codeAfter: 'if ("serviceWorker" in navigator) {\n  navigator.serviceWorker.register("/sw.js");\n}',
      references: [{ label: 'MDN: Service Worker API', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API' }, { label: 'Workbox', url: 'https://developer.chrome.com/docs/workbox/' }],
      confidence: 'medium',
    });
  }

  // 5. HTTPS is a PWA prerequisite (covered by security; skip to avoid dup)

  // 6. X-UA-Compatible meta (legacy IE hint)
  if (doc.querySelector('meta[http-equiv="x-ua-compatible"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'x-ua-compatible',
      category: 'pwa',
      severity: 'info',
      title: 'Legacy X-UA-Compatible meta tag present',
      description: 'The page includes a <meta http-equiv="X-UA-Compatible"> tag targeting old Internet Explorer versions. IE is retired and this tag is obsolete.',
      impact: 'No impact in modern browsers; signals outdated boilerplate.',
      recommendation: 'Remove the X-UA-Compatible meta tag.',
      fixSteps: ['Remove the <meta http-equiv="X-UA-Compatible" content="IE=edge"> line.'],
      codeBefore: '<meta http-equiv="X-UA-Compatible" content="IE=edge">',
      codeAfter: '(removed)',
      references: [{ label: 'MDN: X-UA-Compatible (deprecated)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-UA-Compatible' }],
      confidence: 'certain',
    });
  }

  // 7. Missing apple-mobile-web-app-capable
  if (!doc.querySelector('meta[name="apple-mobile-web-app-capable"]') && !doc.querySelector('meta[name="mobile-web-app-capable"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-apple-web-app-capable',
      category: 'pwa',
      severity: 'info',
      title: 'Missing apple-mobile-web-app-capable meta (standalone iOS mode)',
      description: 'Without this meta tag, iOS opens the home-screen bookmark in Safari with browser chrome, not in a standalone app-like view.',
      impact: 'Less app-like experience when launched from the iOS home screen.',
      recommendation: 'Add the apple-mobile-web-app-capable meta tag if you want a standalone experience on iOS.',
      fixSteps: [
        'Add <meta name="apple-mobile-web-app-capable" content="yes">.',
        'Add <meta name="apple-mobile-web-app-status-bar-style" content="default"> for status bar styling.',
      ],
      codeBefore: '(no apple-mobile-web-app-capable)',
      codeAfter: '<meta name="apple-mobile-web-app-capable" content="yes">',
      references: [{ label: 'Apple: Configure web apps', url: 'https://developer.apple.com/library/archive/documentation/AppleApplications/Reference/SafariWebContent/ConfiguringWebApplications/ConfiguringWebApplications.html' }],
      confidence: 'high',
    });
  }

  // 8. Service-Worker-Allowed or navigate mode inferred; we skip deeper checks.

  // Check Cache-Control for sw.js requirement not measurable here.
  void headers;

  return findings;
};
