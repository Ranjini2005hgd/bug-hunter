import type { Checker, Finding, ScanContext } from '../types';

export const checkPerformance: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc, html } = ctx;

  // 1. Render-blocking stylesheets in <head> without preload/async
  const headStylesheets = Array.from(doc.querySelectorAll('head link[rel="stylesheet"]'));
  if (headStylesheets.length > 2) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'render-blocking-css',
      category: 'performance',
      severity: 'medium',
      title: `${headStylesheets.length} render-blocking stylesheets in <head>`,
      description: 'Multiple external stylesheets in <head> block first render \u2014 the browser cannot paint until all are downloaded and parsed.',
      impact: 'Slower First Contentful Paint and Largest Contentful Paint, hurting Core Web Vitals.',
      recommendation: 'Inline critical CSS and defer non-critical stylesheets with rel="preload" and an onload swap.',
      fixSteps: [
        'Identify the CSS needed for above-the-fold content and inline it in a <style> block.',
        'Load remaining stylesheets with <link rel="preload" as="style" href="..." onload="this.rel=\'stylesheet\'">.',
        'Provide a <noscript><link rel="stylesheet" href="..."></noscript> fallback.',
        'Combine and minify CSS to reduce request count.',
      ],
      codeBefore: '<link rel="stylesheet" href="reset.css">\n<link rel="stylesheet" href="layout.css">\n<link rel="stylesheet" href="theme.css">',
      codeAfter: '<style>/* inlined critical CSS */</style>\n<link rel="preload" as="style" href="full.css" onload="this.rel=\'stylesheet\'">\n<noscript><link rel="stylesheet" href="full.css"></noscript>',
      references: [{ label: 'web.dev: Render-blocking resources', url: 'https://web.dev/render-blocking-resources/' }],
      confidence: 'high',
    });
  }

  // 2. Scripts in <head> without defer/async
  const headScripts = Array.from(doc.querySelectorAll('head script[src]')).filter(
    (s) => !s.hasAttribute('defer') && !s.hasAttribute('async'),
  );
  if (headScripts.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'render-blocking-js',
      category: 'performance',
      severity: 'medium',
      title: `${headScripts.length} render-blocking script${headScripts.length > 1 ? 's' : ''} in <head>`,
      description: 'External scripts in <head> without async or defer block HTML parsing until they download and execute, delaying first paint.',
      impact: 'Delayed First Contentful Paint and poorer Core Web Vitals scores.',
      recommendation: 'Add defer to non-critical head scripts, or move them to the end of <body>.',
      fixSteps: [
        'Add the defer attribute to head scripts that don\u2019t need to run immediately.',
        'For scripts that must run early, use async (they execute as soon as they load).',
        'Prefer defer for scripts that depend on the DOM being parsed.',
      ],
      codeBefore: '<head>\n  <script src="analytics.js"></script>\n</head>',
      codeAfter: '<head>\n  <script src="analytics.js" defer></script>\n</head>',
      references: [{ label: 'MDN: script element \u2014 defer', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script#attr-defer' }],
      confidence: 'high',
    });
  }

  // 3. Large HTML payload
  const htmlBytes = new Blob([html]).size;
  if (htmlBytes > 200_000) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'large-html',
      category: 'performance',
      severity: 'medium',
      title: `HTML document is large (${(htmlBytes / 1024).toFixed(0)} KB)`,
      description: 'The HTML document exceeds 200KB. Large documents take longer to download, parse, and render, especially on mobile networks.',
      impact: 'Slower page load, higher data cost for users, and poorer mobile experience.',
      recommendation: 'Reduce HTML size by removing inline styles, scripts, and unnecessary markup; enable compression (gzip/brotli).',
      fixSteps: [
        'Move inline scripts and styles into external, cacheable files.',
        'Remove unused markup and comments.',
        'Ensure the server enables Brotli or Gzip compression.',
        'Paginate very long content instead of loading it all at once.',
      ],
      codeBefore: '500KB single HTML file',
      codeAfter: '80KB HTML + deferred external CSS/JS + compression',
      references: [{ label: 'web.dev: Reduce payload size', url: 'https://web.dev/reduce-payload-size/' }],
      confidence: 'certain',
    });
  }

  // 4. Images without width/height (causes layout shift)
  const imgs = Array.from(doc.querySelectorAll('img'));
  const noDims = imgs.filter((img) => !img.hasAttribute('width') || !img.hasAttribute('height'));
  if (noDims.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'img-no-dimensions',
      category: 'performance',
      severity: 'medium',
      title: `${noDims.length} image${noDims.length > 1 ? 's' : ''} without width and height attributes`,
      description: 'Images without explicit width and height cause layout shift as they load \u2014 the browser reserves no space and content jumps when the image arrives.',
      impact: 'Poor Cumulative Layout Shift (CLS) score, a Core Web Vital; users mis-tap as content moves.',
      recommendation: 'Add width and height attributes to every <img> so the browser reserves the correct space.',
      fixSteps: [
        'Add width and height attributes to each <img> matching the intrinsic image dimensions.',
        'Use CSS aspect-ratio for responsive images where fixed dimensions aren\u2019t possible.',
        'Use loading="lazy" on below-the-fold images to defer loading.',
      ],
      codeBefore: '<img src="photo.jpg" alt="A photo">',
      codeAfter: '<img src="photo.jpg" alt="A photo" width="800" height="600" loading="lazy">',
      references: [{ label: 'web.dev: Optimize CLS \u2014 images without dimensions', url: 'https://web.dev/cls/#images-without-dimensions' }],
      confidence: 'high',
    });
  }

  // 5. Missing lazy loading on offscreen images
  const imagesNoLazy = imgs.filter((img) => {
    if (img.hasAttribute('loading') && img.getAttribute('loading') === 'lazy') return false;
    // Heuristic: images after the first few are likely below the fold
    return imgs.indexOf(img) > 2;
  });
  if (imagesNoLazy.length > 2) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'img-no-lazy',
      category: 'performance',
      severity: 'low',
      title: `${imagesNoLazy.length} images without loading="lazy"`,
      description: 'Below-the-fold images do not use loading="lazy", so the browser downloads them immediately even if the user never scrolls to them.',
      impact: 'Wasted bandwidth and slower initial load on image-heavy pages.',
      recommendation: 'Add loading="lazy" to below-the-fold images; keep the first image eager for LCP.',
      fixSteps: [
        'Add loading="lazy" to images that are likely below the fold.',
        'Leave the largest above-the-fold image without lazy loading so it loads fast for LCP.',
        'Consider using the "fetchpriority" attribute on the LCP image.',
      ],
      codeBefore: '<img src="hero.jpg" alt="Hero">\n<img src="below.jpg" alt="Below">\n<img src="footer.jpg" alt="Footer">',
      codeAfter: '<img src="hero.jpg" alt="Hero" fetchpriority="high">\n<img src="below.jpg" alt="Below" loading="lazy">\n<img src="footer.jpg" alt="Footer" loading="lazy">',
      references: [{ label: 'MDN: loading attribute', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#attr-loading' }],
      confidence: 'medium',
    });
  }

  // 6. Missing explicit image dimensions already covered; check for modern formats
  const legacyImageFormats = imgs.filter((img) => {
    const src = img.getAttribute('src') || '';
    return /\.(jpg|jpeg|png|gif|bmp)(\?|$)/i.test(src);
  });
  const hasPicture = doc.querySelectorAll('picture source[type="image/webp"], picture source[type="image/avif"]').length > 0;
  if (legacyImageFormats.length > 3 && !hasPicture) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'no-modern-image-formats',
      category: 'performance',
      severity: 'low',
      title: 'Images use legacy formats (JPEG/PNG) without WebP/AVIF fallbacks',
      description: 'The page references JPEG or PNG images but does not provide modern formats like WebP or AVIF via <picture>. Modern formats are 25-50% smaller at equivalent quality.',
      impact: 'Larger image payloads slow page load, especially on mobile.',
      recommendation: 'Serve WebP or AVIF via <picture> with JPEG/PNG fallbacks.',
      fixSteps: [
        'Generate WebP/AVIF versions of each image.',
        'Use <picture><source srcset="img.webp" type="image/webp"><img src="img.jpg" alt="..."></picture>.',
        'Configure your CDN to auto-serve WebP to supporting browsers.',
      ],
      codeBefore: '<img src="photo.jpg" alt="A photo">',
      codeAfter: '<picture>\n  <source srcset="photo.avif" type="image/avif">\n  <source srcset="photo.webp" type="image/webp">\n  <img src="photo.jpg" alt="A photo">\n</picture>',
      references: [{ label: 'web.dev: Serve modern image formats', url: 'https://web.dev/serve-images-modern-formats/' }],
      confidence: 'high',
    });
  }

  // 7. No compression header
  const enc = ctx.headers['content-encoding'];
  if (!enc && htmlBytes > 10_000) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'no-compression',
      category: 'performance',
      severity: 'medium',
      title: 'Response not compressed (no Content-Encoding header)',
      description: 'The server did not return a Content-Encoding (gzip/br) header. Uncompressed HTML is significantly larger over the wire.',
      impact: 'Slower downloads, higher bandwidth costs, especially on mobile networks.',
      recommendation: 'Enable Brotli or Gzip compression on your web server or CDN.',
      fixSteps: [
        'Enable Brotli (preferred) or Gzip compression for text-based responses in your server/CDN config.',
        'In Nginx: gzip on; gzip_types text/plain text/css application/javascript text/html;',
        'In Apache: AddOutputFilterByType DEFLATE text/html text/css application/javascript.',
      ],
      codeBefore: 'Content-Encoding: (none)  \u2192 200KB over the wire',
      codeAfter: 'Content-Encoding: br  \u2192 ~40KB over the wire',
      references: [{ label: 'web.dev: Enable text compression', url: 'https://web.dev/enable-text-compression/' }],
      confidence: 'high',
    });
  }

  // 8. Missing resource hints (preconnect/dns-prefetch)
  const resourceHints = doc.querySelectorAll('link[rel="preconnect"], link[rel="dns-prefetch"], link[rel="preload"]');
  const externalDomains = new Set<string>();
  Array.from(doc.querySelectorAll('script[src^="http"], link[href^="http"][rel="stylesheet"]')).forEach((el) => {
    try {
      const u = new URL(el.getAttribute('src') || el.getAttribute('href') || '');
      externalDomains.add(u.origin);
    } catch { /* ignore */ }
  });
  if (externalDomains.size > 0 && resourceHints.length === 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-resource-hints',
      category: 'performance',
      severity: 'low',
      title: 'No resource hints (preconnect/dns-prefetch) for third-party origins',
      description: `The page loads resources from ${externalDomains.size} external domain${externalDomains.size > 1 ? 's' : ''} but has no preconnect or dns-prefetch hints. These hints let the browser establish connections early.`,
      impact: 'Slower loading of third-party resources due to late DNS/TLS handshake.',
      recommendation: 'Add <link rel="preconnect"> for critical third-party origins.',
      fixSteps: [
        'Identify third-party origins the page depends on (fonts, analytics, CDN).',
        'Add <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin> for each.',
        'Use <link rel="dns-prefetch" href="https://example.com"> for lower-priority origins.',
        'Add <link rel="preload" as="font" href="..." crossorigin> for critical fonts.',
      ],
      codeBefore: '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">',
      codeAfter: '<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>\n<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">',
      references: [{ label: 'MDN: preconnect', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/preconnect' }],
      confidence: 'medium',
    });
  }

  // 9. Excessive DOM size
  const allNodes = doc.querySelectorAll('*').length;
  if (allNodes > 1500) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'excessive-dom-size',
      category: 'performance',
      severity: 'medium',
      title: `Large DOM size (${allNodes} elements)`,
      description: 'The page has over 1500 DOM elements. Large DOMs slow style recalculation, layout, and interactions, and increase memory use.',
      impact: 'Slower interaction response and higher memory consumption, especially on mobile.',
      recommendation: 'Reduce DOM depth and node count by simplifying layout markup and virtualizing long lists.',
      fixSteps: [
        'Flatten nested wrapper divs; use modern CSS (flexbox/grid) instead of nested containers.',
        'Virtualize or paginate long lists so only visible items are in the DOM.',
        'Remove hidden elements that are never shown instead of keeping them with display:none.',
      ],
      codeBefore: '2500 DOM nodes, deeply nested divs',
      codeAfter: '600 DOM nodes, flat flexbox layout',
      references: [{ label: 'web.dev: DOM size', url: 'https://web.dev/dom-size/' }],
      confidence: 'certain',
    });
  }

  // 10. Too many fonts / font-display
  const fontLinks = Array.from(doc.querySelectorAll('link[href*="fonts.googleapis"], link[href*="font"]'));
  if (fontLinks.length > 2) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'too-many-fonts',
      category: 'performance',
      severity: 'low',
      title: `${fontLinks.length} font stylesheet${fontLinks.length > 1 ? 's' : ''} loaded`,
      description: 'Loading many font families and weights increases download size and delays text rendering.',
      impact: 'Slower page load and "invisible text" flashes if font-display is not set.',
      recommendation: 'Limit to 1-2 font families and only the weights you use; set font-display: swap.',
      fixSteps: [
        'Reduce to at most 2 font families and 2-3 weights total.',
        'Add &display=swap to Google Fonts URLs so text renders immediately with a fallback font.',
        'Self-host fonts for fewer requests and better control.',
      ],
      codeBefore: '<link href="https://fonts.googleapis.com/css?family=Roboto:400,700|Open+Sans:400,600,700|Lato:400"> rel="stylesheet">',
      codeAfter: '<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">',
      references: [{ label: 'web.dev: Avoid invisible text', url: 'https://web.dev/avoid-invisible-text/' }],
      confidence: 'high',
    });
  }

  return findings;
};
