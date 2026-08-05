import type { Checker, Finding, ScanContext } from '../types';

export const checkBestPractices: Checker = (ctx: ScanContext): Finding[] => {
  const findings: Finding[] = [];
  const { document: doc, html, headers } = ctx;

  // 1. Missing charset declaration
  if (!doc.querySelector('meta[charset]') && !doc.querySelector('meta[http-equiv="content-type"]')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-charset',
      category: 'best-practices',
      severity: 'medium',
      title: 'Missing character encoding declaration',
      description: 'The page has no <meta charset> declaration. Without it, browsers may guess the encoding incorrectly, garbling text.',
      impact: 'Text may display as mojibake (corrupted characters) in some browsers; security risk via UTF-7 XSS.',
      recommendation: 'Add <meta charset="utf-8"> as the first element in <head>.',
      fixSteps: [
        'Add <meta charset="utf-8"> as the first child of <head>.',
        'Ensure the server also sends Content-Type: text/html; charset=utf-8.',
      ],
      codeBefore: '<head>\n  <title>...</title>\n</head>',
      codeAfter: '<head>\n  <meta charset="utf-8">\n  <title>...</title>\n</head>',
      references: [{ label: 'MDN: charset declaration', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#attr-charset' }],
      confidence: 'certain',
    });
  }

  // 2. Deprecated HTML attributes (align, bgcolor, border on tables, etc.)
  const deprecatedAttrs = ['align', 'bgcolor', 'border', 'valign', 'hspace', 'vspace', 'color', 'background', 'text', 'link', 'vlink', 'alink', 'nowrap', 'size'];
  const deprecated = Array.from(doc.querySelectorAll('*')).filter((el) => {
    return deprecatedAttrs.some((attr) => el.hasAttribute(attr));
  });
  if (deprecated.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'deprecated-attributes',
      category: 'best-practices',
      severity: 'low',
      title: `${deprecated.length} element${deprecated.length > 1 ? 's' : ''} using deprecated HTML attributes`,
      description: 'The page uses presentational HTML attributes (align, bgcolor, border, etc.) that are deprecated and removed from modern HTML standards.',
      impact: 'Future browsers may stop supporting these attributes; the page may render inconsistently.',
      recommendation: 'Replace deprecated presentational attributes with CSS.',
      fixSteps: [
        'Remove deprecated attributes (align, bgcolor, border, valign, etc.).',
        'Apply the same visual styling via CSS classes instead.',
        'Validate the HTML with the W3C validator to catch remaining issues.',
      ],
      codeBefore: '<body bgcolor="#ffffff" text="#000000">\n<table border="1" align="center">',
      codeAfter: '<body class="page">\n<table class="data-table">',
      references: [{ label: 'W3C Markup Validation Service', url: 'https://validator.w3.org/' }],
      confidence: 'high',
    });
  }

  // 3. Deprecated/obsolete elements
  const obsoleteTags = ['font', 'center', 'marquee', 'blink', 'frame', 'frameset', 'noframes', 'big', 'strike', 'tt', 'acronym', 'dir'];
  const obsolete = obsoleteTags.filter((tag) => doc.querySelector(tag));
  if (obsolete.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'obsolete-elements',
      category: 'best-practices',
      severity: 'medium',
      title: `Obsolete HTML elements in use: ${obsolete.join(', ')}`,
      description: 'The page uses HTML elements that have been removed from the HTML standard (font, center, marquee, frames, etc.).',
      impact: 'These elements may not render correctly in modern browsers and fail HTML validation.',
      recommendation: 'Replace obsolete elements with semantic HTML and CSS.',
      fixSteps: [
        'Replace <font> and <center> with CSS (font-family, text-align).',
        'Remove <marquee> and <blink> entirely \u2014 use CSS animations if motion is needed.',
        'Replace <frameset>/<frame> with standard layouts (iframes only if truly necessary).',
        'Replace <acronym> with <abbr>, <strike> with <del> or CSS text-decoration.',
      ],
      codeBefore: '<font color="red" size="4">Important</font>\n<center>Welcome</center>',
      codeAfter: '<span class="important">Important</span>\n<div class="center">Welcome</div>',
      references: [{ label: 'MDN: Obsolete HTML elements', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element#obsolete' }],
      confidence: 'certain',
    });
  }

  // 4. Inline styles
  const inlineStyled = Array.from(doc.querySelectorAll('[style]'));
  if (inlineStyled.length > 8) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'excessive-inline-styles',
      category: 'best-practices',
      severity: 'low',
      title: `${inlineStyled.length} elements with inline style attributes`,
      description: 'The page uses many inline style attributes. Inline styles are hard to maintain, override cascade rules, and prevent caching.',
      impact: 'Harder maintenance, larger HTML, no style caching, inconsistent theming.',
      recommendation: 'Move inline styles into CSS classes in external stylesheets.',
      fixSteps: [
        'Identify repeated inline styles and extract them into CSS classes.',
        'Move one-off styles into component CSS as well where feasible.',
        'Keep inline styles only for genuinely dynamic values set by JavaScript.',
      ],
      codeBefore: '<div style="margin: 16px; padding: 8px; color: #333;">...',
      codeAfter: '<div class="card">...',
      references: [{ label: 'MDN: CSS cascade', url: 'https://developer.mozilla.org/en-US/docs/Web/CSS/Cascade' }],
      confidence: 'high',
    });
  }

  // 5. Deprecated doctype or missing doctype
  const doctype = doc.doctype;
  if (!doctype) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-doctype',
      category: 'best-practices',
      severity: 'medium',
      title: 'Missing <!DOCTYPE> declaration',
      description: 'The page has no DOCTYPE declaration. Without it, browsers enter quirks mode, causing inconsistent and buggy CSS rendering.',
      impact: 'Quirks mode causes layout bugs, inconsistent box model, and harder cross-browser debugging.',
      recommendation: 'Add <!DOCTYPE html> as the very first line of every HTML document.',
      fixSteps: [
        'Add <!DOCTYPE html> before <html> as the first line.',
        'Ensure nothing precedes the DOCTYPE (not even whitespace or comments).',
      ],
      codeBefore: '<html>...',
      codeAfter: '<!DOCTYPE html>\n<html>...',
      references: [{ label: 'MDN: DOCTYPE', url: 'https://developer.mozilla.org/en-US/docs/Glossary/Doctype' }],
      confidence: 'certain',
    });
  }

  // 6. Deprecated HTML4 doctype
  const doctypeStr = html.substring(0, 200).toLowerCase();
  if (doctypeStr.includes('doctype html public') || doctypeStr.includes('doctype html 4')) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'legacy-doctype',
      category: 'best-practices',
      severity: 'low',
      title: 'Legacy (HTML 4 / XHTML) DOCTYPE in use',
      description: 'The page uses an old HTML 4 or XHTML DOCTYPE instead of the simple HTML5 <!DOCTYPE html>. Legacy DOCTYPEs are verbose and unnecessary.',
      impact: 'No functional harm in standards mode, but unnecessary complexity and signals outdated markup.',
      recommendation: 'Replace the DOCTYPE with <!DOCTYPE html>.',
      fixSteps: ['Replace the entire DOCTYPE line with <!DOCTYPE html>.'],
      codeBefore: '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">',
      codeAfter: '<!DOCTYPE html>',
      references: [{ label: 'MDN: DOCTYPE', url: 'https://developer.mozilla.org/en-US/docs/Glossary/Doctype' }],
      confidence: 'certain',
    });
  }

  // 7. HTTP/1.1 without HTTP/2 (heuristic from headers)
  // We can't reliably detect protocol version from fetch headers, so skip.

  // 8. console.log / debugger left in production
  const scriptText = Array.from(doc.querySelectorAll('script')).map((s) => s.textContent || '').join('\n');
  const consoleLogs = (scriptText.match(/console\.(log|debug|info)\s*\(/g) || []).length;
  if (consoleLogs > 5) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'console-log-leftover',
      category: 'best-practices',
      severity: 'low',
      title: `${consoleLogs} console.log statements in inline scripts`,
      description: 'Inline scripts contain many console.log/debug/info calls. These should be removed or stripped in production builds to avoid cluttering users\u2019 consoles and leaking debug info.',
      impact: 'Console noise for users; potential information leakage about internal logic.',
      recommendation: 'Remove console.log statements or use a build step that strips them in production.',
      fixSteps: [
        'Remove debugging console.log calls before deploying.',
        'Configure your bundler (Terser, esbuild) to drop_console in production.',
        'Use a logging library with levels that can be silenced in production.',
      ],
      codeBefore: 'console.log("user data:", user);\nconsole.log("cart:", cart);',
      codeAfter: '// removed in production build',
      references: [{ label: 'MDN: Console', url: 'https://developer.mozilla.org/en-US/docs/Web/API/console' }],
      confidence: 'high',
    });
  }

  // 9. Long <title>
  const title = doc.querySelector('title')?.textContent?.trim() || '';
  if (title.length > 60) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'long-title',
      category: 'best-practices',
      severity: 'info',
      title: `Page title is long (${title.length} characters)`,
      description: 'The <title> exceeds 60 characters. Search engines truncate titles around 60-70 characters in results.',
      impact: 'The title is cut off in search results and browser tabs.',
      recommendation: 'Shorten the title to under 60 characters while keeping it descriptive.',
      fixSteps: [
        'Edit the title to 50-60 characters.',
        'Front-load the most important words.',
      ],
      codeBefore: `<title>${title.slice(0, 50)}... (${title.length} chars)</title>`,
      codeAfter: '<title>Concise Page Name | Brand</title>',
      references: [{ label: 'Google: Title links', url: 'https://developers.google.com/search/docs/appearance/title-links' }],
      confidence: 'high',
    });
  }

  // 10. Missing <html> lang on non-English (covered by accessibility; skip dup)

  // 11. Iframes without title
  const iframes = Array.from(doc.querySelectorAll('iframe'));
  const noTitleIframes = iframes.filter((f) => !f.getAttribute('title')?.trim() && !f.getAttribute('aria-label')?.trim() && !f.getAttribute('name')?.trim());
  if (noTitleIframes.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'iframe-no-title',
      category: 'best-practices',
      severity: 'medium',
      title: `${noTitleIframes.length} iframe${noTitleIframes.length > 1 ? 's' : ''} without a title`,
      description: 'Iframes have no title attribute. Screen reader users cannot identify the iframe\u2019s purpose without a title.',
      impact: 'Screen reader users hear "iframe" with no context and cannot decide whether to enter it.',
      recommendation: 'Add a descriptive title attribute to every iframe.',
      fixSteps: [
        'Add title="description of the iframe content" to each <iframe>.',
        'For embedded videos, title the iframe with the video name.',
        'For ads or tracking, title them as "Advertisement" or "Analytics".',
      ],
      codeBefore: '<iframe src="https://youtube.com/embed/abc"></iframe>',
      codeAfter: '<iframe src="https://youtube.com/embed/abc" title="How to set up Acme backup"></iframe>',
      references: [{ label: 'WCAG 2.4.1 Bypass Blocks', url: 'https://www.w3.org/WAI/WCAG21/Understanding/bypass-blocks.html' }],
      confidence: 'high',
    });
  }

  // 12. Button/anchor used for navigation incorrectly
  // (Heuristic: <button> with onclick="location.href" \u2014 should be <a>)
  const navButtons = Array.from(doc.querySelectorAll('button')).filter((b) => {
    const onclick = b.getAttribute('onclick') || '';
    return /location\.href|window\.location|location\.assign/.test(onclick);
  });
  if (navButtons.length > 0) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'button-for-navigation',
      category: 'best-practices',
      severity: 'low',
      title: `${navButtons.length} <button> used for navigation (should be <a>)`,
      description: 'Buttons with onclick="location.href=..." are used for navigation. This breaks middle-click (open in new tab), right-click, and keyboard accessibility for links.',
      impact: 'Users cannot open the destination in a new tab or copy the link; screen readers announce "button" instead of "link".',
      recommendation: 'Use <a href> for navigation; reserve <button> for actions.',
      fixSteps: [
        'Replace each navigation <button> with <a href="destination">.',
        'Keep <button> for actions that do not navigate (submit form, toggle UI).',
      ],
      codeBefore: '<button onclick="location.href=\'/about\'">About</button>',
      codeAfter: '<a href="/about">About</a>',
      references: [{ label: 'MDN: <a> vs <button>', url: 'https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a' }],
      confidence: 'high',
    });
  }

  // 13. Missing preconnect to fonts (performance covers hints; this is a subset, skip to avoid dup)

  // 14. Unminified CSS/JS heuristic (look for very long indented inline styles/scripts)
  const inlineCss = Array.from(doc.querySelectorAll('style')).map((s) => s.textContent || '').join('');
  if (inlineCss.length > 2000 && /\n    /.test(inlineCss)) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'unminified-inline-css',
      category: 'best-practices',
      severity: 'low',
      title: 'Inline CSS appears unminified',
      description: 'A large <style> block contains indentation and whitespace, suggesting it is not minified. Minification reduces size.',
      impact: 'Larger-than-necessary HTML payload.',
      recommendation: 'Minify inline CSS or move it to an external minified stylesheet.',
      fixSteps: [
        'Run the CSS through a minifier (cssnano, clean-css) and embed the minified version.',
        'Or move the CSS to an external .css file and minify it as part of the build.',
      ],
      codeBefore: '<style>\n  .card {\n    margin: 16px;\n    padding: 8px;\n  }\n</style>',
      codeAfter: '<style>.card{margin:16px;padding:8px}</style>',
      references: [{ label: 'web.dev: Minify CSS', url: 'https://web.dev/minify-css/' }],
      confidence: 'medium',
    });
  }

  // 15. Cache-Control missing
  if (!headers['cache-control'] && html.length > 5000) {
    findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing-cache-control',
      category: 'best-practices',
      severity: 'low',
      title: 'No Cache-Control header on the HTML response',
      description: 'The response has no Cache-Control header. Without it, browsers and CDNs use unpredictable caching behavior, potentially re-fetching on every visit or serving stale content.',
      impact: 'Either excessive re-fetching (slow) or unpredictable caching (stale content).',
      recommendation: 'Set an explicit Cache-Control header appropriate to the content type.',
      fixSteps: [
        'For HTML: Cache-Control: no-cache (revalidate on each visit).',
        'For assets (CSS/JS/images with hashed names): Cache-Control: public, max-age=31536000, immutable.',
        'Configure this in your web server or CDN.',
      ],
      codeBefore: '(no Cache-Control header)',
      codeAfter: 'Cache-Control: no-cache  (HTML)\nCache-Control: public, max-age=31536000, immutable  (hashed assets)',
      references: [{ label: 'MDN: Cache-Control', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control' }],
      confidence: 'high',
    });
  }

  return findings;
};
